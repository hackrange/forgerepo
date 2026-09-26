// Trust policies for image signatures: adding and removing them, checked hard, every change audited.
// Author: Tim Rice

const crypto = require('crypto');
const db = require('../db');
const signatures = require('../images/signatures');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const MAX_POLICIES = 200;
const MAX_KEYS = 10;
const MAX_IDENTITIES = 20;
// eslint-disable-next-line no-control-regex -- one line of plain text
const oneLine = (v, n) => String(v === undefined || v === null ? '' : v).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, n);

// an exact repository, a namespace like acme/*, or a prefix ending in *
function checkPattern(raw) {
  const p = String(raw || '').trim().toLowerCase();
  if (!p || p.length > 255 || p === '*' || p === '/*') return null;
  const body = p.endsWith('/*') ? p.slice(0, -2) : p.endsWith('*') ? p.slice(0, -1) : p;
  return /^[a-z0-9]+([._/-][a-z0-9]+)*[._/-]?$/.test(body) && !body.includes('//') ? p : null;
}

function checkKey(pem) {
  let key;
  try {
    key = crypto.createPublicKey(String(pem));
  } catch (err) {
    fail(400, 'a trusted key has to be a PEM public key, like the cosign.pub that cosign generate-key-pair writes');
  }
  const type = key.asymmetricKeyType;
  if (!['ec', 'ed25519', 'rsa'].includes(type)) fail(400, `a ${type} key is not one cosign signs with`);
  if (type === 'rsa' && key.asymmetricKeyDetails.modulusLength < 2048) fail(400, 'an RSA key shorter than 2048 bits is not trusted');
  const der = key.export({ type: 'spki', format: 'der' });
  return { name: crypto.createHash('sha256').update(der).digest('hex').slice(0, 16), pem: key.export({ type: 'spki', format: 'pem' }) };
}

// who may sign keylessly. a * is only allowed at the end of a URI with its owner in it, or as the name of an email,
// so a policy can't end up trusting everybody with a GitHub account
function checkIdentity(raw) {
  const issuer = oneLine(raw && raw.issuer, 255);
  const subject = oneLine(raw && raw.subject, 512);
  if (!/^https:\/\/[a-z0-9.-]+(:\d+)?(\/[\x21-\x7e]*)?$/i.test(issuer)) fail(400, 'a signer identity needs its issuer, the https address of the login provider, like https://token.actions.githubusercontent.com');
  if (!subject || /\s/.test(subject)) fail(400, 'a signer identity needs its subject: a workflow address or an email, with no spaces');
  const stars = subject.split('*').length - 1;
  if (stars) {
    const uri = /^https:\/\/[a-z0-9.-]+\/[^/*]+\/[^*]*\*$/i.test(subject);
    const mail = /^\*@[a-z0-9.-]+\.[a-z]{2,}$/i.test(subject);
    if (stars > 1 || !(uri || mail)) {
      fail(400, 'a * in a subject can only end an address that names its owner, like https://github.com/acme/*, or stand for the name of an email, like *@acme.com');
    }
  }
  return { issuer, subject };
}

function list() {
  return signatures.policies().then((rows) => rows.map((r) => ({
    id: r.id, pattern: r.pattern, mode: r.mode, note: r.note, created_by: r.created_by, created_at: r.created_at,
    keys: r.trust.keys.map((k) => ({ name: k.name, pem: k.pem })), identities: r.trust.identities, requireLog: r.trust.requireLog
  })));
}

async function add(actor, body) {
  const pattern = checkPattern(body.pattern);
  if (!pattern) fail(400, 'the repository is an exact name like acme/api or library/nginx, a namespace like acme/*, or a prefix ending in *');
  const mode = String(body.mode || '');
  if (!['require', 'warn'].includes(mode)) fail(400, 'the mode is require or warn');
  const keysIn = Array.isArray(body.keys) ? body.keys : [];
  const idsIn = Array.isArray(body.identities) ? body.identities : [];
  if (keysIn.length > MAX_KEYS) fail(400, `at most ${MAX_KEYS} keys in one policy`);
  if (idsIn.length > MAX_IDENTITIES) fail(400, `at most ${MAX_IDENTITIES} signer identities in one policy`);
  const keys = keysIn.map(checkKey);
  const identities = idsIn.map(checkIdentity);
  if (!keys.length && !identities.length) fail(400, 'name at least one trusted key or signer identity, or nothing could ever pass');
  const signers = JSON.stringify({ keys, identities, requireLog: body.requireLog === true || body.requireLog === '1' });
  const note = oneLine(body.note, 255);
  const n = await db.one('SELECT COUNT(*) AS n FROM image_trust');
  if (Number(n.n) >= MAX_POLICIES) fail(400, `there are already ${MAX_POLICIES} trust policies, take some away first`);
  const result = await db.query('INSERT IGNORE INTO image_trust (pattern, mode, signers, note, created_by) VALUES (?, ?, ?, ?, ?)', [pattern, mode, signers, note || null, actor.name]);
  if (result.affectedRows !== 1) fail(409, `${pattern} has a trust policy already, remove it first`);
  signatures.invalidate();
  await audit(actor, 'image_trust.add', pattern, `${mode}, ${keys.length} key(s), ${identities.length} identity(ies)`,
    { after: { pattern, mode, keys: keys.map((k) => k.name), identities, requireLog: JSON.parse(signers).requireLog, note } });
  return { id: Number(result.insertId), pattern, mode };
}

async function remove(actor, id) {
  const row = await db.one('SELECT id, pattern, mode, signers FROM image_trust WHERE id = ?', [id]);
  if (!row) fail(404, 'there is no such trust policy');
  if ((await db.query('DELETE FROM image_trust WHERE id = ?', [id])).affectedRows !== 1) fail(409, 'that trust policy was removed a moment ago');
  signatures.invalidate();
  const was = signatures.parseSigners(row.signers);
  await audit(actor, 'image_trust.remove', row.pattern, null, { before: { pattern: row.pattern, mode: row.mode, keys: was.keys.map((k) => k.name), identities: was.identities } });
  return row;
}

module.exports = { list, add, remove, checkPattern, checkIdentity, checkKey };
