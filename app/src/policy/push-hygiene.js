// What a push must not carry. an archive built to trick whoever unpacks it is refused outright: paths that climb out
// (../, absolute, drive letters), links, the same name twice, a zip whose two directories disagree. a file that looks
// like a secret (a private key, a cloud or registry token, a .env) holds the push until a person has looked.
// Author: Tim Rice
//
// only what is pushed here is read this way. public packages are full of test keys nobody can do anything about.
// a finding names the file and what kind of secret, never the secret itself

const zlib = require('zlib');
const db = require('../db');

const MAX_UNPACKED = 512 * 1024 * 1024;
const MB64 = 64 * 1024 * 1024;
const MAX_ENTRIES = 20000;
const MAX_TEXT = 2 * 1024 * 1024;
const MAX_FINDINGS = 20;

// ---------------------------------------------------------------- what counts as a secret

// "type": "service_account" with "private_key" within 2000 characters after it. a regex with [\s\S]{0,2000} walks
// those 2000 characters again from every "type" in the file, so this keeps one cursor on the next "private_key"
const SERVICE_TYPE = /"type"\s*:\s*"service_account"/g;
const serviceAccountKey = {
  test(body) {
    SERVICE_TYPE.lastIndex = 0;
    let key = -1;
    for (let m = SERVICE_TYPE.exec(body); m; m = SERVICE_TYPE.exec(body)) {
      const end = m.index + m[0].length;
      if (key < end) key = body.indexOf('"private_key"', end);
      if (key < 0) return false;
      if (key - end <= 2000) return true;
    }
    return false;
  }
};

// a file full of near misses has to cost about one pass over it, not one pass per near miss, so a run that can only
// fail at its far end is bounded. the bounds are far past any real token or password
const PATTERNS = [
  ['a private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/],
  ['an AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['a GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/],
  ['a GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/],
  ['an npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['a PyPI token', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/],
  ['a NuGet API key', /\boy2[a-z0-9]{43}\b/],
  ['a ForgeRepo token', /\bnrt_[A-Za-z0-9_-]{20,}/],
  ['a Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ['a Stripe live key', /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/],
  ['a Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['a Google service account key', serviceAccountKey],
  ['an Azure storage key', /AccountKey=[A-Za-z0-9+/]{80,}={0,2}/],
  ['a password in a connection string', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:/@'"]{1,256}:[^\s@'"]{3,256}@/]
];

// files that are secrets by their name, or by a line in them
const NAMED = [
  ['a .env file', (base) => /^\.env(\..+)?$/i.test(base) && !/\.(example|sample|template|dist|defaults?)$/i.test(base), null],
  ['an .npmrc with a login', (base) => base === '.npmrc', /(?:_authToken|_auth|_password)\s*=\s*\S/],
  // [^\S\r\n...] rather than \s: a \s* after ^ runs over line ends too, from every line start, and a file of
  // blank lines took minutes. whitespace across lines is still found, from the line the password is on
  ['a .pypirc with a password', (base) => base === '.pypirc', /^[^\S\r\n\u2028\u2029]*password\s*[=:]\s*\S/m],
  ['saved git credentials', (base) => base === '.git-credentials', null],
  ['an SSH private key', (base) => /^id_(rsa|dsa|ecdsa|ed25519)$/.test(base), null],
  ['AWS credentials', (base, path) => base === 'credentials' && /(^|\/)\.aws\//.test(path), /aws_secret_access_key/i],
  ['a certificate store with a private key', (base) => /\.(p12|pfx|keystore|jks)$/i.test(base), null]
];

// ---------------------------------------------------------------- archives

const text = (buf, start, len) => buf.toString('utf8', start, start + len).replace(/\0.*$/s, '');
const octal = (buf, start, len) => {
  const s = text(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
};

// the path a pax header gives the next entry, if it gives one
function paxPath(data) {
  const s = data.toString('utf8');
  let at = 0;
  let found = null;
  while (at < s.length) {
    const sp = s.indexOf(' ', at);
    if (sp < 0) break;
    const len = parseInt(s.slice(at, sp), 10);
    if (!(len > 0)) break;
    const rec = s.slice(sp + 1, at + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0 && rec.slice(0, eq) === 'path') found = rec.slice(eq + 1);
    at += len;
  }
  return found;
}

// every entry of a tar: { name, type, data }. links and devices come through too, that is the point
function tarEntries(tar) {
  const out = [];
  let offset = 0;
  let longName = null;
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    if (h.every((b) => b === 0)) break;
    const size = octal(h, 124, 12);
    if (!Number.isFinite(size) || size < 0 || offset + 512 + size > tar.length) throw new Error('the tar is damaged');
    const type = String.fromCharCode(h[156] || 48);
    const data = tar.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    // pax and GNU headers name the entry after them
    if (type === 'x' || type === 'L') {
      longName = type === 'x' ? paxPath(data) || longName : data.toString('utf8').replace(/\0.*$/s, '');
      continue;
    }
    if (type === 'g') continue;
    const prefix = text(h, 345, 155);
    const name = longName || (prefix ? `${prefix}/` : '') + text(h, 0, 100);
    longName = null;
    out.push({ name, type: type === '\0' ? '0' : type, data });
    if (out.length > MAX_ENTRIES) throw new Error(`more than ${MAX_ENTRIES} entries`);
  }
  return out;
}

function zipEntries(zip, limit = MAX_UNPACKED) {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i -= 1) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip file');
  const count = zip.readUInt16LE(eocd + 10);
  if (count > MAX_ENTRIES) throw new Error(`more than ${MAX_ENTRIES} entries`);
  let p = zip.readUInt32LE(eocd + 16);
  let unpacked = 0;
  const out = [];
  for (let n = 0; n < count; n += 1) {
    if (p + 46 > zip.length || zip.readUInt32LE(p) !== 0x02014b50) throw new Error('the zip directory is damaged');
    const method = zip.readUInt16LE(p + 10);
    const compressed = zip.readUInt32LE(p + 20);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const attrs = zip.readUInt32LE(p + 38);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (compressed === 0xffffffff || local === 0xffffffff) throw new Error('zip64 archives are not accepted');
    if (local + 30 > zip.length || zip.readUInt32LE(local) !== 0x04034b50) throw new Error('a zip entry is damaged');
    const localLen = zip.readUInt16LE(local + 26);
    const localName = zip.toString('utf8', local + 30, local + 30 + localLen);
    const start = local + 30 + localLen + zip.readUInt16LE(local + 28);
    if (start + compressed > zip.length) throw new Error('a zip entry runs past the end of the file');
    // a unix symlink keeps its mode in the top half of the external attributes
    const type = ((attrs >>> 16) & 0o170000) === 0o120000 ? '2' : name.endsWith('/') ? '5' : '0';
    let data = Buffer.alloc(0);
    if (type === '0') {
      const raw = zip.subarray(start, start + compressed);
      if (method === 0) data = raw;
      else if (method === 8) data = zlib.inflateRawSync(raw, { maxOutputLength: limit - unpacked });
      else throw new Error(`a zip entry is packed a way nothing here reads (method ${method})`);
      unpacked += data.length;
    }
    out.push({ name, localName, type, data });
  }
  return out;
}

function kindOf(filename) {
  const f = String(filename || '').toLowerCase();
  if (f.endsWith('.tgz') || f.endsWith('.tar.gz')) return 'tgz';
  if (/\.(whl|zip|egg|nupkg|jar)$/.test(f)) return 'zip';
  return null;
}

// ---------------------------------------------------------------- tricks

function trickIn(entry) {
  const name = entry.name;
  if (!name) return 'an entry with no name';
  if (/[\0]/.test(name)) return `${JSON.stringify(name.slice(0, 80))} has a NUL in its name`;
  if (/^(\/|[A-Za-z]:|\\\\)/.test(name)) return `${name.slice(0, 120)} is an absolute path`;
  if (name.split(/[\\/]+/).includes('..')) return `${name.slice(0, 120)} climbs out with ..`;
  if (entry.type === '1' || entry.type === '2') return `${name.slice(0, 120)} is a link`;
  if (!['0', '5', '7'].includes(entry.type)) return `${name.slice(0, 120)} is a device or special file`;
  if (entry.localName !== undefined && entry.localName !== name) return `${name.slice(0, 120)} is named differently in the zip's two directories`;
  return null;
}

// ---------------------------------------------------------------- the check

function secretsIn(entry) {
  const path = entry.name.replace(/^\.\//, '');
  const base = path.split('/').pop();
  const found = [];
  const data = entry.data;
  const looksText = data.length <= MAX_TEXT && !data.subarray(0, 8192).includes(0);
  const body = looksText ? data.toString('utf8') : '';
  for (const [what, byName, line] of NAMED) {
    if (!byName(base, path)) continue;
    if (!line || (looksText && line.test(body))) found.push(`${path}: ${what}`);
  }
  if (looksText) {
    for (const [what, re] of PATTERNS) if (re.test(body)) found.push(`${path}: ${what}`);
  }
  return found;
}

// the most a push may unpack to: four times the upload limit (MAX_IMPORT_MB, 64MB unless raised), so 256MB out of the
// box, never under 64MB or over 512MB. all of it is unpacked in one synchronous go while the push waits, and gunzip
// holds about twice its output at the end, so a small upload of zeros shouldn't get to ask for a gigabyte
function unpackLimit() {
  const upload = Number(require('../config').maxImportBytes) || MB64;
  return Math.min(MAX_UNPACKED, Math.max(MB64, 4 * upload));
}

/**
 * reads a pushed file. { refuse } when it is built to trick an unpacker or can't be read, else { findings } for
 * whatever looks like a secret (empty = nothing)
 */
function inspect(buffer, filename) {
  const kind = kindOf(filename);
  if (!kind) return { findings: [] };
  let entries;
  const limit = unpackLimit();
  try {
    entries = kind === 'tgz' ? tarEntries(zlib.gunzipSync(buffer, { maxOutputLength: limit })) : zipEntries(buffer, limit);
  } catch (err) {
    const big = err.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength|too large/i.test(err.message);
    return { refuse: big ? `${filename} unpacks to more than ${Math.round(limit / 1048576)}MB` : `${filename} could not be read: ${err.message}` };
  }
  const seen = new Set();
  const findings = [];
  for (const e of entries) {
    const trick = trickIn(e);
    if (trick) return { refuse: `${filename} is built to trick whatever unpacks it: ${trick}` };
    const key = e.name.replace(/^\.\//, '').replace(/\/+$/, '');
    if (e.type !== '5') {
      if (seen.has(key)) return { refuse: `${filename} is built to trick whatever unpacks it: ${key.slice(0, 120)} is in it twice` };
      seen.add(key);
      if (findings.length < MAX_FINDINGS) findings.push(...secretsIn(e));
    }
  }
  return { findings: findings.slice(0, MAX_FINDINGS) };
}

// hold (default), warn or off, for secrets. tricks are always refused
function mode() {
  const m = String(db.settings.get('push_secret_scan') || 'hold');
  return ['hold', 'warn', 'off'].includes(m) ? m : 'hold';
}

module.exports = { inspect, mode, kindOf, secretsIn, MAX_TEXT, _internal: { tarEntries, zipEntries, trickIn, secretsIn, paxPath } };
