// Waivers. a written down, time boxed "yes, we know" for one finding on one package.
// Author: Tim Rice
// three kinds: an advisory safe resolution would leave out, a license enforce would hold, a version still cooling off.
// every one expires. the kill switch, malware and integrity can never be waived

const db = require('../db');
const auth = require('../security/auth');
const repo = require('../db/repositories/waivers');
const log = require('../logger');
const ecosystems = require('../ecosystems');
const { httpError } = require('../lib/errors');

const KINDS = ['advisory', 'license', 'cooloff'];
const CACHE_MS = 5000;

let cache = null;
let cachedAt = 0;

function invalidate() {
  cache = null;
}

function maxDays() {
  const n = parseInt(db.settings.get('waiver_max_days'), 10);
  return Number.isInteger(n) && n >= 1 ? Math.min(n, 365) : 90;
}

function normalize(ecosystem, name) {
  const n = String(name || '').trim();
  return ecosystem === 'pypi' ? require('../ecosystems/pypi/name').normalize(n) : n;
}

// only ever what is active and not past its date, asked of the database clock
async function active() {
  if (cache && Date.now() - cachedAt < CACHE_MS) return cache;
  cache = await repo.live();
  cachedAt = Date.now();
  return cache;
}

function inRange(w, version, adapter) {
  if (!w.version_range) return true;
  if (!version) return false;
  try {
    return adapter.satisfies(version, w.version_range);
  } catch (err) {
    // a waiver is a yes, and a range that cannot judge the version is not one
    return false;
  }
}

// no scope = the question is for everyone, and only a waiver for everyone answers it
function inScope(w, scope) {
  const s = scope || { app: 0, env: 0 };
  return (!Number(w.application_id) || Number(w.application_id) === s.app) && (!Number(w.environment_id) || Number(w.environment_id) === s.env);
}

async function applicable(kind, ecosystem, name, version, scope) {
  const n = normalize(ecosystem, name);
  const adapter = ecosystems.adapter(ecosystem);
  return (await active()).filter((w) => w.kind === kind && w.ecosystem === ecosystem && w.package_name === n
    && inRange(w, version, adapter) && inScope(w, scope));
}

const splitIds = (text) => String(text || '').split(/[\s,]+/).map((s) => s.trim().toUpperCase()).filter(Boolean);

// every advisory on the version has to be named by some waiver. one new advisory and it is left out again.
// an image waiver can say * instead, for the exact tags or digests it names: the image as it is, taken on as a whole
function coversAdvisories(list, advisoryIds) {
  const ids = splitIds(advisoryIds);
  if (!ids.length) return null;
  const whole = list.filter((w) => w.ecosystem === 'oci' && w.version_range && splitIds(w.subject).includes('*'))
    .sort((a, b) => String(a.expires_at).localeCompare(String(b.expires_at)));
  if (whole.length) return whole[0];
  const named = new Map();
  for (const w of list) for (const id of splitIds(w.subject)) if (!named.has(id)) named.set(id, w);
  if (!ids.every((id) => named.has(id))) return null;
  // the one ending soonest is the one that matters
  return [...new Set(ids.map((id) => named.get(id)))].sort((a, b) => String(a.expires_at).localeCompare(String(b.expires_at)))[0];
}

async function advisoryWaived(ecosystem, name, version, finding, scope) {
  const list = await applicable('advisory', ecosystem, name, version, scope);
  return list.length ? coversAdvisories(list, finding && finding.advisories) : null;
}

// license holds live on the file, so only waivers for everyone, for that exact license
async function licenseWaived(ecosystem, name, version, expression) {
  const want = String(expression || 'unknown').trim().toLowerCase();
  return (await applicable('license', ecosystem, name, version, null))
    .find((w) => String(w.subject || '').trim().toLowerCase() === want) || null;
}

async function coolingWaived(ecosystem, name, version, scope) {
  return (await applicable('cooloff', ecosystem, name, version, scope))[0] || null;
}

// ---------------------------------------------------------------- lifecycle

function waiverEvent(type, w, user, ip) {
  require('../integrations/events').emit(type, {
    ecosystem: w.ecosystem, package: w.package_name, version: w.version_range || null, user, sourceIp: ip,
    policy: `${w.kind} waiver`, cve: w.kind === 'advisory' ? w.subject : null, reason: type === 'waiver.expired' ? 'the waiver ran out, the finding applies again' : w.reason,
    action: type === 'waiver.expired' ? 'expired' : 'granted'
  });
}

const label = (w) => `${w.kind} ${w.ecosystem}:${w.package_name}${w.version_range ? ` ${w.version_range}` : ''}${w.subject ? ` [${w.subject}]` : ''}`;

async function afterChange(rows) {
  invalidate();
  // a license waiver starting or ending changes what the holds should be
  const licenses = rows.filter((w) => w.kind === 'license');
  if (!licenses.length) return;
  const license = require('./licenses');
  const packages = new Map(licenses.map((w) => [`${w.ecosystem}:${w.package_name}`, w]));
  (async () => {
    await license.reevaluate();
    for (const w of packages.values()) await license.rejudgeHeld(w.ecosystem, w.package_name);
  })().catch((err) => log.error('license recheck after a waiver change failed', err.message));
}

async function create(fields, { grant, user, userId, ip }) {
  const days = Math.min(Math.max(1, Number(fields.days) || 30), maxDays());
  const result = await repo.create(fields, { grant, days, user, userId });
  const row = await repo.byId(result.insertId);
  await auth.audit(userId || null, user, ip, grant ? 'waiver.grant' : 'waiver.request', label(row),
    `${fields.reason}${fields.reference ? ` [ticket ${fields.reference}]` : ''} (${days} days)`.slice(0, 4000));
  if (grant) {
    await afterChange([row]);
    waiverEvent('waiver.created', row, user, ip);
  }
  return row;
}

async function decide(id, action, { user, userId, ip, note, days }) {
  const row = await repo.byId(id);
  if (!row) throw httpError(404, 'there is no such waiver');
  let done;
  if (action === 'approve' || action === 'reject') {
    if (row.status !== 'pending') throw httpError(409, `that waiver is already ${row.status}`);
    if (action === 'approve') {
      const d = Math.min(Math.max(1, Number(days) || Number(row.days) || 30), maxDays());
      done = await repo.approve(id, { days: d, user, note: note || null });
    } else {
      done = await repo.reject(id, { user, note: note || null });
    }
  } else if (action === 'revoke') {
    if (row.status !== 'active') throw httpError(409, `only an active waiver can be revoked, that one is ${row.status}`);
    done = await repo.revoke(id, { user, note: note || null });
  } else {
    throw httpError(400, 'approve, reject or revoke');
  }
  if (done !== 1) throw httpError(409, 'someone else just changed that waiver');
  await auth.audit(userId || null, user, ip, `waiver.${action}`, label(row), note || null, {
    before: { status: row.status, expires_at: row.expires_at },
    after: { status: { approve: 'active', reject: 'rejected', revoke: 'revoked' }[action] }
  });
  await afterChange([row]);
  if (action === 'approve') waiverEvent('waiver.created', row, user, ip);
  return repo.byId(id);
}

// past their date: marked, audited, and anything they were holding open goes back to normal
async function sweep() {
  const due = await repo.due();
  if (!due.length) return 0;
  await repo.expire(due.map((w) => w.id));
  for (const w of due) await auth.audit(null, 'system', null, 'waiver.expire', label(w), null, { before: { status: 'active' }, after: { status: 'expired' } });
  log.info(`waivers: ${due.length} expired`);
  await afterChange(due);
  for (const w of due) waiverEvent('waiver.expired', w, 'system', null);
  return due.length;
}

module.exports = {
  KINDS, maxDays, normalize, active, applicable, inRange, inScope, splitIds, coversAdvisories,
  advisoryWaived, licenseWaived, coolingWaived, create, decide, sweep, invalidate
};
