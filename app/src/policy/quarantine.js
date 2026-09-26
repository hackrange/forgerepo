// Quarantine. exact files held back until a person decides.
// Author: Tim Rice
// permissive: still served, with a warning. strict: refused and left out of metadata.
// rejected: refused in either mode. holds key on the file, so a purge + redownload stays held

const db = require('../db');
const auth = require('../security/auth');
const holds = require('../db/repositories/quarantine');
const log = require('../logger');
const { httpError } = require('../lib/errors');

const MODES = ['permissive', 'strict'];
const STATUSES = ['open', 'released', 'rejected'];

function mode() {
  return db.settings.get('quarantine_mode') === 'strict' ? 'strict' : 'permissive';
}

// artifacts.status is just the display copy, the gate reads the holds
async function syncStatus(file) {
  const row = await holds.holdCounts(file);
  let status = 'unknown';
  if (Number(row.rejected)) status = 'blocked';
  else if (Number(row.open)) status = 'quarantined';
  else if (Number(row.n)) status = 'approved';
  await holds.setArtifactStatus(file, status);
  return status;
}

function refreshOverview() {
  try {
    require('../dashboard').invalidate();
  } catch (err) {
    //not loaded yet
  }
}

// one open hold per file per source, a second ask is a no-op
// retell: an open hold of the same source takes the new reason, so what a person reads is the latest thing known
async function hold(file, { source, reason, user, sha256, retell }) {
  const existing = await holds.openHoldFor(file, source);
  if (existing) {
    if (retell) await holds.retellHold(existing.id, String(reason).slice(0, 1000), sha256);
    return { id: Number(existing.id), created: false };
  }
  const result = await holds.createHold(file, {
    sha256: sha256 || null, source: String(source).slice(0, 64), reason: String(reason).slice(0, 1000), user: user ? String(user).slice(0, 64) : null
  });
  await syncStatus(file);
  log.warn(`quarantine: ${file.ecosystem} ${file.packageName} ${file.filename} held (${source}): ${reason}`);
  await auth.audit(null, user || 'system', null, 'quarantine.hold', `${file.ecosystem}:${file.packageName}:${file.filename}`, `${source}: ${reason}`);
  refreshOverview();
  require('../integrations/events').emit('package.quarantined', {
    ecosystem: file.ecosystem, package: file.packageName, version: file.version, filename: file.filename, artifactHash: sha256,
    user: user || 'system', policy: source, reason, action: 'held'
  });
  return { id: Number(result.insertId), created: true };
}

function byId(id) {
  return holds.holdById(id);
}

const asFile = (h) => ({ ecosystem: h.ecosystem, packageName: h.package_name, version: h.version, filename: h.filename });

//release: open or rejected -> released. reject: open -> rejected
async function resolve(id, action, user, noteText) {
  const h = await byId(id);
  if (!h) throw httpError(404, 'there is no such hold');
  const next = action === 'reject' ? 'rejected' : 'released';
  const allowedFrom = action === 'reject' ? ['open'] : ['open', 'rejected'];
  if (!allowedFrom.includes(h.status)) throw httpError(409, `that hold is already ${h.status}`);
  const done = await holds.settleHold(h.id, h.status, {
    status: next, user: user ? String(user).slice(0, 64) : null, note: noteText ? String(noteText).slice(0, 1000) : null
  });
  if (done !== 1) throw httpError(409, 'someone else just changed that hold');
  await syncStatus(asFile(h));
  refreshOverview();
  if (next === 'released') {
    require('../integrations/events').emit('package.released', {
      ecosystem: h.ecosystem, package: h.package_name, version: h.version, filename: h.filename, artifactHash: h.sha256,
      user: user || 'system', policy: h.source, reason: noteText || h.reason, action: 'released'
    });
  }
  return byId(id);
}

// whoever placed a hold can lift theirs, like integrity once its alert is settled
async function releaseSource(file, source, user, noteText) {
  const done = await holds.releaseOpen(file, source, {
    user: user ? String(user).slice(0, 64) : null, note: noteText ? String(noteText).slice(0, 1000) : null
  });
  if (done) {
    await syncStatus(file);
    refreshOverview();
  }
  return done;
}

// what the gate should do with one file: null = nothing held, else { refuse, warn, reason }
// holds that refuse in both modes
const ALWAYS_REFUSED = new Set(['hygiene']);

async function verdict(ecosystem, packageName, version, filename) {
  const rows = await holds.liveHolds({ ecosystem, packageName, version, filename });
  if (!rows.length) return null;
  const rejected = rows.find((r) => r.status === 'rejected');
  if (rejected) return { refuse: true, warn: false, reason: `rejected in quarantine: ${rejected.reason}`, source: rejected.source };
  // a file that may carry a secret is never handed out while it is held, permissive or not
  const secret = rows.find((r) => ALWAYS_REFUSED.has(r.source));
  if (secret) return { refuse: true, warn: false, reason: `held in quarantine: ${secret.reason}`, source: secret.source };
  // lockdown serves only files nothing is held against, whatever the quarantine mode
  const strict = mode() === 'strict' || require('./mode').lockdown();
  return { refuse: strict, warn: !strict, reason: `held in quarantine: ${rows[0].reason}`, source: rows[0].source };
}

// files that metadata should leave out: rejected always, open ones only in strict mode
async function hiddenFor(ecosystem, packageName) {
  const rows = await holds.liveForPackage(ecosystem, packageName);
  const strict = mode() === 'strict' || require('./mode').lockdown();
  return rows.filter((r) => r.status === 'rejected' || strict || ALWAYS_REFUSED.has(r.source));
}

module.exports = { MODES, STATUSES, mode, hold, byId, resolve, releaseSource, verdict, hiddenFor, syncStatus };
