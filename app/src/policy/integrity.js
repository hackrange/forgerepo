// Release integrity. a file we already hold, and the registry now says or sends something else.
// Author: Tim Rice
// npm and PyPI both promise a published file never changes. when it does, somebody should hear about it

const crypto = require('crypto');
const auth = require('../security/auth');
const store = require('../storage');
const quarantine = require('./quarantine');
const log = require('../logger');
const alerts = require('../db/repositories/integrity');
const artifactsRepo = require('../db/repositories/artifacts');
const packagesRepo = require('../db/repositories/packages');
const pypiFiles = require('../db/repositories/pypi-files');
const { httpError } = require('../lib/errors');

const KINDS = ['content', 'published'];
const STATUSES = ['open', 'accepted', 'dismissed'];

function fingerprint(e) {
  return crypto.createHash('sha256')
    .update([e.kind, e.ecosystem, e.packageName, e.version || '', e.filename, e.observed].join('\n'))
    .digest('hex');
}

// one row per distinct change, repeats just bump the count
async function note(e) {
  const result = await alerts.record({
    fingerprint: fingerprint(e), kind: e.kind, ecosystem: e.ecosystem, packageName: e.packageName, version: e.version || '', filename: e.filename,
    artifactId: e.artifactId || null, upstream: e.upstream || null, expected: String(e.expected).slice(0, 255), observed: String(e.observed).slice(0, 255),
    heldSha256: e.heldSha256 || null, heldSize: e.heldSize || null, metadata: e.metadata ? JSON.stringify(e.metadata) : null
  });
  const created = result.affectedRows === 1;
  if (created) {
    const target = `${e.ecosystem}:${e.packageName}:${e.filename}`;
    log.error(`integrity: ${target} ${e.kind === 'content' ? 'came down as' : 'is now published as'} ${e.observed}, `
      + `it was first seen as ${e.expected}`);
    await auth.audit(null, 'system', null, 'integrity.violation', target, `${e.kind}: expected ${e.expected}, got ${e.observed}`);
    require('../integrations/events').emit('artifact.integrity_changed', {
      ecosystem: e.ecosystem, package: e.packageName, version: e.version, filename: e.filename,
      artifactHash: /^[0-9a-f]{64}$/.test(String(e.expected)) ? e.expected : null, policy: 'release integrity',
      reason: `${e.kind === 'content' ? 'the downloaded bytes' : 'the published digest'} changed: first seen as ${e.expected}, now ${e.observed}`,
      action: 'held in quarantine', severity: 'CRITICAL'
    });
    // the file sits in quarantine until the alert is settled. strict mode refuses it meanwhile.
    // npm's expected is a sha512 integrity string, only a real sha256 goes on the hold.
    // a hold that won't write must never cost us the alert itself
    try {
      await quarantine.hold(
        { ecosystem: e.ecosystem, packageName: e.packageName, version: e.version, filename: e.filename },
        {
          source: 'integrity',
          reason: `integrity alert, the ${e.kind === 'content' ? 'downloaded bytes' : 'published digest'} changed`,
          sha256: /^[0-9a-f]{64}$/.test(String(e.expected)) ? e.expected : null
        }
      );
    } catch (err) {
      log.error(`integrity: could not put ${target} in quarantine`, err.message);
    }
    try {
      require('../dashboard').invalidate();
    } catch (err) {
      //overview not loaded, nothing to refresh
    }
  }
  return { id: Number(result.insertId) || null, created };
}

// npm sends several hashes sometimes, sha512 is the one that counts
function sha512Of(integrity) {
  return String(integrity || '').split(/\s+/).find((t) => t.startsWith('sha512-')) || null;
}

function parseMeta(value) {
  if (!value) return null;
  try {
    return typeof value === 'object' && !Buffer.isBuffer(value) ? value : JSON.parse(String(value));
  } catch (err) {
    return null;
  }
}

// a fresh packument against the integrity we recorded when each version came down
async function checkNpm(name, doc, source) {
  const versions = doc && doc.versions;
  if (!versions || typeof versions !== 'object') return 0;
  const rows = await artifactsRepo.npmForIntegrity(name);
  let found = 0;
  for (const row of rows) {
    const had = sha512Of((parseMeta(row.metadata) || {}).integrity);
    const v = Object.prototype.hasOwnProperty.call(versions, row.version) ? versions[row.version] : null;
    const now = sha512Of(v && v.dist && v.dist.integrity);
    // unpublished, or nothing comparable. not a change we can prove
    if (!had || !now || had === now) continue;
    // rerouted to another registry is a different file, not a changed one
    if (row.upstream && source && row.upstream !== source) continue;
    await note({
      kind: 'published', ecosystem: 'npm', packageName: name, version: row.version, filename: row.filename,
      artifactId: row.id, upstream: source, expected: had, observed: now
    });
    found += 1;
  }
  return found;
}

// a fresh PyPI project page against the sha256 of the files we hold
async function checkPypi(project, page, source) {
  const files = page && Array.isArray(page.files) ? page.files : [];
  if (!files.length) return 0;
  const rows = await artifactsRepo.pypiForIntegrity(project);
  if (!rows.length) return 0;
  const listed = new Map(files.map((f) => [f.filename, f]));
  let found = 0;
  for (const row of rows) {
    const f = listed.get(row.filename);
    const now = f && f.hashes && typeof f.hashes.sha256 === 'string' ? f.hashes.sha256.toLowerCase() : null;
    if (!now || !/^[0-9a-f]{64}$/.test(now) || now === row.sha256) continue;
    if (row.upstream && source && row.upstream !== source) continue;
    await note({
      kind: 'published', ecosystem: 'pypi', packageName: project, version: row.version, filename: row.filename,
      artifactId: row.id, upstream: source, expected: row.sha256, observed: now
    });
    found += 1;
  }
  return found;
}

function byId(id) {
  return alerts.eventById(id);
}

async function openEvent(id) {
  const ev = await byId(id);
  if (!ev) throw httpError(404, 'there is no such integrity alert');
  if (ev.status !== 'open') throw httpError(409, 'that alert has already been dealt with');
  return ev;
}

async function close(ev, status, user, noteText) {
  const done = await alerts.settle(ev.id, {
    status, user: user ? String(user).slice(0, 64) : null, note: noteText ? String(noteText).slice(0, 1000) : null
  });
  if (done !== 1) throw httpError(409, 'that alert has already been dealt with');
  // settled, so integrity's hold on the file goes. other holds (manual, scanners) stay put
  await quarantine.releaseSource(
    { ecosystem: ev.ecosystem, packageName: ev.package_name, version: ev.version, filename: ev.filename },
    'integrity', user, `alert ${status}`
  );
}

// keep what we had. the held copy goes unless something else uses those bytes
async function dismiss(id, user, noteText) {
  const ev = await openEvent(id);
  await close(ev, 'dismissed', user, noteText);
  if (ev.held_sha256) await require('../storage/artifacts').collect([ev.held_sha256]);
  return byId(id);
}

// Take the change.
//  published: drop our copy, the next install downloads what's published now
//  content:   the held bytes become the file, old ones go
async function accept(id, user, noteText) {
  const ev = await openEvent(id);
  const artifacts = require('../storage/artifacts');

  if (ev.kind === 'published') {
    if (ev.ecosystem === 'npm') await require('../registry/npm/cache').dropTarball(ev.package_name, ev.version);
    else if (ev.ecosystem === 'pypi') await require('../registry/pypi/upstream').dropFile(ev.package_name, ev.filename);
    await close(ev, 'accepted', user, noteText);
    return byId(id);
  }

  const held = ev.held_sha256;
  if (!held || !(await store.has(held, ev.held_size === null ? undefined : Number(ev.held_size)))) {
    throw httpError(409, 'the new copy is not on disk anymore, purge the file instead and let it download again');
  }
  const current = await artifacts.find(ev.ecosystem, ev.package_name, ev.version, ev.filename);
  if (current && current.sha256 !== ev.expected && current.sha256 !== held) {
    throw httpError(409, 'that file has changed again since this alert, look at the newer alert instead');
  }

  const metadata = parseMeta(ev.metadata);
  let legacyPath = null;
  if (ev.ecosystem === 'npm') legacyPath = require('../registry/npm/cache').tarballPath(ev.package_name, ev.version);
  else if (ev.ecosystem === 'pypi') legacyPath = require('../registry/pypi/upstream').filePath(ev.package_name, ev.filename);

  await artifacts.replace({
    ecosystem: ev.ecosystem, packageName: ev.package_name, version: ev.version, filename: ev.filename,
    upstream: ev.upstream, metadata, legacyPath
  }, held, Number(ev.held_size));

  // the old tables have to agree, or the previous release (and the source check) would refetch it
  const size = Number(ev.held_size);
  if (ev.ecosystem === 'npm') {
    await packagesRepo.recordTarball({
      name: ev.package_name, version: ev.version, path: legacyPath, size, integrity: (metadata && metadata.integrity) || null, source: ev.upstream
    });
  } else if (ev.ecosystem === 'pypi') {
    await pypiFiles.recordFile({
      project: ev.package_name, version: ev.version, filename: ev.filename, path: legacyPath, size, sha256: held, source: ev.upstream
    });
  }

  await close(ev, 'accepted', user, noteText);
  return byId(id);
}

module.exports = { KINDS, STATUSES, note, checkNpm, checkPypi, byId, accept, dismiss, fingerprint, sha512Of };
