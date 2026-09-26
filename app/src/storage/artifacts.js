// Artifacts: one row per exact file we've seen, any ecosystem.
// Author: Tim Rice
//
// version -> artifact -> sha256 -> immutable blob. old tables and cache paths still get
// written (hard links) so the previous release works after a rollback.
// first digest seen for a file wins, forever. different bytes later never overwrite it.

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const { Transform } = require('stream');
const store = require('./index');
const localDisk = require('./local');
const log = require('../logger');
const rows = require('../db/repositories/artifacts');
const integrityRows = require('../db/repositories/integrity');

const STATUSES = ['unknown', 'quarantined', 'approved', 'blocked'];

function contentTypeFor(filename) {
  const f = String(filename || '').toLowerCase();
  if (f.endsWith('.tgz') || f.endsWith('.tar.gz')) return 'application/gzip';
  if (f.endsWith('.whl') || f.endsWith('.zip') || f.endsWith('.egg')) return 'application/zip';
  if (f.endsWith('.tar.bz2')) return 'application/x-bzip2';
  if (f.endsWith('.tar.xz')) return 'application/x-xz';
  if (f.endsWith('.metadata')) return 'text/plain';
  return 'application/octet-stream';
}

function npmFilename(name, version) {
  const short = String(name).includes('/') ? String(name).split('/')[1] : String(name);
  return `${short}-${version}.tgz`;
}

// ---------------------------------------------------------------- one digest at a time
// store vs delete-if-unused racing on one digest could bin a blob a new row just
// pointed at. so everything per digest queues up. one process, a map of promises does it
const queues = new Map();

function withDigest(sha256, work) {
  const before = queues.get(sha256) || Promise.resolve();
  const run = before.then(() => work());
  const after = run.catch(() => {});
  queues.set(sha256, after);
  after.then(() => {
    if (queues.get(sha256) === after) queues.delete(sha256);
  });
  return run;
}

function parseMeta(value) {
  if (!value) return null;
  if (typeof value === 'object' && !Buffer.isBuffer(value)) return value;
  try {
    return JSON.parse(String(value));
  } catch (err) {
    return null;
  }
}

async function noteBlob(sha256, size) {
  await rows.noteBlob(sha256, size);
}

function find(ecosystem, packageName, version, filename) {
  return rows.fileRow(ecosystem, packageName, version, filename);
}

function byId(id) {
  return rows.rowById(id);
}

// records the file. the sha256 returned is always the first one seen from that registry
async function record(entry) {
  const { ecosystem, packageName, filename, sha256, size, upstream, metadata, firstSeen, cachedAt } = entry;
  const version = entry.version || '';
  let existing = await find(ecosystem, packageName, version, filename);
  const retired = [];

  // rerouted to another registry = a different file, not new bytes. retire the old one
  if (existing && existing.sha256 !== sha256 && existing.upstream && upstream && existing.upstream !== upstream) {
    log.warn(`${ecosystem} ${packageName} ${version} ${filename} came from ${existing.upstream} before and comes from `
      + `${upstream} now, so the copy from ${existing.upstream} is retired`);
    await rows.deleteById(existing.id);
    retired.push(existing.sha256);
    existing = null;
  }

  if (!existing) {
    await noteBlob(sha256, size);
    const result = await rows.createFile({
      ecosystem, name: packageName, version, filename, contentType: contentTypeFor(filename), sha256, size,
      upstream: upstream || null, metadata: metadata ? JSON.stringify(metadata) : null, firstSeen: firstSeen || null, cachedAt: cachedAt || null
    });
    //lost an insert race, read back what won
    if (result.affectedRows !== 1) return { ...(await settle(entry)), retired };
    require('../integrations/events').emit('package.cached', { ecosystem, package: packageName, version, filename, artifactHash: sha256, reason: upstream ? `cached from ${upstream}` : 'cached', action: 'cached' });
    return { id: Number(result.insertId), sha256, created: true, mismatch: null, metadata: metadata || null, retired };
  }
  return { ...(await settle(entry, existing)), retired };
}

async function settle(entry, row) {
  const existing = row || await find(entry.ecosystem, entry.packageName, entry.version, entry.filename);
  const metadata = parseMeta(existing.metadata);
  if (existing.sha256 === entry.sha256) {
    await rows.seenAgain(existing.id, entry.upstream || null);
    return { id: Number(existing.id), sha256: existing.sha256, created: false, mismatch: null, metadata };
  }
  // same name, same registry, different bytes. never overwrite the first one.
  log.error(`${entry.ecosystem} ${entry.packageName} ${entry.version} ${entry.filename} came back as ${entry.sha256}, `
    + `but it was first seen as ${existing.sha256}. Keeping and serving the original`);
  await rows.seen(existing.id);
  return {
    id: Number(existing.id), sha256: existing.sha256, created: false, mismatch: { was: existing.sha256, now: entry.sha256 }, metadata
  };
}

function changedBytes(entry) {
  const e = new Error(`${entry.filename} came back with different bytes from the ones first seen, and that first copy `
    + 'is no longer on disk. An admin can accept the new copy under Integrity alerts');
  e.status = 502;
  e.code = 'ECHANGED';
  return e;
}

// every cached file comes through here. from: { buffer } | { tmp, sha256 } | { file, expected }
async function keep(entry, from) {
  let sha256 = from.sha256;
  let known = null;
  if (from.buffer) sha256 = store.digest(from.buffer);
  else if (from.file) {
    known = await store.hashFile(from.file);
    sha256 = known.sha256;
  }

  const result = await withDigest(sha256, async () => {
    let put;
    if (from.buffer) put = await store.putBuffer(from.buffer, sha256);
    else if (from.tmp) put = await store.adoptTmp(from.tmp, sha256);
    else put = await store.putFile(from.file, from.expected, known);

    const kept = await record({ ...entry, sha256, size: put.size });
    if (!kept.mismatch) {
      if (entry.legacyPath && entry.legacyPath !== from.file) {
        await store.keepLegacyCopy(sha256, entry.legacyPath, { replace: true });
      }
      return { ...kept, size: put.size };
    }
    // ours lost. the new bytes stay held for review, the alert is what keeps them alive
    try {
      await noteBlob(sha256, put.size);
      await require('../policy/integrity').note({
        kind: 'content', ecosystem: entry.ecosystem, packageName: entry.packageName, version: entry.version,
        filename: entry.filename, artifactId: kept.id, upstream: entry.upstream, expected: kept.sha256,
        observed: sha256, heldSha256: sha256, heldSize: put.size, metadata: entry.metadata
      });
    } catch (err) {
      log.error('could not record an integrity alert', err.message);
      if (!put.existed) await dropIfUnused(sha256);
    }
    return kept;
  });

  if (result.retired && result.retired.length) await collect(result.retired);
  // new bytes get a malware scan in the background. no-op while scanning is off
  if (result.created) require('../malware').enqueue(result.sha256);
  if (!result.mismatch) return result;

  // the original has its own digest, so its own queue
  const original = await withDigest(result.sha256, async () => {
    if (!(await store.has(result.sha256)) && entry.legacyPath && entry.legacyPath !== from.file) {
      // only if the old path really is the first copy
      await store.putFile(entry.legacyPath, result.sha256).catch(() => {});
    }
    const s = await store.stat(result.sha256);
    if (!s) return null;
    if (entry.legacyPath && entry.legacyPath !== from.file) {
      await store.keepLegacyCopy(result.sha256, entry.legacyPath, { replace: true });
    }
    return s;
  });
  if (!original) throw changedBytes(entry);
  return { ...result, size: original.size };
}

// points a file at other bytes already in the store. only accepting an integrity alert does this
async function replace(entry, sha256, size) {
  const old = await withDigest(sha256, async () => {
    if (!(await store.has(sha256))) throw new Error('those bytes are not in the blob store');
    await noteBlob(sha256, size);
    const row = await find(entry.ecosystem, entry.packageName, entry.version, entry.filename);
    let previous = null;
    if (row) {
      previous = row.sha256;
      await rows.replaceBytes(row.id, { sha256, size, metadata: entry.metadata ? JSON.stringify(entry.metadata) : null, upstream: entry.upstream || null });
    } else {
      await record({ ...entry, sha256, size });
    }
    if (entry.legacyPath) await store.keepLegacyCopy(sha256, entry.legacyPath, { replace: true });
    return previous;
  });
  if (old && old !== sha256) await collect([old]);
}

// where a cached file's bytes are, or null. a missing blob can come back from the old
// path only if it still hashes right. no row yet = old path like before
async function locate(ecosystem, packageName, version, filename, legacyPath) {
  const row = await find(ecosystem, packageName, version, filename);
  if (row) {
    const size = Number(row.size);
    const hit = { id: Number(row.id), sha256: row.sha256, size, upstream: row.upstream };
    if (await store.has(row.sha256, size)) return hit;
    if (!legacyPath) return null;
    try {
      await withDigest(row.sha256, () => store.putFile(legacyPath, row.sha256));
      log.info(`${ecosystem} ${filename} was missing from the blob store, put it back from its old cache path`);
      return hit;
    } catch (err) {
      if (err.code === 'EDIGEST') {
        log.error(`${ecosystem} ${filename} in the old cache path is not the ${row.sha256} it was first seen as, not serving it`);
      }
      return null;
    }
  }
  if (!legacyPath) return null;
  try {
    const s = await fsp.stat(legacyPath);
    // an empty file is a write that failed, not a cache hit
    if (s.isFile() && s.size) return { id: null, sha256: null, size: s.size, path: legacyPath, legacy: true };
  } catch (err) {
    // not cached
  }
  return null;
}

// the bytes of a cached file. a plain file (old cache path, temporary download) wins, else the blob
// what goes out is checked against the digest it's filed under, as it goes. the last chunk waits until the hash is known,
// so a file that changed on disk never reaches anyone complete: the stream errors, the caller cuts the connection, the
// damaged copy on this disk is dropped (a bucket copy is left alone) and the next download fetches and checks it again.
// an old cache path with no digest on record has nothing to be checked against
function open(found) {
  const file = found.file || found.path;
  const source = file ? fs.createReadStream(file) : store.open(found.sha256);
  const want = String(found.sha256 || '');
  if (!/^[a-f0-9]{64}$/.test(want)) return source;
  const hash = crypto.createHash('sha256');
  let held = null;
  const checked = new Transform({
    transform(chunk, encoding, done) {
      hash.update(chunk);
      const out = held;
      held = chunk;
      done(null, out);
    },
    flush(done) {
      const got = hash.digest('hex');
      if (got === want) return done(null, held);
      log.error(`the stored copy of ${want} now hashes to ${got}. It was not served, and is dropped so the next download fetches it again`);
      withDigest(want, () => localDisk.remove(want)).catch(() => {});
      const e = new Error('the stored copy of this file is damaged, so it was not served');
      e.code = 'EDIGEST';
      return done(e);
    }
  });
  source.on('error', (err) => checked.destroy(err));
  return source.pipe(checked);
}

// small files only, like a .metadata sidecar. the lot in memory
async function readAll(found) {
  const chunks = [];
  for await (const chunk of open(found)) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// counted, never awaited
function touch(id) {
  if (!id) return Promise.resolve();
  return rows.countDownload(id).catch((err) => log.warn('could not count an artifact download', err.message));
}

// ---------------------------------------------------------------- forgetting

// the caller holds this digest's queue. an open integrity alert holding the bytes counts as a user
async function dropIfUnused(sha256) {
  if (await rows.anyWithDigest(sha256)) return false;
  if (await integrityRows.holdsDigest(sha256)) return false;
  await store.remove(sha256);
  await rows.deleteBlob(sha256);
  return true;
}

// blobs can be shared, one only goes with its last artifact
async function collect(digests) {
  let removed = 0;
  for (const sha256 of new Set(digests)) {
    if (await withDigest(sha256, () => dropIfUnused(sha256))) removed += 1;
  }
  return removed;
}

async function forget(scope) {
  const found = await rows.filesIn(scope);
  if (!found.length) return 0;
  await rows.deleteIds(found.map((r) => r.id));
  await collect(found.map((r) => r.sha256));
  return found.length;
}

function forgetPackage(ecosystem, packageName) {
  return forget({ ecosystem, packageName });
}

function forgetVersion(ecosystem, packageName, version) {
  return forget({ ecosystem, packageName, version });
}

function forgetFile(ecosystem, packageName, filename) {
  return forget({ ecosystem, packageName, filename });
}

// rows only. emptying the whole cache clears the disk in one go afterward
async function forgetAll() {
  await rows.deleteAll();
  await rows.deleteAllBlobs();
}

module.exports = {
  STATUSES,
  contentTypeFor,
  npmFilename,
  parseMeta,
  find,
  byId,
  record,
  keep,
  replace,
  locate,
  open,
  readAll,
  touch,
  forgetPackage,
  forgetVersion,
  forgetFile,
  forgetAll,
  collect
};
