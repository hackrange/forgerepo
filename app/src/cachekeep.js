// Cache housekeeping: rows vs disk, put back what wandered off, drop what the rules block.
// Author: Tim Rice
//
// db and disk drift (restores, full disks, hand cleanup). with the upstream off a missing
// file is a 503 mid build, so better to find out while it's still on. npm and PyPI both.

const fsp = require('fs/promises');
const path = require('path');
const packages = require('./db/repositories/packages');
const packuments = require('./db/repositories/packuments');
const pypiFiles = require('./db/repositories/pypi-files');
const pypiDocs = require('./db/repositories/pypi-documents');
const artifactRows = require('./db/repositories/artifacts');
const cache = require('./registry/npm/cache');
const policy = require('./policy');
const upstream = require('./registry/npm/upstream');
const pypi = require('./registry/pypi/upstream');
const artifacts = require('./storage/artifacts');
const store = require('./storage');
const ecosystems = require('./ecosystems');
const warm = require('./warm');
const log = require('./logger');

//stat calls are cheap, downloads are not
const STAT_CONCURRENCY = 64;
const FETCH_CONCURRENCY = 4;

let job = null;

function idle() {
  return {
    running: false, kind: null, startedAt: null, finishedAt: null, by: null,
    total: 0, done: 0, ok: 0, missing: 0, truncated: 0, orphans: 0, blocked: 0,
    repaired: 0, removed: 0, failed: 0, bytesFreed: 0, current: null, notes: [], errors: []
  };
}

function status() {
  return job ? { ...job, notes: job.notes.slice(0, 50), errors: job.errors.slice(0, 50) } : idle();
}

function running() {
  return !!(job && job.running);
}

function busy(what) {
  if (running()) {
    const e = new Error(`cache ${job.kind} is already running, wait for it to finish`);
    e.status = 409;
    throw e;
  }
  if (warm.running()) {
    const e = new Error(`a cache warm is running, ${what} would fight with it for the upstream`);
    e.status = 409;
    throw e;
  }
}

// a few at a time, the OS objects to ten thousand open handles
async function mapLimit(items, limit, worker) {
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      await worker(items[i], i);
    }
  });
  await Promise.all(runners);
}

// ---------------------------------------------------------------- what's cached, both kinds

async function cachedRows() {
  const npm = await packages.allTarballs();
  const py = await pypiFiles.allFiles();
  return [
    ...npm.map((r) => ({
      ecosystem: 'npm', name: r.package_name, version: r.version, filename: artifacts.npmFilename(r.package_name, r.version),
      path: r.path, size: r.size, label: `${r.package_name}@${r.version}`
    })),
    ...py.map((r) => ({
      ecosystem: 'pypi', name: r.project, version: r.version, filename: r.filename, path: r.path, size: r.size,
      label: `${r.project} ${r.filename}`
    }))
  ];
}

const fileKey = (r) => `${r.ecosystem}\n${r.name}\n${r.version}\n${r.filename}`;

async function blobIndex() {
  const rows = await artifactRows.fileIndex();
  return new Map(rows.map((r) => [fileKey({ ecosystem: r.ecosystem, name: r.package_name, version: r.version, filename: r.filename }), r]));
}

async function verdictFor(row) {
  if (row.ecosystem === 'pypi') {
    // no version on the row means we can't ask, so leave it be
    if (!row.version) return { allowed: true };
    return policy.allowedAnywhere(row.name, row.version, ecosystems.adapter('pypi'));
  }
  // allowed for any application counts, or housekeeping throws out what dev may use
  return policy.allowedAnywhere(row.name, row.version);
}

// one file gone from every table and the disk. PyPI metadata files are their own rows
async function dropRow(row) {
  if (row.ecosystem === 'npm') return cache.dropTarball(row.name, row.version);
  await fsp.unlink(row.path).catch(() => {});
  await pypiFiles.deleteFile(row.name, row.filename);
  await artifacts.forgetFile('pypi', row.name, row.filename);
}

async function fetchRow(row) {
  if (row.ecosystem === 'npm') return upstream.getTarball(row.name, row.version);
  const metadata = row.filename.endsWith('.metadata');
  const filename = metadata ? row.filename.slice(0, -'.metadata'.length) : row.filename;
  return pypi.getFile(row.name, filename, row.version, { metadata });
}

// ---------------------------------------------------------------- audit

// read only, run it whenever. a row is fine if its old path OR its blob is whole, serving copes with either
async function inspect(onProgress) {
  const rows = await cachedRows();
  const blobs = await blobIndex();
  const missing = [];
  const truncated = [];
  let ok = 0;

  await mapLimit(rows, STAT_CONCURRENCY, async (row) => {
    const want = Number(row.size) || 0;
    const artifact = blobs.get(fileKey(row));
    row.blob = artifact && (await store.has(artifact.sha256, Number(artifact.size))) ? artifact.sha256 : null;
    // with a bucket the old cache paths go with their local copies on purpose, the blob is the file
    if (row.blob && store.kind === 'bucket') {
      ok += 1;
      if (onProgress) onProgress();
      return;
    }
    try {
      const stat = await fsp.stat(row.path);
      // a zero byte or short file is a write that failed, not a cache hit
      if (!stat.size || (want > 0 && stat.size !== want)) {
        if (row.blob) row.relink = true;
        else truncated.push({ ...row, actual: stat.size });
      }
      if (!row.relink && stat.size && !(want > 0 && stat.size !== want)) ok += 1;
      else if (row.relink) missing.push(row);
    } catch (err) {
      if (row.blob) row.relink = true;
      missing.push(row);
    }
    if (onProgress) onProgress();
  });

  return { rows, ok, missing, truncated };
}

// files no row points at, usually a db restore older than the disk
async function findOrphans(rows) {
  const known = new Set(rows.map((r) => r.path));
  const found = [];
  const walk = async (dir) => {
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch (err) {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      // .tmp is a download still in flight, not an orphan
      else if (entry.isFile() && !known.has(full) && !full.endsWith('.tmp')) found.push(full);
    }
  };
  await walk(cache.tarDir);
  await walk(pypi.fileDir);
  return found;
}

// ---------------------------------------------------------------- the jobs

async function runAudit(actor) {
  job = { ...idle(), running: true, kind: 'audit', startedAt: new Date().toISOString(), by: actor };
  try {
    const { rows, ok, missing, truncated } = await inspect(() => { job.done += 1; });
    job.total = rows.length;
    job.ok = ok;
    job.missing = missing.length;
    job.truncated = truncated.length;

    const orphans = await findOrphans(rows);
    job.orphans = orphans.length;

    let blocked = 0;
    for (const row of rows) {
      const verdict = await verdictFor(row);
      if (!verdict.allowed) blocked += 1;
    }
    job.blocked = blocked;

    const relinkable = missing.filter((r) => r.relink).length;
    missing.slice(0, 25).forEach((r) => job.notes.push(`missing on disk: ${r.label}${r.relink ? ' (still in the blob store, recache puts it back without a download)' : ''}`));
    truncated.slice(0, 25).forEach((r) => job.notes.push(`wrong size: ${r.label}, database says ${r.size} bytes, disk has ${r.actual}`));
    if (relinkable) job.notes.push(`${relinkable} of the missing file(s) can be put back from the blob store`);
    if (orphans.length) job.notes.push(`${orphans.length} file(s) on disk that no row points at`);
    if (blocked) job.notes.push(`${blocked} cached file(s) are blocked by the rules and cannot be served`);
    if (!missing.length && !truncated.length && !orphans.length) job.notes.push('every row matches a real file');
  } catch (err) {
    job.failed += 1;
    job.errors.push(err.message);
  }
  job.running = false;
  job.finishedAt = new Date().toISOString();
  log.info(`cache audit: ${job.ok} ok, ${job.missing} missing, ${job.truncated} wrong size, ${job.orphans} orphaned, ${job.blocked} blocked`);
  return job;
}

// puts back missing files. from the blob store when it has them, else the upstream.
// blocked ones get dropped, no point fetching what we won't serve
async function runRecacheMissing(actor) {
  job = { ...idle(), running: true, kind: 'recache', startedAt: new Date().toISOString(), by: actor };
  try {
    const { ok, missing, truncated } = await inspect();
    job.ok = ok;
    job.missing = missing.length;
    job.truncated = truncated.length;

    const broken = [...missing, ...truncated];
    job.total = broken.length;
    if (!broken.length) {
      job.notes.push('nothing to put back, every row already matches a real file');
    }
    const needsUpstream = broken.some((r) => !r.relink);
    if (needsUpstream && !upstream.upstreamEnabled()) {
      job.notes.push('the upstream registry is switched off, so only files still in the blob store can be put back');
    }

    await mapLimit(broken, FETCH_CONCURRENCY, async (row) => {
      if (!job.running) return;
      job.current = row.label;
      try {
        const verdict = await verdictFor(row);
        if (!verdict.allowed) {
          await dropRow(row);
          job.removed += 1;
          job.notes.push(`${row.label}: ${verdict.reason}, dropped rather than fetched again`);
        } else if (row.relink) {
          await store.keepLegacyCopy(row.blob, row.path, { replace: true });
          job.repaired += 1;
        } else if (upstream.upstreamEnabled()) {
          // clear the stale row first so a failed fetch can't leave a lie behind
          await dropRow(row);
          await fetchRow(row);
          job.repaired += 1;
        } else {
          job.failed += 1;
          job.errors.push(`${row.label}: not in the blob store and the upstream is off`);
        }
      } catch (err) {
        job.failed += 1;
        job.errors.push(`${row.label}: ${err.message}`);
      }
      job.done += 1;
    });

    const orphans = await findOrphans(await cachedRows());
    job.orphans = orphans.length;
    for (const file of orphans) {
      try {
        const stat = await fsp.stat(file);
        await fsp.unlink(file);
        job.bytesFreed += stat.size;
      } catch (err) {
        /* already gone, fine */
      }
    }
    if (orphans.length) job.notes.push(`removed ${orphans.length} orphaned file(s) no row pointed at`);
  } catch (err) {
    job.failed += 1;
    job.errors.push(err.message);
  }
  job.running = false;
  job.current = null;
  job.finishedAt = new Date().toISOString();
  log.info(`cache recache: ${job.repaired} put back, ${job.removed} dropped, ${job.failed} failed, ${job.orphans} orphans cleared`);
  return job;
}

// blocked files can never be served, pure disk cost. definitely not staying
async function runPurgeBlocked(actor) {
  job = { ...idle(), running: true, kind: 'purge', startedAt: new Date().toISOString(), by: actor };
  try {
    const rows = await cachedRows();
    job.total = rows.length;

    const doomed = [];
    for (const row of rows) {
      const verdict = await verdictFor(row);
      if (!verdict.allowed) doomed.push(row);
      job.done += 1;
    }
    job.blocked = doomed.length;

    for (const row of doomed) {
      if (!job.running) break;
      try {
        await dropRow(row);
        job.removed += 1;
        job.bytesFreed += Number(row.size || 0);
      } catch (err) {
        job.failed += 1;
        job.errors.push(`${row.label}: ${err.message}`);
      }
    }

    //metadata for a package with nothing left cached is dead weight too, separate table same idea
    const stale = await packuments.forgetUncached();
    const stalePages = await pypiDocs.forgetUncached();
    const pages = stale.affectedRows + stalePages.affectedRows;
    if (pages) job.notes.push(`also cleared ${pages} cached metadata document(s) for packages with nothing left on disk`);
    if (!doomed.length) job.notes.push('nothing cached is blocked, there was nothing to remove');
  } catch (err) {
    job.failed += 1;
    job.errors.push(err.message);
  }
  job.running = false;
  job.finishedAt = new Date().toISOString();
  log.info(`cache purge: removed ${job.removed} blocked file(s), freed ${job.bytesFreed} bytes`);
  return job;
}

// ---------------------------------------------------------------- starters (the portal buttons land here)

function startAudit(actor) {
  busy('an audit');
  runAudit(actor).catch((err) => finish(err));
  return status();
}

// the upstream is only needed for files the blob store can't put back, so no longer refused up front
function startRecacheMissing(actor) {
  busy('a recache');
  runRecacheMissing(actor).catch((err) => finish(err));
  return status();
}

function startPurgeBlocked(actor) {
  busy('a purge');
  runPurgeBlocked(actor).catch((err) => finish(err));
  return status();
}

function finish(err) {
  log.error('cache maintenance blew up', err.message);
  if (job) {
    job.running = false;
    job.errors.push(err.message);
    job.finishedAt = new Date().toISOString();
  }
}

function cancel() {
  if (job && job.running) {
    job.running = false;
    job.notes.push('canceled');
  }
  return status();
}

module.exports = { startAudit, startRecacheMissing, startPurgeBlocked, status, cancel, running };
