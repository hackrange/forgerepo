// Adopts everything that was cached before artifacts existed.
// Author: Tim Rice
//
// hash, hard link into the blob store, write the row. only looks at files with no row
// so a restart just carries on, and it naps between files so installs don't notice.

const fsp = require('fs/promises');
const store = require('./index');
const artifacts = require('./artifacts');
const cache = require('../registry/npm/cache');
const log = require('../logger');
const packages = require('../db/repositories/packages');
const pypiFiles = require('../db/repositories/pypi-files');

const BATCH = 200;
const PAUSE_EVERY = 25;
const PAUSE_MS = 20;

let job = null;

function idle() {
  return { running: false, startedAt: null, finishedAt: null, npm: tally(), pypi: tally(), errors: [] };
}

function tally() {
  return { adopted: 0, missing: 0, corrupt: 0, failed: 0 };
}

function status() {
  return job ? { ...job, npm: { ...job.npm }, pypi: { ...job.pypi }, errors: job.errors.slice(0, 20) } : idle();
}

const nap = () => new Promise((resolve) => setTimeout(resolve, PAUSE_MS));

// a zero byte file is a download that died, not something to adopt
async function usable(file) {
  const s = await fsp.stat(file);
  if (!s.isFile() || !s.size) {
    const e = new Error('empty');
    e.code = 'ENOENT';
    throw e;
  }
}

async function adoptNpm(current) {
  let after = 0;
  for (;;) {
    const rows = await packages.tarballsWithoutArtifacts(after, BATCH);
    if (!rows.length) return;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      after = row.id;
      if (!current.running) return;
      const file = row.path || cache.tarballPath(row.package_name, row.version);
      try {
        await usable(file);
        await artifacts.keep({
          ecosystem: 'npm',
          packageName: row.package_name,
          version: row.version,
          filename: artifacts.npmFilename(row.package_name, row.version),
          upstream: row.source,
          metadata: row.integrity ? { integrity: row.integrity } : null,
          firstSeen: row.cached_at,
          cachedAt: row.cached_at,
          legacyPath: file
        }, { file });
        current.npm.adopted += 1;
      } catch (err) {
        if (err.code === 'ENOENT') current.npm.missing += 1;
        else {
          current.npm.failed += 1;
          current.errors.push(`npm ${row.package_name}@${row.version}: ${err.message}`);
        }
      }
      if (i % PAUSE_EVERY === 0) await nap();
    }
  }
}

async function adoptPypi(current) {
  let after = 0;
  for (;;) {
    const rows = await pypiFiles.filesWithoutArtifacts(after, BATCH);
    if (!rows.length) return;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      after = row.id;
      if (!current.running) return;
      try {
        await usable(row.path);
        // the PyPI side hashed these when they came down, so hold them to it
        await artifacts.keep({
          ecosystem: 'pypi',
          packageName: row.project,
          version: row.version,
          filename: row.filename,
          upstream: row.source,
          metadata: null,
          firstSeen: row.cached_at,
          cachedAt: row.cached_at,
          legacyPath: row.path
        }, { file: row.path, expected: row.sha256 || undefined });
        current.pypi.adopted += 1;
      } catch (err) {
        if (err.code === 'ENOENT') current.pypi.missing += 1;
        else if (err.code === 'EDIGEST') {
          current.pypi.corrupt += 1;
          log.error(`${row.filename} on disk no longer matches the sha256 it was cached with, leaving it out of the blob store`);
        } else {
          current.pypi.failed += 1;
          current.errors.push(`pypi ${row.filename}: ${err.message}`);
        }
      }
      if (i % PAUSE_EVERY === 0) await nap();
    }
  }
}

async function run(current) {
  try {
    await store.init();
    const swept = await store.sweepTmp();
    if (swept) log.info(`cleared ${swept} half written file(s) out of the blob store's temp directory`);
    await adoptNpm(current);
    await adoptPypi(current);
    const moved = current.npm.adopted + current.pypi.adopted;
    if (moved || current.npm.missing || current.pypi.missing) {
      log.info(`artifact backfill: ${current.npm.adopted} npm and ${current.pypi.adopted} PyPI file(s) adopted, `
        + `${current.npm.missing + current.pypi.missing} listed but not on disk, `
        + `${current.pypi.corrupt} not matching their recorded hash, ${current.npm.failed + current.pypi.failed} failed`);
    }
  } catch (err) {
    current.errors.push(err.message);
    log.error('artifact backfill stopped', err.message);
  }
  current.running = false;
  current.finishedAt = new Date().toISOString();
}

// safe to call twice
function start() {
  if (job && job.running) return status();
  job = { ...idle(), running: true, startedAt: new Date().toISOString() };
  const mine = job;
  run(mine).catch(() => {});
  return status();
}

function stop() {
  if (job) job.running = false;
  return status();
}

module.exports = { start, stop, status };
