// Tarballs live on disk, metadata lives in the database. Everyone has their own room.
// Author: Tim Rice

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');
const config = require('../../config');
const packages = require('../../db/repositories/packages');
const packuments = require('../../db/repositories/packuments');
const log = require('../../logger');
const store = require('../../storage');
const artifacts = require('../../storage/artifacts');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

const tarDir = path.join(config.cacheDir, 'tarballs');

async function init() {
  await fsp.mkdir(tarDir, { recursive: true });
  await store.init();
  await require('../pypi/upstream').init();
}

// hash the key so a weird package name (../../etc, anyone?) can never walk out of the cache dir
function tarballPath(name, version) {
  const hash = crypto.createHash('sha256').update(`${name}@${version}`).digest('hex');
  return path.join(tarDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.tgz`);
}

// row says where it came from. a file we can't place isn't handed out
async function getTarball(name, version) {
  try {
    const row = await packages.tarballSource(name, version);
    const found = await artifacts.locate('npm', name, version, artifacts.npmFilename(name, version), tarballPath(name, version));
    if (!found) return null;
    return { file: found.path || null, sha256: found.sha256, size: found.size, source: row ? row.source : null, artifactId: found.id };
  } catch (err) {
    return null;
  }
}

async function putTarball(name, version, buffer, integrity, source) {
  const file = tarballPath(name, version);
  // blob store first, the old path becomes a hard link to it
  const kept = await artifacts.keep({
    ecosystem: 'npm',
    packageName: name,
    version,
    filename: artifacts.npmFilename(name, version),
    upstream: source,
    metadata: integrity ? { integrity } : null,
    legacyPath: file
  }, { buffer });
  // first copy wins. when that's not what just came down, the row keeps describing the first copy
  const keptIntegrity = kept.mismatch ? (kept.metadata && kept.metadata.integrity) || null : integrity;

  await packages.recordTarball({ name, version, path: file, size: kept.size, integrity: keptIntegrity || null, source: source || null });
  return { file: null, sha256: kept.sha256, size: kept.size, source: source || null, artifactId: kept.id };
}

async function touchTarball(name, version) {
  await packages.touchTarball(name, version);
}

async function dropTarball(name, version) {
  const row = await packages.tarballRow(name, version);
  const file = row ? row.path : tarballPath(name, version);
  await fsp.unlink(file).catch(() => {});
  await packages.deleteTarball(name, version);
  await artifacts.forgetVersion('npm', name, version);
}

async function dropPackage(name) {
  const rows = await packages.tarballPaths(name);
  for (const row of rows) await fsp.unlink(row.path).catch(() => {});
  await packages.deleteTarballs(name);
  await packuments.forget(name);
  await artifacts.forgetPackage('npm', name);
}

// a tarball download written to a temp file and hashed on the way in, so a big one costs disk, not the box's memory
async function spoolTarball(stream, name, version) {
  const into = tarballPath(name, version);
  await fsp.mkdir(path.dirname(into), { recursive: true });
  const tmp = `${into}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const sums = { sha256: crypto.createHash('sha256'), sha512: crypto.createHash('sha512'), sha1: crypto.createHash('sha1') };
  let size = 0;
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      stream.on('data', (chunk) => {
        size += chunk.length;
        for (const h of Object.values(sums)) h.update(chunk);
      });
      stream.on('error', (err) => {
        out.destroy();
        reject(err);
      });
      out.on('error', reject);
      out.on('finish', resolve);
      stream.pipe(out);
    });
  } catch (err) {
    await fsp.unlink(tmp).catch(() => {});
    throw err;
  }
  const sha1 = sums.sha1.digest();
  return { tmp, size, sha256: sums.sha256.digest('hex'), sha512: sums.sha512.digest('base64'), sha1: sha1.toString('base64'), shasum: sha1.toString('hex') };
}

// the same rules as verifyIntegrity, for a file that was hashed as it came in
function spooledMatches(got, integrity, shasum) {
  if (integrity && integrity.startsWith('sha512-')) return got.sha512 === integrity.slice(7);
  if (integrity && integrity.startsWith('sha1-')) return got.sha1 === integrity.slice(5);
  if (shasum) return got.shasum === shasum;
  // nothing to check against, so wave it through
  return true;
}

// putTarball for a spooled file. the blob store adopts the temp file instead of copying bytes out of memory
async function putTarballFile(name, version, got, integrity, source) {
  const file = tarballPath(name, version);
  const kept = await artifacts.keep({
    ecosystem: 'npm',
    packageName: name,
    version,
    filename: artifacts.npmFilename(name, version),
    upstream: source,
    metadata: integrity ? { integrity } : null,
    legacyPath: file
  }, { tmp: got.tmp, sha256: got.sha256 });
  const keptIntegrity = kept.mismatch ? (kept.metadata && kept.metadata.integrity) || null : integrity;
  await packages.recordTarball({ name, version, path: file, size: kept.size, integrity: keptIntegrity || null, source: source || null });
  return { file: null, sha256: kept.sha256, size: kept.size, source: source || null, artifactId: kept.id };
}

function verifyIntegrity(buffer, integrity, shasum) {
  if (integrity && integrity.startsWith('sha512-')) {
    const want = integrity.slice(7);
    const got = crypto.createHash('sha512').update(buffer).digest('base64');
    return got === want;
  }
  if (integrity && integrity.startsWith('sha1-')) {
    const want = integrity.slice(5);
    const got = crypto.createHash('sha1').update(buffer).digest('base64');
    return got === want;
  }
  if (shasum) {
    const got = crypto.createHash('sha1').update(buffer).digest('hex');
    return got === shasum;
  }
  // nothing to check against, so wave it through
  return true;
}

async function getPackument(name, variant) {
  const row = await packuments.get(name, variant);
  if (!row) return null;
  try {
    const json = JSON.parse((await gunzip(row.body)).toString('utf8'));
    return { doc: json, etag: row.etag, source: row.source, fetchedAt: new Date(row.fetched_at) };
  } catch (err) {
    log.warn('could not read cached metadata for', name, err.message);
    return null;
  }
}

async function putPackument(name, variant, doc, etag, source) {
  const body = await gzip(Buffer.from(JSON.stringify(doc), 'utf8'));
  await packuments.put(name, variant, body, source || null, etag || null);
}

async function touchPackumentTime(name, variant) {
  await packuments.touch(name, variant);
}

async function stats() {
  const tar = await packages.tarballTotals();
  const pack = await packuments.totals();
  return {
    tarballs: Number(tar.files),
    tarballBytes: Number(tar.bytes),
    packuments: Number(pack.docs),
    packumentBytes: Number(pack.bytes)
  };
}

async function purgeAll() {
  await fsp.rm(tarDir, { recursive: true, force: true });
  await fsp.mkdir(tarDir, { recursive: true });
  await packages.deleteAllTarballs();
  await packuments.deleteAll();
  await require('../pypi/upstream').purgeAll();
  // blobs last. rows first, so nothing gets served from a blob that's halfway gone
  await artifacts.forgetAll();
  await store.purgeAll();
}

module.exports = {
  init,
  tarDir,
  tarballPath,
  getTarball,
  putTarball,
  spoolTarball,
  spooledMatches,
  putTarballFile,
  touchTarball,
  dropTarball,
  dropPackage,
  verifyIntegrity,
  getPackument,
  putPackument,
  touchPackumentTime,
  stats,
  purgeAll,
  openTarball: (result) => artifacts.open(result)
};
