// npm packages seen, and the tarballs cached for them.
// Author: Tim Rice

const db = require('../../db');

const SORTS = { name: 'p.name', hits: 'p.hits', last: 'p.last_access' };

// search arrives already escaped for LIKE
async function page(search, { sort, dir, limit, offset }) {
  const clause = search ? 'WHERE p.name LIKE ?' : '';
  const params = search ? [search] : [];
  const order = SORTS[String(sort || '').toLowerCase()] || 'p.last_access';
  const direction = dir === 'asc' ? 'ASC' : 'DESC';
  const rows = await db.query(
    `SELECT p.name, p.hits, p.blocked_hits, p.first_seen, p.last_access,
            (SELECT COUNT(*) FROM tarballs t WHERE t.package_name = p.name) AS cached_versions,
            (SELECT COALESCE(SUM(t.size),0) FROM tarballs t WHERE t.package_name = p.name) AS cached_bytes
       FROM packages p ${clause} ORDER BY ${order} ${direction} LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM packages p ${clause}`, params);
  return { rows, total: Number(total.n) };
}

function versions(name) {
  return db.query(
    'SELECT version, size, cached_at, last_access, hits FROM tarballs WHERE package_name = ? ORDER BY cached_at DESC',
    [name]
  );
}

async function cachedBytes(name) {
  return Number((await db.one('SELECT COALESCE(SUM(size),0) AS bytes FROM tarballs WHERE package_name = ?', [name])).bytes || 0);
}

// a tarball went out, so this is a real package and not a scanner guessing names
function countServed(name) {
  return db.query(
    `INSERT INTO packages (name, first_seen, last_access, hits, blocked_hits)
     VALUES (?, NOW(), NOW(), 1, 0)
     ON DUPLICATE KEY UPDATE last_access = NOW(), hits = hits + 1`,
    [name]
  );
}

// blocked only bumps an existing row, never makes one
function countBlocked(name) {
  return db.query('UPDATE packages SET blocked_hits = blocked_hits + 1, last_access = NOW() WHERE name = ?', [name]);
}

function forget(name) {
  return db.query('DELETE FROM packages WHERE name = ?', [name]);
}

function tarballVersions(name) {
  return db.query('SELECT version FROM tarballs WHERE package_name = ?', [name]);
}

// served the most, at least minHits times
function busiest(minHits, limit) {
  return db.query('SELECT name FROM packages WHERE hits >= ? ORDER BY hits DESC LIMIT ?', [minHits, limit]);
}

// the legacy tarballs row for a file the artifact store now holds
function recordTarball({ name, version, path, size, integrity, source }) {
  return db.query(
    `INSERT INTO tarballs (package_name, version, path, size, integrity, source, cached_at, last_access, hits)
     VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW(), 0)
     ON DUPLICATE KEY UPDATE path = VALUES(path), size = VALUES(size), integrity = VALUES(integrity),
       source = VALUES(source), cached_at = NOW()`,
    [name, version, path, size, integrity, source]
  );
}

// legacy tarball rows the artifact store has not adopted yet, in id order
function tarballsWithoutArtifacts(after, limit) {
  return db.query(
    `SELECT t.id, t.package_name, t.version, t.path, t.source, t.integrity, t.cached_at
       FROM tarballs t
       LEFT JOIN artifacts a
         ON a.ecosystem = 'npm' AND a.package_name = t.package_name AND a.version = t.version
        AND a.filename = CONCAT(SUBSTRING_INDEX(t.package_name, '/', -1), '-', t.version, '.tgz')
      WHERE a.id IS NULL AND t.id > ?
      ORDER BY t.id LIMIT ?`,
    [after, limit]
  );
}

function tarballSource(name, version) {
  return db.one('SELECT source FROM tarballs WHERE package_name = ? AND version = ?', [name, version]);
}

function tarballRow(name, version) {
  return db.one('SELECT path FROM tarballs WHERE package_name = ? AND version = ?', [name, version]);
}

function touchTarball(name, version) {
  return db.query('UPDATE tarballs SET hits = hits + 1, last_access = NOW() WHERE package_name = ? AND version = ?', [name, version]);
}

function deleteTarball(name, version) {
  return db.query('DELETE FROM tarballs WHERE package_name = ? AND version = ?', [name, version]);
}

function tarballPaths(name) {
  return db.query('SELECT path FROM tarballs WHERE package_name = ?', [name]);
}

function deleteTarballs(name) {
  return db.query('DELETE FROM tarballs WHERE package_name = ?', [name]);
}

function tarballTotals() {
  return db.one('SELECT COUNT(*) AS files, COALESCE(SUM(size),0) AS bytes FROM tarballs');
}

function deleteAllTarballs() {
  return db.query('DELETE FROM tarballs');
}

// every cached tarball, for housekeeping to check against the disk
function allTarballs() {
  return db.query('SELECT package_name, version, path, size FROM tarballs');
}

// PyPI projects and images have no packages table, what the store holds is the list. search arrives escaped for LIKE
const STORE_SORTS = { name: 'name', hits: 'hits', last: 'last_access' };
// an image's files don't count downloads. a pull asks for its tag once and everything else by digest, so the
// traffic log's tag requests are the pulls, for as long as the log is kept
const PULLS = `(SELECT COUNT(*) FROM access_log l WHERE l.package_name = artifacts.package_name AND l.ecosystem = 'oci'
       AND l.action = 'allow' AND l.method IN ('GET', 'HEAD') AND l.path LIKE '%/manifests/%' AND l.version NOT LIKE 'sha256:%')`;
// a pull of an image docker already has the layers for only fetches the manifest, and manifests aren't in artifacts
const LAST_PULL = `(SELECT MAX(l.ts) FROM access_log l WHERE l.package_name = artifacts.package_name AND l.ecosystem = 'oci'
       AND l.action = 'allow' AND l.method IN ('GET', 'HEAD') AND l.path LIKE '%/manifests/%')`;
async function storedPage(ecosystem, search, { sort, dir, limit, offset }) {
  const where = search ? 'AND package_name LIKE ?' : '';
  const params = search ? [ecosystem, search] : [ecosystem];
  const order = STORE_SORTS[String(sort || '').toLowerCase()] || 'last_access';
  const direction = dir === 'asc' ? 'ASC' : 'DESC';
  const rows = await db.query(
    `SELECT package_name AS name, ${ecosystem === 'oci' ? PULLS : 'SUM(download_count)'} AS hits, MIN(first_seen) AS first_seen,
            ${ecosystem === 'oci' ? `GREATEST(MAX(COALESCE(last_access, first_seen)), COALESCE(${LAST_PULL}, MAX(COALESCE(last_access, first_seen))))` : 'MAX(COALESCE(last_access, first_seen))'} AS last_access,
            COUNT(*) AS files, COALESCE(SUM(size), 0) AS cached_bytes, COUNT(DISTINCT NULLIF(version, '')) AS cached_versions
       FROM artifacts WHERE ecosystem = ? ${where} GROUP BY package_name ORDER BY ${order} ${direction} LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(DISTINCT package_name) AS n FROM artifacts WHERE ecosystem = ? ${where}`, params);
  return { rows, total: Number(total.n) };
}

module.exports = { storedPage, tarballSource, tarballRow, touchTarball, deleteTarball, tarballPaths, deleteTarballs, tarballTotals, deleteAllTarballs, allTarballs, SORTS, page, versions, cachedBytes, tarballVersions, busiest, recordTarball, countServed, countBlocked, forget, tarballsWithoutArtifacts };
