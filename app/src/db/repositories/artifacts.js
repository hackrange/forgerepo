// Cached files for the portal: the list, and everything known about one file.
// Author: Tim Rice
// recording and forgetting files lives in artifacts.js, this is only what the pages read

const db = require('../../db');
const { likeTerm } = require('../../lib/validate');

const SORTS = {
  first: 'a.first_seen', last: 'a.last_access', downloads: 'a.download_count', name: 'a.package_name', size: 'a.size'
};

const SAME_FILE = 'p.ecosystem = a.ecosystem AND p.package_name = a.package_name AND p.version = a.version AND p.filename = a.filename';

function filterClause(f) {
  const where = [];
  const params = [];
  if (f.licensed === 'unchecked') {
    where.push('a.license_checked_at IS NULL');
  } else if (f.licensed) {
    where.push('a.license_checked_at IS NOT NULL AND a.license_verdict = ?');
    params.push(f.licensed);
  }
  if (f.ecosystem) {
    where.push('a.ecosystem = ?');
    params.push(f.ecosystem);
  }
  if (f.proven === 'unchecked') {
    where.push(`NOT EXISTS (SELECT 1 FROM provenance p WHERE ${SAME_FILE})`);
  } else if (f.proven) {
    where.push(`EXISTS (SELECT 1 FROM provenance p WHERE ${SAME_FILE} AND p.status = ?)`);
    params.push(f.proven);
  }
  if (f.property) {
    const m = require('./properties').matchClause('a', f.property);
    where.push(m.sql);
    params.push(...m.params);
  }
  if (f.stage) {
    const m = require('./lifecycle').matchClause('a', f.stage);
    where.push(m.sql);
    params.push(...m.params);
  }
  if (f.status) {
    where.push('a.status = ?');
    params.push(f.status);
  }
  if (f.search) {
    const term = likeTerm(f.search);
    //could be the front of a pasted digest
    const hex = f.search.toLowerCase().replace(/^sha256:/, '');
    if (/^[0-9a-f]{6,64}$/.test(hex)) {
      where.push('(a.sha256 LIKE ? OR a.package_name LIKE ? OR a.filename LIKE ?)');
      params.push(`${hex}%`, term, term);
    } else {
      where.push('(a.package_name LIKE ? OR a.filename LIKE ?)');
      params.push(term, term);
    }
  }
  return { clause: where.length ? `WHERE ${where.join(' AND ')}` : '', params };
}

async function page(filters, { sort, dir, limit, offset }) {
  const { clause, params } = filterClause(filters);
  const order = SORTS[String(sort || '').toLowerCase()] || 'a.first_seen';
  const direction = dir === 'asc' ? 'ASC' : 'DESC';
  const rows = await db.query(
    `SELECT a.id, a.ecosystem, a.package_name, a.version, a.filename, a.sha256, a.size, a.upstream,
            a.first_seen, a.last_access, a.download_count, a.status,
            a.license_expression, a.license_verdict, a.license_checked_at,
            (SELECT p.status FROM provenance p WHERE ${SAME_FILE}) AS provenance_status
       FROM artifacts a ${clause} ORDER BY ${order} ${direction}, a.id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n, COALESCE(SUM(a.size),0) AS bytes FROM artifacts a ${clause}`, params);
  return { rows, total: Number(total.n), bytes: Number(total.bytes) };
}

async function blobTotals() {
  const row = await db.one('SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS bytes FROM blobs');
  return { count: Number(row.n), bytes: Number(row.bytes) };
}

function blobLedger(sha256) {
  return db.one('SELECT created_at, verified_at FROM blobs WHERE sha256 = ?', [sha256]);
}

function markVerified(sha256) {
  return db.query('UPDATE blobs SET verified_at = NOW() WHERE sha256 = ?', [sha256]);
}

// other artifacts pointing at the same bytes
async function sharedCount(sha256, exceptId) {
  return Number((await db.one('SELECT COUNT(*) AS n FROM artifacts WHERE sha256 = ? AND id <> ?', [sha256, exceptId])).n);
}

const fileKey = (row) => [row.ecosystem, row.package_name, row.version, row.filename];

function integrityAlerts(row) {
  return db.query(
    `SELECT id, kind, status, observed, occurrences, last_seen FROM integrity_events
      WHERE ecosystem = ? AND package_name = ? AND version = ? AND filename = ? ORDER BY last_seen DESC LIMIT 20`,
    fileKey(row)
  );
}

function holds(row) {
  return db.query(
    `SELECT id, source, reason, status, created_by, created_at, resolved_by, resolved_at FROM quarantine_holds
      WHERE ecosystem = ? AND package_name = ? AND version = ? AND filename = ? ORDER BY created_at DESC LIMIT 20`,
    fileKey(row)
  );
}

function scans(sha256) {
  return db.query(
    'SELECT scanner, scanner_version, status, signature, findings, scan_time, duration_ms FROM artifact_scans WHERE sha256 = ? ORDER BY scanner',
    [sha256]
  );
}

function provenanceFor(row) {
  return db.one(
    `SELECT status, reason, registry_signature, source_repository, source_commit, source_ref, builder, workflow, issuer, subject_digest,
            predicate_type, attestation, verified_at, checked_at, sha256 FROM provenance
      WHERE ecosystem = ? AND package_name = ? AND version = ? AND filename = ?`,
    fileKey(row)
  );
}

// ---------------------------------------------------------------- licenses

const LICENSE_FILE = 'ecosystem = ? AND package_name = ? AND version = ? AND filename = ?';
const licenseArgs = (f) => [f.ecosystem, f.packageName, f.version || '', f.filename];

function licenseFor(file) {
  return db.one(`SELECT id, license_expression, license_note, license_checked_at FROM artifacts WHERE ${LICENSE_FILE}`, licenseArgs(file));
}

// the stored copy for any file of that version that has been read, for the dry run
function storedLicense(ecosystem, name, version) {
  return db.one(
    `SELECT license_expression, license_verdict, license_note, license_checked_at FROM artifacts
      WHERE ecosystem = ? AND package_name = ? AND version = ? AND license_checked_at IS NOT NULL LIMIT 1`,
    [ecosystem, name, version]
  );
}

// values arrive already cut to fit
function saveLicense(id, { expression, verdict, note }) {
  return db.query(
    'UPDATE artifacts SET license_expression = ?, license_verdict = ?, license_note = ?, license_checked_at = NOW() WHERE id = ?',
    [expression, verdict, note, id]
  );
}

// the types whose license can be read. image layers have none, and a review verdict for one would hold every layer of
// every image. the ids are the box's own constants, never anything typed
const licenseTypes = () => ['npm', 'pypi', ...require('../../registry/kinds').ids()].map((id) => `'${id}'`).join(', ');

function uncheckedLicenses(after, limit) {
  return db.query(`SELECT id, ecosystem, package_name, version, filename FROM artifacts WHERE license_checked_at IS NULL AND ecosystem IN (${licenseTypes()}) AND id > ? ORDER BY id LIMIT ?`, [after, limit]);
}

function checkedLicenses(after, limit) {
  return db.query(
    `SELECT id, ecosystem, package_name, version, filename, license_expression, license_verdict, license_note
       FROM artifacts WHERE license_checked_at IS NOT NULL AND ecosystem IN (${licenseTypes()}) AND id > ? ORDER BY id LIMIT ?`,
    [after, limit]
  );
}

function setLicenseVerdict(id, verdict) {
  return db.query('UPDATE artifacts SET license_verdict = ? WHERE id = ?', [verdict, id]);
}

// everything gets read again
function clearLicenseChecks() {
  return db.query('UPDATE artifacts SET license_checked_at = NULL');
}

function licenseCounts() {
  return db.query(
    `SELECT CASE WHEN license_checked_at IS NULL THEN 'unchecked' ELSE license_verdict END AS verdict, COUNT(*) AS n
       FROM artifacts GROUP BY 1`
  );
}

function licensesInUse() {
  return db.query(
    `SELECT license_expression AS expression, license_verdict AS verdict, COUNT(*) AS files, COUNT(DISTINCT ecosystem, package_name) AS packages
       FROM artifacts WHERE license_checked_at IS NOT NULL
      GROUP BY license_expression, license_verdict ORDER BY files DESC LIMIT 200`
  );
}

// ---------------------------------------------------------------- the files the store holds

const FILE_COLUMNS = `id, ecosystem, package_name, version, filename, content_type, sha256, size, upstream, metadata,
            first_seen, last_seen, cached_at, last_access, download_count, status`;

// version is '' for files that have none
function fileRow(ecosystem, name, version, filename) {
  return db.one(`SELECT ${FILE_COLUMNS} FROM artifacts WHERE ecosystem = ? AND package_name = ? AND version = ? AND filename = ?`, [ecosystem, name, version || '', filename]);
}

function rowById(id) {
  return db.one(`SELECT ${FILE_COLUMNS},
            license_expression, license_verdict, license_note, license_checked_at
       FROM artifacts WHERE id = ?`, [id]);
}

// a race on the unique key updates last_seen instead, the caller reads back what won
function createFile(f) {
  return db.query(
    `INSERT INTO artifacts
       (ecosystem, package_name, version, filename, content_type, sha256, size, upstream, metadata,
        first_seen, last_seen, cached_at, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, NOW()), NOW(), COALESCE(?, NOW()), 'unknown')
     ON DUPLICATE KEY UPDATE last_seen = NOW()`,
    [f.ecosystem, f.name, f.version, f.filename, f.contentType, f.sha256, f.size, f.upstream, f.metadata, f.firstSeen, f.cachedAt]
  );
}

function deleteById(id) {
  return db.query('DELETE FROM artifacts WHERE id = ?', [id]);
}

// the same bytes came down again
function seenAgain(id, upstream) {
  return db.query('UPDATE artifacts SET last_seen = NOW(), cached_at = COALESCE(cached_at, NOW()), upstream = COALESCE(upstream, ?) WHERE id = ?', [upstream, id]);
}

function seen(id) {
  return db.query('UPDATE artifacts SET last_seen = NOW() WHERE id = ?', [id]);
}

// an accepted integrity change: the new bytes become the file
function replaceBytes(id, { sha256, size, metadata, upstream }) {
  return db.query(
    `UPDATE artifacts SET sha256 = ?, size = ?, metadata = ?, upstream = COALESCE(?, upstream),
            last_seen = NOW(), cached_at = NOW() WHERE id = ?`,
    [sha256, size, metadata, upstream, id]
  );
}

function countDownload(id) {
  return db.query('UPDATE artifacts SET download_count = download_count + 1, last_access = NOW() WHERE id = ?', [id]);
}

async function anyWithDigest(sha256) {
  return !!(await db.one('SELECT id FROM artifacts WHERE sha256 = ? LIMIT 1', [sha256]));
}

// every file of a package, a version of it, or one file. the columns come from here, never from a caller
function filesIn({ ecosystem, packageName, version, filename }) {
  const where = ['ecosystem = ?', 'package_name = ?'];
  const params = [ecosystem, packageName];
  if (version !== undefined) {
    where.push('version = ?');
    params.push(version);
  }
  if (filename !== undefined) {
    where.push('filename = ?');
    params.push(filename);
  }
  return db.query(`SELECT id, sha256 FROM artifacts WHERE ${where.join(' AND ')}`, params);
}

// in chunks, a big package can have thousands of files
// the versions of a package with a file here, and the files. for lockdown and kill purges of the newer ecosystems
async function cachedVersions(ecosystem, packageName) {
  return (await db.query('SELECT DISTINCT version FROM artifacts WHERE ecosystem = ? AND package_name = ?', [ecosystem, packageName])).map((r) => r.version);
}

function cachedFiles(ecosystem, packageName) {
  return db.query('SELECT package_name, version, filename FROM artifacts WHERE ecosystem = ? AND package_name = ?', [ecosystem, packageName]);
}

async function deleteIds(ids) {
  for (let i = 0; i < ids.length; i += 500) {
    const chunk = ids.slice(i, i + 500);
    await db.query(`DELETE FROM artifacts WHERE id IN (${chunk.map(() => '?').join(',')})`, chunk);
  }
}

function deleteAll() {
  return db.query('DELETE FROM artifacts');
}

function noteBlob(sha256, size) {
  return db.query(
    `INSERT INTO blobs (sha256, size, created_at) VALUES (?, ?, NOW())
     ON DUPLICATE KEY UPDATE size = VALUES(size)`,
    [sha256, size]
  );
}

function deleteBlob(sha256) {
  return db.query('DELETE FROM blobs WHERE sha256 = ?', [sha256]);
}

function deleteAllBlobs() {
  return db.query('DELETE FROM blobs');
}

// ---------------------------------------------------------------- integrity and provenance

function npmForIntegrity(name) {
  return db.query("SELECT id, version, filename, upstream, metadata FROM artifacts WHERE ecosystem = 'npm' AND package_name = ?", [name]);
}

function pypiForIntegrity(project) {
  return db.query(
    `SELECT id, version, filename, sha256, upstream FROM artifacts
      WHERE ecosystem = 'pypi' AND package_name = ? AND filename NOT LIKE '%.metadata'`,
    [project]
  );
}

// never checked, bytes changed since, or unverified and a day old
function provenanceBacklog(limit) {
  return db.query(
    `SELECT a.id, a.ecosystem, a.package_name, a.version, a.filename, a.sha256, a.metadata
       FROM artifacts a
       LEFT JOIN provenance p ON p.ecosystem = a.ecosystem AND p.package_name = a.package_name AND p.version = a.version AND p.filename = a.filename
      WHERE p.id IS NULL OR p.sha256 <> a.sha256
         OR (p.status = 'PRESENT_UNVERIFIED' AND p.checked_at < DATE_SUB(NOW(), INTERVAL 1 DAY))
      ORDER BY a.id DESC LIMIT ?`,
    [limit]
  );
}

// every file's digest, keyed by housekeeping
function fileIndex() {
  return db.query('SELECT ecosystem, package_name, version, filename, sha256, size FROM artifacts');
}

module.exports = {
  cachedVersions,
  cachedFiles,
  fileIndex,
  SORTS, filterClause, page, blobTotals, blobLedger, markVerified, sharedCount, integrityAlerts, holds, scans, provenanceFor,
  licenseFor, storedLicense, saveLicense, uncheckedLicenses, checkedLicenses, setLicenseVerdict, clearLicenseChecks, licenseCounts, licensesInUse,
  npmForIntegrity, pypiForIntegrity, provenanceBacklog,
  fileRow, rowById, createFile, deleteById, seenAgain, seen, replaceBytes, countDownload, anyWithDigest, filesIn, deleteIds, deleteAll,
  noteBlob, deleteBlob, deleteAllBlobs
};
