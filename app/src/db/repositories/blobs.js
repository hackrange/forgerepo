// Where blobs live once there is a bucket: on this box, in the bucket, or both, and what still has to go up.
// Author: Tim Rice

const db = require('../../db');

// oldest first, and the ones that keep failing go to the back of the line
function waitingForUpload(limit) {
  return db.query(
    'SELECT sha256, size, upload_attempts FROM blobs WHERE in_bucket = 0 ORDER BY upload_attempts ASC, created_at ASC LIMIT ?',
    [limit]
  );
}

function markUploaded(sha256) {
  return db.query('UPDATE blobs SET in_bucket = 1, uploaded_at = NOW(), upload_error = NULL WHERE sha256 = ?', [sha256]);
}

function markUploadFailed(sha256, error) {
  return db.query(
    'UPDATE blobs SET upload_attempts = upload_attempts + 1, upload_error = ? WHERE sha256 = ?',
    [String(error || 'unknown').slice(0, 255), sha256]
  );
}

function location(sha256) {
  return db.one('SELECT size, in_bucket FROM blobs WHERE sha256 = ?', [sha256]);
}

// which of these the bucket already holds, a chunk at a time
async function inBucketOf(digests) {
  const out = new Set();
  const list = [...new Set(digests)];
  for (let i = 0; i < list.length; i += 500) {
    const chunk = list.slice(i, i + 500);
    const rows = await db.query(`SELECT sha256 FROM blobs WHERE in_bucket = 1 AND sha256 IN (${chunk.map(() => '?').join(',')})`, chunk);
    for (const r of rows) out.add(r.sha256);
  }
  return out;
}

async function counts() {
  const row = await db.one(
    `SELECT COUNT(*) AS blobs, COALESCE(SUM(size), 0) AS bytes,
            COALESCE(SUM(in_bucket), 0) AS in_bucket, COALESCE(SUM(CASE WHEN in_bucket = 1 THEN size END), 0) AS bucket_bytes,
            COALESCE(SUM(in_bucket = 0 AND upload_attempts > 0), 0) AS failing
       FROM blobs`
  );
  return {
    blobs: Number(row.blobs), bytes: Number(row.bytes), inBucket: Number(row.in_bucket),
    bucketBytes: Number(row.bucket_bytes), failing: Number(row.failing)
  };
}

function uploadErrors(limit) {
  return db.query(
    `SELECT sha256, size, upload_attempts, upload_error FROM blobs
      WHERE in_bucket = 0 AND upload_error IS NOT NULL ORDER BY upload_attempts DESC, sha256 LIMIT ?`,
    [limit]
  );
}

// the old npm and PyPI cache paths hard linked to a blob. only local copies of files the bucket holds get dropped
function legacyPaths(sha256) {
  return db.query(
    `SELECT t.path FROM artifacts a
       JOIN tarballs t ON a.ecosystem = 'npm' AND t.package_name = a.package_name AND t.version = a.version
      WHERE a.sha256 = ?
     UNION
     SELECT f.path FROM artifacts a
       JOIN pypi_files f ON a.ecosystem = 'pypi' AND f.project = a.package_name AND f.filename = a.filename
      WHERE a.sha256 = ?`,
    [sha256, sha256]
  );
}

async function anyInBucket() {
  return !!(await db.one('SELECT 1 AS ok FROM blobs WHERE in_bucket = 1 LIMIT 1'));
}

module.exports = { waitingForUpload, markUploaded, markUploadFailed, location, inBucketOf, counts, uploadErrors, legacyPaths, anyInBucket };
