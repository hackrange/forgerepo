// npm metadata documents, gzipped, one per package and variant.
// Author: Tim Rice

const db = require('../../db');

function get(name, variant) {
  return db.one('SELECT body, etag, source, fetched_at FROM packuments WHERE name = ? AND variant = ?', [name, variant]);
}

// bytes is the gzipped length, so sizing the cache never reads a body
function put(name, variant, body, source, etag) {
  return db.query(
    `INSERT INTO packuments (name, variant, body, bytes, source, etag, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE body = VALUES(body), bytes = VALUES(bytes),
       source = VALUES(source), etag = VALUES(etag), fetched_at = NOW()`,
    [name, variant, body, body.length, source, etag]
  );
}

function touch(name, variant) {
  return db.query('UPDATE packuments SET fetched_at = NOW() WHERE name = ? AND variant = ?', [name, variant]);
}

function forget(name) {
  return db.query('DELETE FROM packuments WHERE name = ?', [name]);
}

// bytes, not LENGTH(body). same answer, without reading every single document
function totals() {
  return db.one('SELECT COUNT(*) AS docs, COALESCE(SUM(bytes),0) AS bytes FROM packuments');
}

// metadata for packages with no tarball left in the cache
function forgetUncached() {
  return db.query('DELETE FROM packuments WHERE name NOT IN (SELECT DISTINCT package_name FROM tarballs)');
}

function deleteAll() {
  return db.query('DELETE FROM packuments');
}

module.exports = { get, put, touch, forget, totals, forgetUncached, deleteAll };
