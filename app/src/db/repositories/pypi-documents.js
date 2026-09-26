// PyPI pages kept in the cache: simple index pages and JSON API documents, gzipped.
// Author: Tim Rice

const db = require('../../db');

function get(project, kind, version) {
  return db.one(
    'SELECT body, etag, source, fetched_at FROM pypi_documents WHERE project = ? AND kind = ? AND version = ?',
    [project, kind, version]
  );
}

function put(project, kind, version, body, source, etag) {
  return db.query(
    `INSERT INTO pypi_documents (project, kind, version, body, bytes, source, etag, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE body = VALUES(body), bytes = VALUES(bytes), source = VALUES(source),
       etag = VALUES(etag), fetched_at = NOW()`,
    [project, kind, version, body, body.length, source, etag]
  );
}

// a 304 still counts as fresh
function touch(project, kind, version) {
  return db.query('UPDATE pypi_documents SET fetched_at = NOW() WHERE project = ? AND kind = ? AND version = ?', [project, kind, version]);
}

// pages for projects with no file left in the cache
function forgetUncached() {
  return db.query('DELETE FROM pypi_documents WHERE project NOT IN (SELECT DISTINCT project FROM pypi_files)');
}

function deleteAll() {
  return db.query('DELETE FROM pypi_documents');
}

module.exports = { get, put, touch, forgetUncached, deleteAll };
