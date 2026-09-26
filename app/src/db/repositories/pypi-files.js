// PyPI files the cache holds, read side for policy work like the kill switch purge.
// Author: Tim Rice

const db = require('../../db');

// real files only, the .metadata sidecars ride along with them
function cachedFiles(project) {
  return db.query("SELECT filename, version FROM pypi_files WHERE project = ? AND filename NOT LIKE '%.metadata'", [project]);
}

// projects served the most, at least minHits times across their files
function busiest(minHits, limit) {
  return db.query('SELECT project AS name FROM pypi_files GROUP BY project HAVING SUM(hits) >= ? ORDER BY SUM(hits) DESC LIMIT ?', [minHits, limit]);
}

// the legacy pypi_files row for a file the artifact store now holds
function recordFile({ project, version, filename, path, size, sha256, source }) {
  return db.query(
    `INSERT INTO pypi_files (project, version, filename, path, size, sha256, source, cached_at, last_access, hits)
     VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 0)
     ON DUPLICATE KEY UPDATE version = VALUES(version), path = VALUES(path), size = VALUES(size),
       sha256 = VALUES(sha256), source = VALUES(source), cached_at = NOW()`,
    [project, version, filename, path, size, sha256, source]
  );
}

// legacy pypi_files rows the artifact store has not adopted yet, in id order
function filesWithoutArtifacts(after, limit) {
  return db.query(
    `SELECT f.id, f.project, f.version, f.filename, f.path, f.sha256, f.source, f.cached_at
       FROM pypi_files f
       LEFT JOIN artifacts a
         ON a.ecosystem = 'pypi' AND a.package_name = f.project AND a.version = f.version AND a.filename = f.filename
      WHERE a.id IS NULL AND f.id > ?
      ORDER BY f.id LIMIT ?`,
    [after, limit]
  );
}

function sourceOf(project, filename) {
  return db.one('SELECT source, sha256 FROM pypi_files WHERE project = ? AND filename = ?', [project, filename]);
}

function touchFile(project, filename) {
  return db.query('UPDATE pypi_files SET hits = hits + 1, last_access = NOW() WHERE project = ? AND filename = ?', [project, filename]);
}

// a file that just came down and went straight out, so it starts on one hit
function cacheFile({ project, version, filename, path, size, sha256, source }) {
  return db.query(
    `INSERT INTO pypi_files (project, version, filename, path, size, sha256, source, cached_at, last_access, hits)
     VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1)
     ON DUPLICATE KEY UPDATE version = VALUES(version), path = VALUES(path), size = VALUES(size),
       sha256 = VALUES(sha256), source = VALUES(source), cached_at = NOW(), last_access = NOW(), hits = hits + 1`,
    [project, version, filename, path, size, sha256, source]
  );
}

function deleteFile(project, filename) {
  return db.query('DELETE FROM pypi_files WHERE project = ? AND filename = ?', [project, filename]);
}

function deleteAll() {
  return db.query('DELETE FROM pypi_files');
}

// every cached file, for housekeeping to check against the disk
function allFiles() {
  return db.query('SELECT project, version, filename, path, size FROM pypi_files');
}

// projects worth warming: allowed by exact name, cached already, or with an index page on file
function knownProjects() {
  return db.query(
    `SELECT pattern AS name FROM rules
      WHERE ecosystem = 'pypi' AND kind = 'allow' AND enabled = 1 AND pattern NOT LIKE '%*%'
     UNION SELECT project FROM pypi_files
     UNION SELECT project FROM pypi_documents WHERE kind = 'simple'
     ORDER BY 1 LIMIT 100000`
  );
}

module.exports = { sourceOf, touchFile, cacheFile, deleteFile, deleteAll, allFiles, knownProjects, cachedFiles, busiest, recordFile, filesWithoutArtifacts };
