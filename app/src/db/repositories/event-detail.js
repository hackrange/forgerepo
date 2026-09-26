// The evidence behind one traffic log line: the lookalike finding, the cached files, who else pulled it,
// requests waiting on it, and the rest of the same install.
// Author: Tim Rice

const db = require('../../db');

function lookalike(ecosystem, name) {
  return db.one(
    `SELECT looks_like, technique, last_action, hits, status, first_seen, last_seen FROM typosquat_findings
      WHERE ecosystem = ? AND package_name = ?`,
    [ecosystem, name]
  );
}

// every file of the version this box holds, with what the license lists made of it
function files(ecosystem, name, version) {
  return db.query(
    `SELECT id, ecosystem, package_name, version, filename, sha256, size, license_expression, license_verdict
       FROM artifacts WHERE ecosystem = ? AND package_name = ? AND version = ? ORDER BY filename LIMIT 20`,
    [ecosystem, name, version]
  );
}

// how far it already got: consumers, applications and downloads for that exact version
function consumers(ecosystem, name, version) {
  return db.one(
    `SELECT COUNT(*) AS consumers, COUNT(DISTINCT application) AS applications, COALESCE(SUM(downloads), 0) AS downloads, MAX(last_seen) AS last_seen
       FROM consumption WHERE ecosystem = ? AND package_name = ? AND version = ?`,
    [ecosystem, name, version]
  );
}

// ownerId null = staff, every request. a user id = only theirs. anything else = none, a caller that forgot to say gets nothing
async function pendingRequests(ecosystem, name, ownerId) {
  const cols = 'id, version_range, source, requested_by, token_name, hits, created_at';
  if (ownerId === null) {
    return db.query(
      `SELECT ${cols} FROM requests
        WHERE ecosystem = ? AND package_name = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 10`,
      [ecosystem, name]
    );
  }
  if (!Number.isSafeInteger(ownerId) || ownerId < 1) return [];
  return db.query(
    `SELECT ${cols} FROM requests
      WHERE ecosystem = ? AND package_name = ? AND status = 'pending' AND user_id = ? ORDER BY created_at DESC LIMIT 10`,
    [ecosystem, name, ownerId]
  );
}

// the other requests one install made, so a refused tarball can be read next to the metadata that led to it
function sameInstall(session, exceptId) {
  return db.query(
    `SELECT id, ts, method, path, package_name, version, action, status, reason, blocked_by FROM access_log
      WHERE npm_session = ? AND id <> ? ORDER BY id DESC LIMIT 20`,
    [session, exceptId]
  );
}

module.exports = { lookalike, files, consumers, pendingRequests, sameInstall };
