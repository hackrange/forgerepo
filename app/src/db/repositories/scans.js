// Malware scan results, as the portal sees them.
// Author: Tim Rice

const db = require('../../db');

function statusCounts() {
  return db.query('SELECT status, COUNT(DISTINCT sha256) AS n FROM artifact_scans GROUP BY status');
}

function flagged() {
  return db.query(
    `SELECT s.sha256, s.scanner, s.scanner_version, s.status, s.signature, s.scan_time,
            a.id AS artifact_id, a.ecosystem, a.package_name, a.version, a.filename
       FROM artifact_scans s JOIN artifacts a ON a.sha256 = s.sha256
      WHERE s.status IN ('MALICIOUS', 'SUSPICIOUS')
      ORDER BY s.scan_time DESC LIMIT 100`
  );
}

async function unscannedCount() {
  return Number((await db.one(
    'SELECT COUNT(DISTINCT a.sha256) AS n FROM artifacts a LEFT JOIN artifact_scans s ON s.sha256 = a.sha256 WHERE s.id IS NULL'
  )).n);
}

module.exports = { statusCounts, flagged, unscannedCount };
