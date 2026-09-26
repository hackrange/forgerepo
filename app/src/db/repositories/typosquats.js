// Lookalike package findings for the portal. spotting them lives in typosquat.js
// Author: Tim Rice

const db = require('../../db');

function byStatus(status) {
  return db.query(
    `SELECT id, ecosystem, package_name, looks_like, technique, last_action, hits, status, first_seen, last_seen, dismissed_by, dismissed_at
       FROM typosquat_findings WHERE status = ? ORDER BY last_seen DESC LIMIT 500`,
    [status]
  );
}

function counts() {
  return db.query('SELECT status, COUNT(*) AS n FROM typosquat_findings GROUP BY status');
}

function byId(id) {
  return db.one('SELECT id, ecosystem, package_name, looks_like, status FROM typosquat_findings WHERE id = ?', [id]);
}

function dismissedNames(ecosystem) {
  return db.query("SELECT package_name FROM typosquat_findings WHERE ecosystem = ? AND status = 'dismissed'", [ecosystem]);
}

function flaggedNames(ecosystem) {
  return db.query('SELECT package_name FROM typosquat_findings WHERE ecosystem = ?', [ecosystem]);
}

// one row per name, a repeat bumps it. returns rows changed, 1 = the first time
async function record({ ecosystem, name, lookalike, technique, action }) {
  return (await db.query(
    `INSERT INTO typosquat_findings (ecosystem, package_name, looks_like, technique, last_action, hits, status, first_seen, last_seen)
     VALUES (?, ?, ?, ?, ?, 1, 'open', NOW(), NOW())
     ON DUPLICATE KEY UPDATE hits = hits + 1, last_seen = NOW(), last_action = VALUES(last_action),
       looks_like = VALUES(looks_like), technique = VALUES(technique)`,
    [ecosystem, name, lookalike, technique, action]
  )).affectedRows;
}

function setStatus(id, { status, by, at }) {
  return db.query('UPDATE typosquat_findings SET status = ?, dismissed_by = ?, dismissed_at = ? WHERE id = ?', [status, by, at, id]);
}

module.exports = { byStatus, counts, byId, dismissedNames, flaggedNames, record, setStatus };
