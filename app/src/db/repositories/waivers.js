// Waivers for the portal lists. creating and deciding them lives in waivers.js
// Author: Tim Rice

const db = require('../../db');

const COLUMNS = `w.*, (SELECT name FROM applications WHERE id = w.application_id) AS application_name,
  (SELECT name FROM environments WHERE id = w.environment_id) AS environment_name`;

// null = every waiver (staff who decide them), a user id = the ones that user asked for, anything else = none at all
function ownedBy(ownerId) {
  if (ownerId === null) return { sql: '', params: [] };
  if (Number.isSafeInteger(ownerId) && ownerId > 0) return { sql: ' AND w.requested_by_id = ?', params: [ownerId] };
  return { sql: ' AND 1 = 0', params: [] };
}

function pending(ownerId) {
  const o = ownedBy(ownerId);
  return db.query(`SELECT ${COLUMNS} FROM waivers w WHERE status = 'pending'${o.sql} ORDER BY requested_at`, o.params);
}

function active(ownerId) {
  const o = ownedBy(ownerId);
  return db.query(`SELECT ${COLUMNS} FROM waivers w WHERE status = 'active' AND expires_at > NOW()${o.sql} ORDER BY expires_at`, o.params);
}

// an active waiver past its date counts as history even before the sweep marks it
function history(ownerId) {
  const o = ownedBy(ownerId);
  return db.query(
    `SELECT ${COLUMNS} FROM waivers w WHERE (status IN ('rejected','revoked','expired') OR (status = 'active' AND expires_at <= NOW()))${o.sql}
      ORDER BY COALESCE(decided_at, requested_at) DESC LIMIT 100`,
    o.params
  );
}

// ---------------------------------------------------------------- what policy reads, and the lifecycle

// active and not past its date, asked of the database clock
function live() {
  return db.query(
    `SELECT id, kind, ecosystem, package_name, version_range, subject, application_id, environment_id, expires_at, reason, requested_by, decided_by
       FROM waivers WHERE status = 'active' AND expires_at > NOW()`
  );
}

function byId(id) {
  return db.one('SELECT * FROM waivers WHERE id = ?', [id]);
}

// grant = active from now, otherwise pending for an approver
function create(f, { grant, days, user, userId }) {
  return db.query(
    `INSERT INTO waivers (kind, ecosystem, package_name, version_range, subject, application_id, environment_id, reason, reference, days, status,
                          expires_at, requested_by, requested_by_id, decided_by, decided_at, decision_note)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ${grant ? 'DATE_ADD(NOW(), INTERVAL ? DAY)' : 'NULL'}, ?, ?, ?, ${grant ? 'NOW()' : 'NULL'}, ?)`,
    [
      f.kind, f.ecosystem, f.packageName, f.versionRange || '', f.subject || '',
      f.app || 0, f.env || 0, f.reason, f.reference || '', days, grant ? 'active' : 'pending',
      ...(grant ? [days] : []),
      user, userId || null, grant ? user : null, grant ? 'granted when asked' : null
    ]
  );
}

// each returns rows changed, 0 = the waiver moved on before this got there
async function approve(id, { days, user, note }) {
  return (await db.query(
    `UPDATE waivers SET status = 'active', days = ?, expires_at = DATE_ADD(NOW(), INTERVAL ? DAY), decided_by = ?, decided_at = NOW(), decision_note = ?
      WHERE id = ? AND status = 'pending'`,
    [days, days, user, note, id]
  )).affectedRows;
}

async function reject(id, { user, note }) {
  return (await db.query(
    "UPDATE waivers SET status = 'rejected', decided_by = ?, decided_at = NOW(), decision_note = ? WHERE id = ? AND status = 'pending'",
    [user, note, id]
  )).affectedRows;
}

async function revoke(id, { user, note }) {
  return (await db.query(
    "UPDATE waivers SET status = 'revoked', decided_by = ?, decided_at = NOW(), decision_note = ? WHERE id = ? AND status = 'active'",
    [user, note, id]
  )).affectedRows;
}

function due() {
  return db.query("SELECT id, kind, ecosystem, package_name, version_range, subject FROM waivers WHERE status = 'active' AND expires_at <= NOW()");
}

function expire(ids) {
  return db.query(`UPDATE waivers SET status = 'expired' WHERE status = 'active' AND id IN (${ids.map(() => '?').join(',')})`, ids);
}

// ---------------------------------------------------------------- for the digest

function waitingForDecision(limit) {
  return db.query("SELECT kind, ecosystem, package_name, version_range, subject, reference, requested_by, reason FROM waivers WHERE status = 'pending' ORDER BY requested_at LIMIT ?", [limit]);
}

function endingWithinAWeek(limit) {
  return db.query(
    "SELECT kind, ecosystem, package_name, version_range, subject, reference, expires_at FROM waivers WHERE status = 'active' AND expires_at > NOW() AND expires_at <= DATE_ADD(NOW(), INTERVAL 7 DAY) ORDER BY expires_at LIMIT ?",
    [limit]
  );
}

module.exports = { pending, active, history, live, byId, create, approve, reject, revoke, due, expire, waitingForDecision, endingWithinAWeek };
