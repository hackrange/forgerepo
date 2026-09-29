// The requests table, and cleared packages. SQL for approval requests lives here.
// Author: Tim Rice
// ownerId: null means any request (staff), a number means only that user's own

const db = require('../../db');

const marks = (list) => list.map(() => '?').join(',');

async function page({ ownerId, ecosystem, status }, { limit, offset }) {
  const where = [];
  const params = [];
  if (ownerId !== null && ownerId !== undefined) {
    where.push('r.user_id = ?');
    params.push(ownerId);
  }
  if (ecosystem) {
    where.push('r.ecosystem = ?');
    params.push(ecosystem);
  }
  if (status) {
    where.push('r.status = ?');
    params.push(status);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = await db.query(
    `SELECT r.id, r.ecosystem, r.package_name, r.version_range, r.status, r.source, r.reason,
            r.decision_note, r.auto_state, r.auto_note, r.auto_at, r.hits, r.created_at, r.updated_at, r.resolved_at,
            r.user_id, r.requested_by, r.token_name, r.ip,
            u.username AS requested_by_user, u.full_name AS owner_name, u.email AS owner_email,
            d.username AS resolved_by_user
       FROM requests r
       LEFT JOIN users u ON u.id = r.user_id
       LEFT JOIN users d ON d.id = r.resolved_by
       ${clause}
       ORDER BY FIELD(r.status,'pending','approved','blocked','rejected','withdrawn'), r.created_at DESC, r.id DESC
       LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM requests r ${clause}`, params);
  return { rows, total: Number(total.n) };
}

function byId(id, ownerId) {
  return ownerId === null || ownerId === undefined
    ? db.one('SELECT * FROM requests WHERE id = ?', [id])
    : db.one('SELECT * FROM requests WHERE id = ? AND user_id = ?', [id, ownerId]);
}

// brief = just what the advisory check needs
function byIds(ids, ownerId, { brief = false } = {}) {
  const cols = brief ? 'id, ecosystem, package_name, version_range' : '*';
  return ownerId === null || ownerId === undefined
    ? db.query(`SELECT ${cols} FROM requests WHERE id IN (${marks(ids)})`, ids)
    : db.query(`SELECT ${cols} FROM requests WHERE id IN (${marks(ids)}) AND user_id = ?`, [...ids, ownerId]);
}

// same versions too, ubuntu 24.04 isn't a repeat of ubuntu 22.04
function openFor(ecosystem, name, userId, range = '') {
  return db.one(
    "SELECT id FROM requests WHERE ecosystem = ? AND package_name = ? AND user_id = ? AND COALESCE(version_range, '') = ? AND status = 'pending'",
    [ecosystem, name, userId, range || '']
  );
}

function bump(id) {
  return db.query('UPDATE requests SET hits = hits + 1, updated_at = NOW() WHERE id = ?', [id]);
}

function createFromPortal(r) {
  return db.query(
    `INSERT INTO requests (ecosystem, package_name, version_range, user_id, source, requested_by, ip, reason)
     VALUES (?, ?, ?, ?, 'portal', ?, ?, ?)`,
    [r.ecosystem, r.name, r.range, r.userId, r.username, r.ip, r.reason]
  );
}

// the pending one a blocked install folds into. learning mode may fold into its own ones too
function pendingFromRegistry(ecosystem, name, learning) {
  return db.one(
    `SELECT id, version_range FROM requests
      WHERE ecosystem = ? AND package_name = ? AND status = 'pending'
        AND source IN (${learning ? "'blocked-install', 'learning'" : "'blocked-install'"}) LIMIT 1`,
    [ecosystem, name]
  );
}

// a repeat hit. who is only filled in if the first one was anonymous, range only when given
function foldIn(id, { range, token, userId, who }) {
  return db.query(
    `UPDATE requests
        SET hits = hits + 1, updated_at = NOW(),
            version_range = COALESCE(?, version_range),
            token_name = COALESCE(token_name, ?),
            user_id = COALESCE(user_id, ?),
            requested_by = COALESCE(requested_by, ?)
      WHERE id = ?`,
    [range, token, userId, who, id]
  );
}

function createFromRegistry(r) {
  return db.query(
    `INSERT INTO requests (ecosystem, package_name, version_range, user_id, source, requested_by, token_name, ip, reason)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [r.ecosystem, r.name, r.range, r.userId, r.source, r.who, r.token, r.ip, r.reason]
  );
}

async function withdraw(id, userId) {
  return (await db.query(
    "UPDATE requests SET status = 'withdrawn', resolved_at = NOW() WHERE id = ? AND user_id = ? AND status = 'pending'",
    [id, userId]
  )).affectedRows;
}

// claims a pending request for a decision. 0 = somebody settled it first
async function settle({ id, status, note, resolvedBy }, q = db.query) {
  return (await q(
    'UPDATE requests SET status = ?, decision_note = ?, resolved_at = NOW(), resolved_by = ? WHERE id = ? AND status = \'pending\'',
    [status, note, resolvedBy, id]
  )).affectedRows;
}

function summaries(ids) {
  return db.query(`SELECT id, package_name, status FROM requests WHERE id IN (${marks(ids)})`, ids);
}

function removeMany(ids) {
  return db.query(`DELETE FROM requests WHERE id IN (${marks(ids)})`, ids);
}

function markCleared(name, username) {
  return db.query(
    `INSERT INTO cleared_packages (name, cleared_at, cleared_by) VALUES (?, NOW(), ?)
     ON DUPLICATE KEY UPDATE cleared_at = NOW(), cleared_by = VALUES(cleared_by)`,
    [name, username]
  );
}

// ---------------------------------------------------------------- for the digest

// someone's requests decided since a moment, with who decided them
function decidedSince(userId, since) {
  return db.query(
    `SELECT r.ecosystem, r.package_name, r.version_range, r.status, r.decision_note, r.resolved_at, r.token_name,
            d.username AS decided_by
       FROM requests r
       LEFT JOIN users d ON d.id = r.resolved_by
      WHERE r.user_id = ? AND r.resolved_at IS NOT NULL AND r.resolved_at > ?
        AND r.status IN ('approved', 'rejected', 'blocked')
      ORDER BY r.resolved_at`,
    [userId, since]
  );
}

function pendingSince(since) {
  return db.query(
    `SELECT r.ecosystem, r.package_name, r.version_range, r.reason, r.hits, r.created_at, r.token_name, r.requested_by,
            u.username AS requested_by_user
       FROM requests r
       LEFT JOIN users u ON u.id = r.user_id
      WHERE r.status = 'pending' AND r.created_at > ?
      ORDER BY r.created_at
      LIMIT 200`,
    [since]
  );
}

// how many were already waiting before that moment, and since when
function pendingBefore(since) {
  return db.one("SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM requests WHERE status = 'pending' AND created_at <= ?", [since]);
}

module.exports = {
  page, byId, byIds, openFor, bump, createFromPortal, pendingFromRegistry, foldIn, createFromRegistry,
  withdraw, settle, summaries, removeMany, markCleared, decidedSince, pendingSince, pendingBefore
};
