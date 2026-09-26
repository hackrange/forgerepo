// Portal sessions. rows are keyed by a hash of the cookie, the cookie itself is never stored.
// Author: Tim Rice

const db = require('../../db');

function create({ key, userId, csrf, ip, userAgent, hours }) {
  return db.query(
    `INSERT INTO sessions (id, user_id, csrf, ip, user_agent, expires_at)
     VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR))`,
    [key, userId, csrf, ip, userAgent, hours]
  );
}

// a short session as someone else, remembering who is behind it
function createImpersonation({ key, userId, csrf, ip, userAgent, minutes, impersonatorId }) {
  return db.query(
    `INSERT INTO sessions (id, user_id, csrf, ip, user_agent, expires_at, impersonator_id, impersonation_ends_at)
     VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))`,
    [key, userId, csrf, ip, userAgent, minutes, impersonatorId, minutes]
  );
}

// the clock is read in sql, same clock that wrote it
function load(key) {
  return db.one(
    `SELECT s.id, s.csrf, s.user_id, s.expires_at, s.last_seen_at, s.impersonator_id,
            TIMESTAMPDIFF(SECOND, NOW(), s.impersonation_ends_at) AS imp_left,
            u.username, u.role, u.disabled, u.must_change_password, u.full_name, u.email,
            iu.username AS imp_username, iu.role AS imp_role, iu.disabled AS imp_disabled
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       LEFT JOIN users iu ON iu.id = s.impersonator_id
      WHERE s.id = ? AND s.expires_at > NOW()`,
    [key]
  );
}

function touch(key) {
  return db.query('UPDATE sessions SET last_seen_at = NOW() WHERE id = ?', [key]);
}

function remove(key) {
  return db.query('DELETE FROM sessions WHERE id = ?', [key]);
}

// only if it really is that user's, a cookie alone can't sign someone else out
function removeOwnedBy(key, userId) {
  return db.query('DELETE FROM sessions WHERE id = ? AND user_id = ?', [key, userId]);
}

function removeImpersonation(key) {
  return db.query('DELETE FROM sessions WHERE id = ? AND impersonator_id IS NOT NULL', [key]);
}

// also the sessions where they are the one doing the impersonating
function removeForUser(userId, keepKey) {
  return keepKey
    ? db.query('DELETE FROM sessions WHERE (user_id = ? OR impersonator_id = ?) AND id <> ?', [userId, userId, keepKey])
    : db.query('DELETE FROM sessions WHERE user_id = ? OR impersonator_id = ?', [userId, userId]);
}

function sweep() {
  return db.query('DELETE FROM sessions WHERE expires_at < NOW()');
}

module.exports = { create, createImpersonation, load, touch, remove, removeOwnedBy, removeImpersonation, removeForUser, sweep };
