// Registry tokens. only the hash and a short prefix are ever stored, the token itself never is.
// Author: Tim Rice

const db = require('../../db');

const SETTABLE = new Set(['email', 'application_id', 'environment_id']);

const COLUMNS = `t.id, t.name, t.email, t.prefix, t.revoked, t.created_at, t.expires_at,
                 t.last_used_at, t.last_used_ip, t.user_id,
                 t.application_id, t.environment_id,
                 a.name AS application, a.retired AS application_retired,
                 e.name AS environment, e.retired AS environment_retired`;
const JOINS = `LEFT JOIN applications a ON a.id = t.application_id
               LEFT JOIN environments e ON e.id = t.environment_id`;

// ownerId null = every token, with whose it is
function list(ownerId) {
  return ownerId === null
    ? db.query(
      `SELECT ${COLUMNS}, u.username
         FROM tokens t JOIN users u ON u.id = t.user_id ${JOINS}
        ORDER BY t.created_at DESC`
    )
    : db.query(
      `SELECT ${COLUMNS} FROM tokens t ${JOINS}
        WHERE t.user_id = ? ORDER BY t.created_at DESC`,
      [ownerId]
    );
}

function byId(id, ownerId) {
  return ownerId === null
    ? db.one('SELECT id, name, user_id FROM tokens WHERE id = ?', [id])
    : db.one('SELECT id, name, user_id FROM tokens WHERE id = ? AND user_id = ?', [id, ownerId]);
}

// a live token by its hash, with its owner and label names. names not ids, they just get stamped on the traffic row
function forRegistry(hash) {
  return db.one(
    `SELECT t.id, t.user_id, t.name, t.token_hash, t.expires_at, u.username, u.role, u.disabled,
            t.application_id, t.environment_id, a.name AS application, e.name AS environment
       FROM tokens t
       JOIN users u ON u.id = t.user_id
       LEFT JOIN applications a ON a.id = t.application_id
       LEFT JOIN environments e ON e.id = t.environment_id
      WHERE t.token_hash = ? AND t.revoked = 0`,
    [hash]
  );
}

// the token behind a bearer from /v2/token, while the bearer has time left and the token is still good
function forBearer(hash) {
  return db.one(
    `SELECT t.id, t.user_id, t.name, t.token_hash, t.expires_at, u.username, u.role, u.disabled,
            t.application_id, t.environment_id, a.name AS application, e.name AS environment
       FROM oci_bearers b
       JOIN tokens t ON t.id = b.token_id
       JOIN users u ON u.id = t.user_id
       LEFT JOIN applications a ON a.id = t.application_id
       LEFT JOIN environments e ON e.id = t.environment_id
      WHERE b.hash = ? AND b.expires_at > NOW() AND t.revoked = 0`,
    [hash]
  );
}

function touch(id, ip) {
  return db.query('UPDATE tokens SET last_used_at = NOW(), last_used_ip = ? WHERE id = ?', [ip, id]);
}

async function liveCount(userId) {
  return Number((await db.one('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ? AND revoked = 0', [userId])).n);
}

function create({ userId, name, email, applicationId, environmentId, prefix, hash, days }) {
  return db.query(
    `INSERT INTO tokens (user_id, name, email, application_id, environment_id, prefix, token_hash, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ${days ? 'DATE_ADD(NOW(), INTERVAL ? DAY)' : 'NULL'})`,
    days
      ? [userId, name, email, applicationId, environmentId, prefix, hash, days]
      : [userId, name, email, applicationId, environmentId, prefix, hash]
  );
}

// sets: [[column, value]] in the order they should be written
function update(id, sets) {
  for (const [c] of sets) {
    if (!SETTABLE.has(c)) throw new Error(`tokens has no settable column called ${c}`);
  }
  return db.query(`UPDATE tokens SET ${sets.map(([c]) => `${c} = ?`).join(', ')} WHERE id = ?`, [...sets.map(([, v]) => v), id]);
}

function revoke(id) {
  return db.query('UPDATE tokens SET revoked = 1 WHERE id = ?', [id]);
}

// a user's tokens that carry their own address, so a shared build token can point at its team
function emailsFor(userId) {
  return db.query("SELECT name, email FROM tokens WHERE user_id = ? AND email IS NOT NULL AND email <> ''", [userId]);
}

module.exports = { list, byId, forRegistry, forBearer, touch, liveCount, create, update, revoke, emailsFor };
