// Break glass keys and the grants they hand out. only a hash and a short hint of a key are stored.
// Author: Tim Rice

const db = require('../../db');

function liveKeys() {
  return db.query(
    `SELECT k.id, k.label, k.hint, k.max_uses, k.uses, k.grant_minutes,
            k.created_at, k.expires_at, k.last_used_at, k.last_used_ip, u.username AS created_by,
            (k.expires_at IS NOT NULL AND k.expires_at <= NOW()) AS expired
       FROM breakglass_keys k LEFT JOIN users u ON u.id = k.created_by
      WHERE k.revoked = 0
      ORDER BY k.created_at DESC`
  );
}

function createKey({ label, hash, hint, maxUses, grantMinutes, createdBy, days }) {
  return db.query(
    `INSERT INTO breakglass_keys (label, uuid_hash, hint, max_uses, grant_minutes, created_by, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ${days ? 'DATE_ADD(NOW(), INTERVAL ? DAY)' : 'NULL'})`,
    days
      ? [label, hash, hint, maxUses, grantMinutes, createdBy, days]
      : [label, hash, hint, maxUses, grantMinutes, createdBy]
  );
}

function keyById(id) {
  return db.one('SELECT id, label FROM breakglass_keys WHERE id = ?', [id]);
}

// deleted, not marked revoked. its grants end in the same transaction. returns how many were live
function deleteKey(id) {
  return db.transaction(async (q) => {
    const grants = await q('UPDATE bypass_grants SET revoked = 1 WHERE key_id = ? AND revoked = 0', [id]);
    await q('DELETE FROM breakglass_keys WHERE id = ?', [id]);
    return grants.affectedRows;
  });
}

function recentGrants() {
  return db.query(
    `SELECT g.id, g.ip, g.user_agent, g.created_at, g.expires_at, g.revoked, k.label AS key_label
       FROM bypass_grants g LEFT JOIN breakglass_keys k ON k.id = g.key_id
      WHERE g.expires_at > DATE_SUB(NOW(), INTERVAL 1 DAY)
      ORDER BY g.created_at DESC LIMIT 100`
  );
}

async function revokeActiveGrants() {
  return (await db.query('UPDATE bypass_grants SET revoked = 1 WHERE revoked = 0 AND expires_at > NOW()')).affectedRows;
}

// ---------------------------------------------------------------- redeeming a key

function keyByHash(hash) {
  return db.one(
    `SELECT id, label, max_uses, uses, grant_minutes, revoked, expires_at
       FROM breakglass_keys WHERE uuid_hash = ?`,
    [hash]
  );
}

// the WHERE clause stops two people racing for the last use. false = none left
async function burnUse(id, ip) {
  return (await db.query(
    `UPDATE breakglass_keys
        SET uses = uses + 1, last_used_at = NOW(), last_used_ip = ?
      WHERE id = ? AND revoked = 0 AND (max_uses = 0 OR uses < max_uses)`,
    [ip, id]
  )).affectedRows > 0;
}

// key is the hash of the grant cookie, never the cookie itself
function createGrant({ key, keyId, ip, userAgent, minutes }) {
  return db.query(
    `INSERT INTO bypass_grants (id, key_id, ip, user_agent, expires_at)
     VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))`,
    [key, keyId, ip, userAgent, minutes]
  );
}

function liveGrant(key) {
  return db.one('SELECT id, ip FROM bypass_grants WHERE id = ? AND revoked = 0 AND expires_at > NOW()', [key]);
}

function sweepGrants() {
  return db.query('DELETE FROM bypass_grants WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY)');
}

module.exports = {
  liveKeys, createKey, keyById, deleteKey, recentGrants, revokeActiveGrants, keyByHash, burnUse, createGrant, liveGrant, sweepGrants
};
