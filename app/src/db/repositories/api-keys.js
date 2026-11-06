// API keys for /_api/v1. hash and prefix only, a key itself is never stored.
// Author: Tim Rice

const db = require('../../db');

const COLUMNS = `id, name, prefix, scopes, allowed_cidrs, max_priority, expires_at, revoked_at, revoked_by,
                 created_by, created_at, last_used_at, last_used_ip,
                 UNIX_TIMESTAMP(expires_at) AS expires_ts,
                 (SELECT COUNT(*) FROM rules WHERE rules.api_key_id = api_keys.id) AS rule_count`;

function list() {
  return db.query(`SELECT ${COLUMNS} FROM api_keys ORDER BY revoked_at IS NOT NULL, created_at DESC`);
}

function byId(id) {
  return db.one(`SELECT ${COLUMNS} FROM api_keys WHERE id = ?`, [id]);
}

// what a request's key resolves to. revoked and expired are checked by the caller so it can say which
function byHash(hash) {
  return db.one(
    `SELECT id, name, prefix, key_hash, scopes, allowed_cidrs, max_priority, revoked_at,
            (expires_at IS NOT NULL AND expires_at <= NOW()) AS expired
       FROM api_keys WHERE key_hash = ?`,
    [hash]
  );
}

async function insert(k) {
  const res = await db.query(
    `INSERT INTO api_keys (name, prefix, key_hash, scopes, allowed_cidrs, max_priority, expires_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, FROM_UNIXTIME(?), ?)`,
    [k.name, k.prefix, k.hash, k.scopes, k.cidrs, k.maxPriority, k.expiresTs, k.createdBy]
  );
  return res.insertId;
}

// a revoked key stays revoked, editing it would be bringing it back by the side door
async function update(id, k) {
  return (await db.query(
    `UPDATE api_keys SET name = ?, scopes = ?, allowed_cidrs = ?, max_priority = ?, expires_at = FROM_UNIXTIME(?)
      WHERE id = ? AND revoked_at IS NULL`,
    [k.name, k.scopes, k.cidrs, k.maxPriority, k.expiresTs, id]
  )).affectedRows;
}

async function revoke(id, by) {
  return (await db.query('UPDATE api_keys SET revoked_at = NOW(), revoked_by = ? WHERE id = ? AND revoked_at IS NULL', [by, id])).affectedRows;
}

// only once revoked. the rules it made stay, they just belong to nobody now
async function remove(id) {
  return (await db.query('DELETE FROM api_keys WHERE id = ? AND revoked_at IS NOT NULL', [id])).affectedRows;
}

function touch(id, ip) {
  return db.query('UPDATE api_keys SET last_used_at = NOW(), last_used_ip = ? WHERE id = ?', [String(ip || '').slice(0, 45), id]);
}

module.exports = { list, byId, byHash, insert, update, revoke, remove, touch };
