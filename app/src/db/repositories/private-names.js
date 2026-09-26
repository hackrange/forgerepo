// Reserved names: the npm scopes and PyPI prefixes that belong to this organization and are never fetched from outside.
// Author: Tim Rice

const db = require('../../db');

function all() {
  return db.query('SELECT id, ecosystem, pattern, note, created_by, created_at FROM private_names ORDER BY ecosystem, pattern');
}

function byId(id) {
  return db.one('SELECT id, ecosystem, pattern, note, created_by, created_at FROM private_names WHERE id = ?', [id]);
}

async function count() {
  const row = await db.one('SELECT COUNT(*) AS n FROM private_names');
  return Number(row ? row.n : 0);
}

// the unique key makes a second add of the same pattern a no-op the caller can see
async function add({ ecosystem, pattern, note, user }) {
  const result = await db.query(
    'INSERT IGNORE INTO private_names (ecosystem, pattern, note, created_by) VALUES (?, ?, ?, ?)',
    [ecosystem, pattern, note || null, user || null]
  );
  return result.affectedRows === 1 ? Number(result.insertId) : null;
}

async function remove(id) {
  return (await db.query('DELETE FROM private_names WHERE id = ?', [id])).affectedRows === 1;
}

module.exports = { all, byId, count, add, remove };
