// Applications and environments, the labels tokens and rules carry. same table shape, one set of queries.
// Author: Tim Rice
// the table and column come from the fixed list below, never from a request

const db = require('../../db');

const KINDS = {
  applications: { table: 'applications', column: 'application_id' },
  environments: { table: 'environments', column: 'environment_id', flag: 'production' }
};
const SETTABLE = new Set(['name', 'note', 'retired', 'production']);

function kind(key) {
  const k = KINDS[key];
  if (!k) throw new Error(`there is no label list called ${key}`);
  return k;
}

// token count in the same query, the retire button uses it
function list(key) {
  const { table, column, flag } = kind(key);
  return db.query(
    `SELECT l.id, l.name, l.note, l.retired, l.created_by, l.created_at, ${flag ? 'l.production,' : ''}
            COUNT(t.id) AS live_tokens
       FROM ${table} l
       LEFT JOIN tokens t ON t.${column} = l.id AND t.revoked = 0
      GROUP BY l.id, l.name, l.note, l.retired, l.created_by, l.created_at${flag ? ', l.production' : ''}
      ORDER BY l.retired ASC, l.name ASC`
  );
}

function byId(key, id) {
  return db.one(`SELECT id, name, retired FROM ${kind(key).table} WHERE id = ?`, [id]);
}

// the column is _ci, so this finds another spelling of the same name too
function byName(key, name) {
  return db.one(`SELECT name FROM ${kind(key).table} WHERE name = ?`, [name]);
}

async function nameTakenByAnother(key, name, id) {
  return !!(await db.one(`SELECT id FROM ${kind(key).table} WHERE name = ? AND id <> ?`, [name, id]));
}

function create(key, { name, note, production, createdBy }) {
  const { table, flag } = kind(key);
  return flag
    ? db.query(`INSERT INTO ${table} (name, note, production, created_by) VALUES (?, ?, ?, ?)`, [name, note, production, createdBy])
    : db.query(`INSERT INTO ${table} (name, note, created_by) VALUES (?, ?, ?)`, [name, note, createdBy]);
}

// sets: [[column, value]] in the order they should be written
function update(key, id, sets) {
  for (const [c] of sets) {
    if (!SETTABLE.has(c)) throw new Error(`${key} has no settable column called ${c}`);
  }
  return db.query(`UPDATE ${kind(key).table} SET ${sets.map(([c]) => `${c} = ?`).join(', ')} WHERE id = ?`, [...sets.map(([, v]) => v), id]);
}

function remove(key, id) {
  return db.query(`DELETE FROM ${kind(key).table} WHERE id = ?`, [id]);
}

async function tokenUse(key, id) {
  const row = await db.one(`SELECT COUNT(*) AS n, SUM(revoked = 0) AS live FROM tokens WHERE ${kind(key).column} = ?`, [id]);
  return { total: Number(row.n), live: Number(row.live || 0) };
}

async function ruleUse(key, id) {
  return Number((await db.one(`SELECT COUNT(*) AS n FROM rules WHERE ${kind(key).column} = ?`, [id])).n);
}

// every id and name, environments with their production flag
function names(key) {
  const { table, flag } = kind(key);
  return db.query(`SELECT id, name${flag ? `, ${flag}` : ''} FROM ${table}`);
}

module.exports = { KINDS, list, byId, byName, nameTakenByAnother, create, update, remove, tokenUse, ruleUse, names };
