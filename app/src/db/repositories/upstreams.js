// The upstream registries table, for the portal. the routing cache itself lives in upstreams.js
// Author: Tim Rice

const db = require('../../db');

const UPDATABLE = new Set(['name', 'url', 'priority', 'enabled', 'fallback', 'pattern', 'token', 'options']);

function list() {
  return db.query('SELECT * FROM upstreams ORDER BY is_default DESC, priority DESC, name ASC');
}

function byId(id) {
  return db.one('SELECT * FROM upstreams WHERE id = ?', [id]);
}

function defaultFor(ecosystem) {
  return db.one('SELECT name FROM upstreams WHERE ecosystem = ? AND is_default = 1', [ecosystem]);
}

async function nameTaken(name, exceptId) {
  const row = exceptId
    ? await db.one('SELECT id FROM upstreams WHERE name = ? AND id <> ?', [name, exceptId])
    : await db.one('SELECT id FROM upstreams WHERE name = ?', [name]);
  return !!row;
}

function create(u) {
  return db.query(
    `INSERT INTO upstreams (name, ecosystem, url, token, pattern, priority, enabled, is_default, fallback, options, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [u.name, u.ecosystem, u.url, u.token, u.pattern, u.priority, u.enabled, u.is_default, u.fallback, u.options || null, u.created_by]
  );
}

function update(id, changes) {
  const keys = Object.keys(changes);
  for (const k of keys) {
    if (!UPDATABLE.has(k)) throw new Error(`upstreams has no updatable column called ${k}`);
  }
  return db.query(`UPDATE upstreams SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, [...keys.map((k) => changes[k]), id]);
}

function remove(id) {
  return db.query('DELETE FROM upstreams WHERE id = ?', [id]);
}

async function cachedFrom(name) {
  return Number((await db.one('SELECT COUNT(*) AS n FROM packuments WHERE source = ?', [name])).n);
}

module.exports = { list, byId, defaultFor, nameTaken, create, update, remove, cachedFrom };
