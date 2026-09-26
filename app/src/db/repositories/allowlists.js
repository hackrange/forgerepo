// The two network allow lists: who reaches the portal, and which clients reach the registry.
// Author: Tim Rice
// same table shape. the table comes from the fixed list below, never from a request

const db = require('../../db');

const TABLES = { portal: 'ip_acl', registry: 'registry_acl' };

function table(list) {
  const t = TABLES[list];
  if (!t) throw new Error(`there is no allow list called ${list}`);
  return t;
}

function list(name) {
  return db.query(`SELECT id, cidr, label, enabled, created_by, created_at FROM ${table(name)} ORDER BY created_at DESC`);
}

function byId(name, id) {
  return db.one(`SELECT id, cidr FROM ${table(name)} WHERE id = ?`, [id]);
}

// exceptId leaves one out, for "would this be the last one"
async function enabledCount(name, exceptId) {
  const row = exceptId
    ? await db.one(`SELECT COUNT(*) AS n FROM ${table(name)} WHERE enabled = 1 AND id <> ?`, [exceptId])
    : await db.one(`SELECT COUNT(*) AS n FROM ${table(name)} WHERE enabled = 1`);
  return Number(row.n);
}

// what the address checks match against
function enabledEntries(name) {
  return db.query(`SELECT id, cidr, label FROM ${table(name)} WHERE enabled = 1`);
}

// adding a network that is already there switches it back on
function add(name, { cidr, label, createdBy }) {
  return db.query(
    `INSERT INTO ${table(name)} (cidr, label, enabled, created_by) VALUES (?, ?, 1, ?)
     ON DUPLICATE KEY UPDATE label = VALUES(label), enabled = 1`,
    [cidr, label, createdBy]
  );
}

function setEnabled(name, id, enabled) {
  return db.query(`UPDATE ${table(name)} SET enabled = ? WHERE id = ?`, [enabled, id]);
}

function remove(name, id) {
  return db.query(`DELETE FROM ${table(name)} WHERE id = ?`, [id]);
}

// puts a deleted entry straight back, when it turned out to be someone's own way in
function restore(name, { cidr, label, createdBy }) {
  return db.query(`INSERT INTO ${table(name)} (cidr, label, enabled, created_by) VALUES (?, ?, 1, ?)`, [cidr, label, createdBy]);
}

module.exports = { TABLES, list, byId, enabledCount, enabledEntries, add, setEnabled, remove, restore };
