// Integrations and their outbox. the secret column is written here and never selected back out for a list.
// Author: Tim Rice

const db = require('../../db');

// a list only ever learns whether a secret is set
const LIST_COLUMNS = `id, name, kind, url, host, port, transport, format, events, enabled, secret IS NOT NULL AND secret <> '' AS has_secret,
  last_status, last_error, last_attempt_at, last_success_at, failures, created_by, created_at,
  (SELECT COUNT(*) FROM event_outbox o WHERE o.integration_id = integrations.id AND o.status = 'pending') AS pending,
  (SELECT COUNT(*) FROM event_outbox o WHERE o.integration_id = integrations.id AND o.status = 'failed') AS failed`;

function list() {
  return db.query(`SELECT ${LIST_COLUMNS} FROM integrations ORDER BY name`);
}

// the whole row, secret included, for sending and for edits. never straight to a response
function byId(id) {
  return db.one('SELECT * FROM integrations WHERE id = ?', [id]);
}

async function nameTaken(name, exceptId) {
  const row = exceptId
    ? await db.one('SELECT id FROM integrations WHERE name = ? AND id <> ?', [name, exceptId])
    : await db.one('SELECT id FROM integrations WHERE name = ?', [name]);
  return !!row;
}

function create(f, createdBy) {
  return db.query(
    `INSERT INTO integrations (name, kind, url, host, port, transport, format, secret, events, enabled, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [f.name, f.kind, f.url, f.host, f.port, f.transport, f.format, f.secret, f.events, f.enabled, createdBy]
  );
}

function update(id, v) {
  return db.query(
    'UPDATE integrations SET name = ?, url = ?, host = ?, port = ?, transport = ?, format = ?, secret = ?, events = ?, enabled = ? WHERE id = ?',
    [v.name, v.url, v.host, v.port, v.transport, v.format, v.secret, v.events, v.enabled, id]
  );
}

function remove(id) {
  return db.query('DELETE FROM integrations WHERE id = ?', [id]);
}

function deliveries(id) {
  return db.query(
    `SELECT id, event_type, status, attempts, response_status, last_error, next_attempt_at, created_at, delivered_at
       FROM event_outbox WHERE integration_id = ? ORDER BY id DESC LIMIT 100`,
    [id]
  );
}

async function retryFailed(id) {
  return (await db.query(
    "UPDATE event_outbox SET status = 'pending', attempts = 0, next_attempt_at = NOW(), claim = NULL WHERE integration_id = ? AND status = 'failed'",
    [id]
  )).affectedRows;
}

// how the last send went. error arrives already cut to fit, a success clears the failure count
function noteAttempt(id, { status, error }) {
  return db.query(
    `UPDATE integrations SET last_attempt_at = NOW(), last_status = ?, last_error = ?,
            last_success_at = IF(? = 'ok', NOW(), last_success_at), failures = IF(? = 'ok', 0, failures + 1) WHERE id = ?`,
    [status, error, status, status, id]
  );
}

module.exports = { LIST_COLUMNS, list, byId, nameTaken, create, update, remove, deliveries, retryFailed, noteAttempt };
