// Logins someone started at the identity provider and hasn't come back from yet.
// Author: Tim Rice
// a state is single use, the caller deletes it the moment it is read

const db = require('../../db');

function add({ state, nonce, verifier, ip }) {
  return db.query('INSERT INTO sso_states (state, nonce, verifier, ip) VALUES (?, ?, ?, ?)', [state, nonce, verifier, ip]);
}

// only one young enough to still count
function live(state, ttlMinutes) {
  return db.one(
    `SELECT state, nonce, verifier FROM sso_states
      WHERE state = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
    [state, ttlMinutes]
  );
}

function remove(state) {
  return db.query('DELETE FROM sso_states WHERE state = ?', [state]);
}

function sweep(ttlMinutes) {
  return db.query('DELETE FROM sso_states WHERE created_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)', [ttlMinutes]);
}

module.exports = { add, live, remove, sweep };
