// The users table. SQL for portal accounts lives here.
// Author: Tim Rice

const db = require('../../db');

// columns an update may touch. names never come from outside this list
const UPDATABLE = new Set([
  'role', 'disabled', 'username', 'full_name', 'email', 'locked_until', 'failed_logins',
  'password_hash', 'must_change_password', 'password_changed_at'
]);

function list() {
  return db.query(
    `SELECT id, username, full_name, email, role, disabled, must_change_password,
            locked_until, created_at, last_login_at
       FROM users ORDER BY username`
  );
}

function byId(id) {
  return db.one('SELECT * FROM users WHERE id = ?', [id]);
}

// what a login attempt needs, hash included. never goes to a response
function forLogin(username) {
  return db.one(
    `SELECT id, username, password_hash, role, disabled, must_change_password, locked_until, failed_logins
       FROM users WHERE username = ?`,
    [username]
  );
}

async function nameTaken(username, exceptId) {
  const row = exceptId
    ? await db.one('SELECT id FROM users WHERE username = ? AND id <> ?', [username, exceptId])
    : await db.one('SELECT id FROM users WHERE username = ?', [username]);
  return !!row;
}

async function activeAdmins() {
  const row = await db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0");
  return Number(row.n);
}

function create(u) {
  return db.query(
    `INSERT INTO users (username, full_name, email, password_hash, role, must_change_password, password_changed_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW())`,
    [u.username, u.full_name, u.email, u.password_hash, u.role, u.must_change_password]
  );
}

function update(id, patch) {
  const columns = Object.keys(patch);
  for (const c of columns) {
    if (!UPDATABLE.has(c)) throw new Error(`users has no updatable column called ${c}`);
  }
  return db.query(`UPDATE users SET ${columns.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`, [...columns.map((c) => patch[c]), id]);
}

// someone changing their own password, which also ends the must-change nag
function setPassword(id, hash) {
  return db.query(
    'UPDATE users SET password_hash = ?, must_change_password = 0, password_changed_at = NOW() WHERE id = ?',
    [hash, id]
  );
}

// one attempt, taken before the password is looked at. true = go ahead, false = locked or out of attempts.
// counted by the database itself. reading the count and writing back one more let a burst of simultaneous guesses
// all read the same number and all get checked. a lock that ran out gives back one attempt, like it always did
async function reserveAttempt(id, maxAttempts) {
  const result = await db.query(
    `UPDATE users SET failed_logins = failed_logins + 1, locked_until = NULL
      WHERE id = ? AND ((locked_until IS NULL AND failed_logins < ?) OR locked_until <= NOW())`,
    [id, maxAttempts]
  );
  return Number(result.affectedRows) === 1;
}

// out of attempts: lock, once. true when this call is the one that locked it
async function lockIfSpent(id, maxAttempts, minutes) {
  const result = await db.query(
    `UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE)
      WHERE id = ? AND failed_logins >= ? AND locked_until IS NULL`,
    [minutes, id, maxAttempts]
  );
  return Number(result.affectedRows) === 1;
}

function recordLogin(id) {
  return db.query('UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = NOW() WHERE id = ?', [id]);
}

// ---------------------------------------------------------------- single sign on

async function otherActiveAdmins(exceptId) {
  const row = await db.one('SELECT COUNT(*) AS n FROM users WHERE role = ? AND disabled = 0 AND id <> ?', ['admin', exceptId]);
  return Number(row ? row.n : 0);
}

// emails aren't unique here, so two rows back tells the caller to refuse
function byEmailForSso(email) {
  return db.query('SELECT id, username, role, disabled FROM users WHERE LOWER(email) = ? ORDER BY id LIMIT 2', [email]);
}

function byUsernameForSso(username) {
  return db.one('SELECT id, username, role, disabled FROM users WHERE username = ? LIMIT 1', [username]);
}

// name and email follow the provider. a blank one leaves what is stored alone
function recordSsoLogin(id, { email, fullName, role }) {
  return db.query(
    `UPDATE users SET last_login_at = NOW(),
            email = COALESCE(NULLIF(?, ''), email),
            full_name = COALESCE(NULLIF(?, ''), full_name),
            role = ?,
            failed_logins = 0, locked_until = NULL
      WHERE id = ?`,
    [email, fullName, role, id]
  );
}

// passwordHash is random junk nothing hashes to, so the account is SSO only until an admin sets one
function createFromSso({ username, email, fullName, passwordHash, role }) {
  return db.query(
    `INSERT INTO users (username, email, full_name, password_hash, role, must_change_password)
     VALUES (?, ?, ?, ?, ?, 0)`,
    [username, email, fullName, passwordHash, role]
  );
}

function remove(id) {
  return db.query('DELETE FROM users WHERE id = ?', [id]);
}

// enabled accounts with an address to mail, the caller checks the address itself
function withEmail() {
  return db.query(
    `SELECT id, username, email, role FROM users
      WHERE disabled = 0 AND email IS NOT NULL AND email <> ''
      ORDER BY id`
  );
}

module.exports = {
  list, byId, forLogin, nameTaken, activeAdmins, create, update, setPassword, reserveAttempt, lockIfSpent, recordLogin, remove,
  otherActiveAdmins, byEmailForSso, byUsernameForSso, recordSsoLogin, createFromSso, withEmail
};
