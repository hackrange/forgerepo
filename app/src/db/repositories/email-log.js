// What mail went out, and what didn't.
// Author: Tim Rice

const db = require('../../db');

async function page({ limit, offset }) {
  const rows = await db.query(
    `SELECT id, ts, kind, to_address, subject, transport, ok, error
       FROM email_log ORDER BY id DESC LIMIT ? OFFSET ?`,
    [limit, offset]
  );
  const total = await db.one('SELECT COUNT(*) AS n FROM email_log');
  return { rows, total: Number(total.n) };
}

// one send, worked or not. text arrives already cut to fit
function insert({ kind, to, subject, transport, ok, error }) {
  return db.query(
    `INSERT INTO email_log (kind, to_address, subject, transport, ok, error)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [kind, to, subject, transport, ok, error]
  );
}

module.exports = { page, insert };
