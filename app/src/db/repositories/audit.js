// The audit trail: one row per thing someone did, and the page and export that read them back.
// Author: Tim Rice

const db = require('../../db');

const EXPORT_COLUMNS = ['ts', 'username', 'ip', 'action', 'target', 'result', 'detail', 'before_state', 'after_state'];

// values arrive already cut to fit the columns, states already masked
function insert({ userId, username, ip, action, target, detail, before, after, result }) {
  return db.query(
    `INSERT INTO audit_log (user_id, username, ip, action, target, detail, before_state, after_state, result)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, username, ip, action, target, detail, before === undefined ? null : before, after === undefined ? null : after, result || 'success']
  );
}

// action arrives already escaped as a LIKE prefix. the page and the export share this
function filterClause(f) {
  const where = [];
  const params = [];
  if (f.action) {
    where.push('action LIKE ?');
    params.push(f.action);
  }
  if (f.who) {
    where.push('username = ?');
    params.push(f.who);
  }
  if (f.result) {
    where.push('result = ?');
    params.push(f.result);
  }
  return { clause: where.length ? `WHERE ${where.join(' AND ')}` : '', params };
}

async function page(f, { limit, offset }) {
  const { clause, params } = filterClause(f);
  const rows = await db.query(
    `SELECT id, ts, username, ip, action, target, detail, before_state, after_state, result FROM audit_log ${clause}
      ORDER BY id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM audit_log ${clause}`, params);
  return { rows, total: Number(total.n) };
}

function exportSql(clause) {
  return `SELECT ${EXPORT_COLUMNS.join(', ')} FROM audit_log ${clause} ORDER BY id DESC`;
}

// rows past keeping. returns how many went
async function deleteOlderThan(days) {
  return (await db.query('DELETE FROM audit_log WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)', [days])).affectedRows;
}

module.exports = { EXPORT_COLUMNS, insert, filterClause, page, exportSql, deleteOlderThan };
