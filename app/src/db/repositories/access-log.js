// The traffic log: rows the registries write, and what the page and its export read.
// Author: Tim Rice

const db = require('../../db');

// npm_session isn't on the page but ties metadata to tarball - handy in a spreadsheet
const EXPORT_COLUMNS = ['ts', 'ip', 'token_name', 'application', 'environment', 'method', 'path',
  'package_name', 'version', 'pulled_version', 'pulled_exact', 'npm_session', 'action', 'reason',
  'status', 'bytes', 'cache_hit', 'duration_ms'];

// one registry request. long text is cut to fit the columns
function insert(row, session, ci) {
  return db.query(
    `INSERT INTO access_log
       (ip, user_id, token_id, token_name, application, environment, ecosystem,
        method, path, package_name, version,
        pulled_version, pulled_exact, npm_session, ci,
        action, reason, blocked_by, rule_id, status, bytes, cache_hit, duration_ms)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      row.ip, row.user_id, row.token_id, row.token_name,
      row.application, row.environment, row.ecosystem,
      row.method, row.path,
      row.package_name, row.version,
      row.pulled_version ? String(row.pulled_version).slice(0, 255) : null,
      row.pulled_exact ? 1 : 0, session, ci,
      row.action, row.reason ? String(row.reason).slice(0, 255) : null,
      row.blocked_by ? String(row.blocked_by).slice(0, 16) : null,
      row.rule_id, row.status, row.bytes, row.cache_hit, row.duration_ms
    ]
  );
}

// replace the latest-tag guess with what really got pulled. several can pile up
function notePulled(session, name, version) {
  return db.query(
    `UPDATE access_log
        SET pulled_version = LEFT(
              CASE
                WHEN pulled_exact = 0 OR pulled_version IS NULL THEN ?
                WHEN FIND_IN_SET(?, REPLACE(pulled_version, ', ', ',')) THEN pulled_version
                ELSE CONCAT(pulled_version, ', ', ?)
              END, 255),
            pulled_exact = 1
      WHERE npm_session = ? AND package_name = ? AND version IS NULL
      ORDER BY id DESC LIMIT 1`,
    [version, version, version, session, name]
  );
}

// package arrives already escaped for LIKE. application/environment: undefined = any, null = not tagged
function filterClause(f) {
  const where = [];
  const params = [];
  if (f.action) {
    where.push('action = ?');
    params.push(f.action);
  }
  if (f.pkg) {
    where.push('package_name LIKE ?');
    params.push(f.pkg);
  }
  if (f.ip) {
    where.push('ip = ?');
    params.push(f.ip);
  }
  for (const [column, value] of [['application', f.application], ['environment', f.environment]]) {
    if (value === undefined) continue;
    if (value === null) {
      where.push(`${column} IS NULL`);
    } else {
      where.push(`${column} = ?`);
      params.push(value);
    }
  }
  return { clause: where.length ? `WHERE ${where.join(' AND ')}` : '', params };
}

async function page(filters, { limit, offset }) {
  const { clause, params } = filterClause(filters);
  const rows = await db.query(
    `SELECT id, ts, ip, token_name, application, environment, ecosystem, method, path, package_name, version,
            pulled_version, pulled_exact, action,
            reason, blocked_by, status, bytes, cache_hit, duration_ms
       FROM access_log ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  return { rows, total: await count(clause, params) };
}

async function count(clause, params) {
  return Number((await db.one(`SELECT COUNT(*) AS n FROM access_log ${clause}`, params)).n);
}

function exportSql(clause) {
  return `SELECT ${EXPORT_COLUMNS.join(', ')} FROM access_log ${clause} ORDER BY id DESC`;
}

// one line with everything it recorded, and the account name when there was one
function byId(id) {
  return db.one('SELECT a.*, u.username FROM access_log a LEFT JOIN users u ON u.id = a.user_id WHERE a.id = ?', [id]);
}

// downloads served in the last few days, newest first, capped. for "who already has it"
function pullsFor(ecosystem, name, days) {
  return db.query(
    `SELECT ts, ip, token_name, application, environment, COALESCE(pulled_version, version) AS version, pulled_exact,
            version AS requested, path LIKE '/v2/%/manifests/%' AS manifest
       FROM access_log
      WHERE ecosystem = ? AND package_name = ? AND action IN ('allow', 'audit') AND status < 400
        AND ts >= DATE_SUB(NOW(), INTERVAL ? DAY)
      ORDER BY ts DESC LIMIT 20000`,
    [ecosystem, name, days]
  );
}

// what a proposed rule would be judged against. deny = refused files, otherwise exact downloads that went out
function replayRows(days, action, maxRows) {
  // an image is replayed by the tag or digest that was asked for, which is what a rule names
  const which = action === 'deny'
    ? "a.action = 'deny' AND a.status = 403 AND a.version IS NOT NULL AND (a.path LIKE '%/-/%' OR a.path LIKE '/pypi/files/%' OR a.path LIKE '/v2/%/manifests/%')"
    : "a.pulled_exact = 1 AND a.action IN ('allow', 'audit') AND a.status < 400";
  return db.query(
    `SELECT a.user_id, a.token_name, a.application, a.environment, a.ecosystem, a.package_name,
            IF(a.ecosystem = 'oci', a.version, COALESCE(a.pulled_version, a.version)) AS version, a.ci, a.reason, u.username
       FROM access_log a
       LEFT JOIN users u ON u.id = a.user_id
      WHERE a.ts >= DATE_SUB(NOW(), INTERVAL ? DAY) AND a.package_name IS NOT NULL
        AND ${which}
      ORDER BY a.id DESC LIMIT ?`,
    [days, maxRows]
  );
}

// rows past keeping. returns how many went
async function deleteOlderThan(days) {
  return (await db.query('DELETE FROM access_log WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)', [days])).affectedRows;
}

module.exports = { EXPORT_COLUMNS, insert, notePulled, filterClause, page, count, byId, exportSql, pullsFor, replayRows, deleteOlderThan };
