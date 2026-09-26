// The safe version resolution log.
// Author: Tim Rice

const db = require('../../db');

// search arrives already escaped for LIKE
async function page(f, { limit, offset }) {
  const where = [];
  const params = [];
  if (f.ecosystem) {
    where.push('r.ecosystem = ?');
    params.push(f.ecosystem);
  }
  if (f.search) {
    where.push('r.package_name LIKE ?');
    params.push(f.search);
  }
  if (f.application) {
    where.push('r.application = ?');
    params.push(f.application);
  }
  if (f.environment) {
    where.push('r.environment = ?');
    params.push(f.environment);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = await db.query(
    `SELECT r.id, r.ts, r.ecosystem, r.package_name, r.application, r.environment, r.token_name, r.ip,
            r.offered_count, r.excluded_count, r.excluded, r.latest_offered, r.selected_version, r.selected_at
       FROM resolutions r ${clause} ORDER BY r.ts DESC, r.id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM resolutions r ${clause}`, params);
  return { rows, total: Number(total.n) };
}

// one resolution that left versions out. excluded arrives as json text
function record(r) {
  return db.query(
    `INSERT INTO resolutions
       (ecosystem, package_name, application, environment, token_name, user_id, ip, npm_session,
        offered_count, excluded_count, excluded, latest_offered)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [r.ecosystem, r.name, r.application, r.environment, r.tokenName, r.userId, r.ip, r.session, r.offered, r.excludedCount, r.excluded, r.latest]
  );
}

// the version the install then pulled, matched by npm session or by address and token, within 15 minutes
function noteSelected({ version, ecosystem, name, session, ip, tokenName }) {
  const match = session ? 'npm_session = ?' : 'ip = ? AND token_name <=> ?';
  const params = session ? [session] : [ip, tokenName];
  return db.query(
    `UPDATE resolutions SET selected_version = ?, selected_at = NOW()
      WHERE ecosystem = ? AND package_name = ? AND selected_version IS NULL AND ${match}
        AND ts > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
      ORDER BY id DESC LIMIT 1`,
    [version, ecosystem, name, ...params]
  );
}

async function deleteOlderThan(days) {
  return (await db.query('DELETE FROM resolutions WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)', [days])).affectedRows;
}

module.exports = { page, record, noteSelected, deleteOlderThan };
