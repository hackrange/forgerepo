// Lifecycle stages of package versions: where each one stands now, and every move it ever made.
// Author: Tim Rice

const db = require('../../db');

function current(ecosystem, name, version) {
  return db.one(
    'SELECT stage, reason, set_by, set_at FROM lifecycle_stages WHERE ecosystem = ? AND package_name = ? AND version = ?',
    [ecosystem, name, version]
  );
}

function history(ecosystem, name, version, limit) {
  return db.query(
    `SELECT from_stage, to_stage, reason, moved_by, moved_at FROM lifecycle_history
      WHERE ecosystem = ? AND package_name = ? AND version = ? ORDER BY id DESC LIMIT ?`,
    [ecosystem, name, version, limit]
  );
}

// the current stage and the history row together, or neither. from is what the caller saw, so a race loses
function move({ ecosystem, name, version, from, to, reason, user }) {
  return db.transaction(async (q) => {
    const rows = await q(
      'SELECT stage FROM lifecycle_stages WHERE ecosystem = ? AND package_name = ? AND version = ? FOR UPDATE',
      [ecosystem, name, version]
    );
    const now = rows && rows[0] ? rows[0].stage : null;
    if (now !== from) return false;
    await q(
      `INSERT INTO lifecycle_stages (ecosystem, package_name, version, stage, reason, set_by) VALUES (?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE stage = VALUES(stage), reason = VALUES(reason), set_by = VALUES(set_by), set_at = NOW()`,
      [ecosystem, name, version, to, reason, user]
    );
    await q(
      'INSERT INTO lifecycle_history (ecosystem, package_name, version, from_stage, to_stage, reason, moved_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [ecosystem, name, version, from, to, reason, user]
    );
    return true;
  });
}

// what the gate needs: only the versions a stage matters for, blocked and everything that is not production yet
function enforced() {
  return db.query('SELECT ecosystem, package_name, version, stage FROM lifecycle_stages');
}

function counts() {
  return db.query('SELECT stage, COUNT(*) AS n FROM lifecycle_stages GROUP BY stage');
}

// for the artifacts list: a file matches when its version stands at that stage
function matchClause(alias, stage) {
  return {
    sql: `EXISTS (SELECT 1 FROM lifecycle_stages s WHERE s.ecosystem = ${alias}.ecosystem AND s.package_name = ${alias}.package_name AND s.version = ${alias}.version AND s.stage = ?)`,
    params: [stage]
  };
}

module.exports = { current, history, move, enforced, counts, matchClause };
