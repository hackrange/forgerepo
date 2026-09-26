// Properties: searchable key=value metadata on a package version, or on every version of a package.
// Author: Tim Rice

const db = require('../../db');

// the properties that apply to one version: its own, then the package wide ones it does not override
function forVersion(ecosystem, name, version) {
  return db.query(
    `SELECT k, v, version, set_by, set_at FROM artifact_properties
      WHERE ecosystem = ? AND package_name = ? AND version IN (?, '')
      ORDER BY k, version DESC`,
    [ecosystem, name, version || '']
  );
}

// exactly what is set on one target, version '' being the whole package
function onTarget(ecosystem, name, version) {
  return db.query(
    'SELECT k, v, set_by, set_at FROM artifact_properties WHERE ecosystem = ? AND package_name = ? AND version = ? ORDER BY k',
    [ecosystem, name, version || '']
  );
}

// all of it in one transaction, so a limit or a bad value never leaves half a change
function apply(target, { set, remove }, user) {
  return db.transaction(async (q) => {
    for (const k of remove) {
      await q('DELETE FROM artifact_properties WHERE ecosystem = ? AND package_name = ? AND version = ? AND k = ?',
        [target.ecosystem, target.name, target.version, k]);
    }
    for (const [k, v] of Object.entries(set)) {
      await q(
        `INSERT INTO artifact_properties (ecosystem, package_name, version, k, v, set_by) VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE v = VALUES(v), set_by = VALUES(set_by), set_at = NOW()`,
        [target.ecosystem, target.name, target.version, k, v, user]
      );
    }
  });
}

// the keys in use and how often, for the filter and the form to suggest
function keys(limit) {
  return db.query('SELECT k, COUNT(*) AS n FROM artifact_properties GROUP BY k ORDER BY n DESC, k LIMIT ?', [limit]);
}

// for the artifacts list: a file matches on the value that applies to it, so its own version's value beats the package's
function matchClause(alias, { key, value }) {
  const same = `p.ecosystem = ${alias}.ecosystem AND p.package_name = ${alias}.package_name`;
  if (value === null || value === undefined) {
    return { sql: `EXISTS (SELECT 1 FROM artifact_properties p WHERE ${same} AND p.version IN (${alias}.version, '') AND p.k = ?)`, params: [key] };
  }
  return {
    sql: `(EXISTS (SELECT 1 FROM artifact_properties p WHERE ${same} AND p.version = ${alias}.version AND p.k = ? AND p.v = ?)
       OR (EXISTS (SELECT 1 FROM artifact_properties p WHERE ${same} AND p.version = '' AND p.k = ? AND p.v = ?)
           AND NOT EXISTS (SELECT 1 FROM artifact_properties p WHERE ${same} AND p.version = ${alias}.version AND ${alias}.version <> '' AND p.k = ?)))`,
    params: [key, value, key, value, key]
  };
}

module.exports = { forVersion, onTarget, apply, keys, matchClause };
