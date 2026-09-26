// What an SBOM is made from: cached files of the packages a version depends on, and what an application downloaded.
// Author: Tim Rice

const db = require('../../db');

// every cached file of these packages, so a dependency can be pinned to a version this box really has
function cachedFiles(ecosystem, names) {
  if (!names.length) return Promise.resolve([]);
  return db.query(
    `SELECT package_name, version, filename, sha256, license_expression FROM artifacts
      WHERE ecosystem = ? AND package_name IN (${names.map(() => '?').join(', ')}) AND version <> ''
      ORDER BY package_name, version, filename`,
    [ecosystem, ...names]
  );
}

// one row per cached file of each version the application took, or one with no file when it has been purged since
function consumed(application, environment, limit) {
  const envClause = environment ? 'AND environment = ?' : '';
  return db.query(
    `SELECT c.ecosystem, c.package_name, c.version, a.filename, a.sha256, a.license_expression
       FROM (SELECT DISTINCT ecosystem, package_name, version FROM consumption WHERE application = ? ${envClause}) c
       LEFT JOIN artifacts a ON a.ecosystem = c.ecosystem AND a.package_name = c.package_name AND a.version = c.version
      ORDER BY c.ecosystem, c.package_name, c.version, a.filename
      LIMIT ?`,
    environment ? [application, environment, limit] : [application, limit]
  );
}

module.exports = { cachedFiles, consumed };
