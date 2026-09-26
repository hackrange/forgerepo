// Any-version allow rules and whether anything of their package is cached.
// Author: Tim Rice
// the older npm tarballs and PyPI files tables count too, a box upgraded mid backfill has files only they know about

const db = require('../../db');

async function anyCached(ecosystem, name) {
  const row = await db.one(
    `SELECT (EXISTS (SELECT 1 FROM artifacts WHERE ecosystem = ? AND package_name = ?)
          OR (? = 'npm' AND EXISTS (SELECT 1 FROM tarballs WHERE package_name = ?))
          OR (? = 'pypi' AND EXISTS (SELECT 1 FROM pypi_files WHERE project = ?))) AS hit`,
    [ecosystem, name, ecosystem, name, ecosystem, name]
  );
  return !!(row && Number(row.hit));
}

// newest rules first, so the ones approved lately go before a backlog
function uncachedAnyVersion(limit) {
  return db.query(
    `SELECT r.id, r.ecosystem, r.pattern, r.kind, r.version_range, r.application_id, r.environment_id, r.enabled
       FROM rules r
      WHERE r.kind = 'allow' AND r.enabled = 1 AND COALESCE(r.version_range, '') = '' AND r.ecosystem IN ('npm', 'pypi')
        AND r.pattern NOT LIKE '%*%'
        AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.ecosystem = r.ecosystem AND a.package_name = r.pattern)
        AND NOT (r.ecosystem = 'npm' AND EXISTS (SELECT 1 FROM tarballs t WHERE t.package_name = r.pattern))
        AND NOT (r.ecosystem = 'pypi' AND EXISTS (SELECT 1 FROM pypi_files f WHERE f.project = r.pattern))
      ORDER BY r.id DESC
      LIMIT ?`,
    [limit]
  );
}

module.exports = { anyCached, uncachedAnyVersion };
