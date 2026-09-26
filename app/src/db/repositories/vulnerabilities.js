// Vulnerability scans, findings, and the advisory versions somebody pulled anyway.
// Author: Tim Rice

const db = require('../../db');
const { sevRank } = require('./severity');

const FINDING_SORTS = { severity: 'sev_rank', package: 'package_name', first_seen: 'first_seen' };

function scanHistory() {
  return db.query(
    `SELECT id, started_at, finished_at, started_by, checked, vulnerable, fresh, resolved, failed, status
       FROM cve_scans ORDER BY id DESC LIMIT 10`
  );
}

// application/environment: undefined = any, null = not tagged, text = that one
async function downloadsPage(f, { limit, offset }) {
  const where = [];
  const params = [];
  if (f.severity) { where.push('d.severity = ?'); params.push(f.severity); }
  if (f.search) { where.push('d.package_name LIKE ?'); params.push(f.search); }
  if (f.ecosystem) { where.push('d.ecosystem = ?'); params.push(f.ecosystem); }
  for (const [column, value] of [['d.application', f.application], ['d.environment', f.environment]]) {
    if (value === undefined) continue;
    if (value === null) where.push(`${column} IS NULL`);
    else { where.push(`${column} = ?`); params.push(value); }
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const rows = await db.query(
    `SELECT d.id, d.ecosystem, d.package_name, d.version, d.severity, d.cves, d.ip, d.token_name,
            d.application, d.environment, d.cache_hit, d.ts, u.username
       FROM vuln_downloads d
       LEFT JOIN users u ON u.id = d.user_id
       ${clause} ORDER BY d.ts DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM vuln_downloads d ${clause}`, params);
  return { rows, total: Number(total.n) };
}

// search arrives already escaped for LIKE. the list and the export share this
function findingClause(f) {
  const where = [];
  const params = [];
  if (f.ecosystem) {
    where.push('ecosystem = ?');
    params.push(f.ecosystem);
  }
  if (f.severity) {
    where.push('severity = ?');
    params.push(f.severity);
  }
  if (f.search) {
    where.push('(package_name LIKE ? OR cves LIKE ? OR summary LIKE ?)');
    params.push(f.search, f.search, f.search);
  }
  // on the CISA KEV list under any of its CVEs
  if (f.kev) where.push("cves <> '' AND EXISTS (SELECT 1 FROM vuln_intel i WHERE i.kev = 1 AND FIND_IN_SET(i.cve, REPLACE(cves, ' ', '')))");
  //first seen in the last day = what last night's scan dragged in
  if (f.onlyNew) where.push('first_seen > DATE_SUB(NOW(), INTERVAL 24 HOUR)');
  return { clause: where.length ? `WHERE ${where.join(' AND ')}` : '', params };
}

async function findingsPage(filters, { sort, dir, limit, offset }) {
  const { clause, params } = findingClause(filters);
  // sevRank, not the words
  const order = FINDING_SORTS[String(sort || '').toLowerCase()] || 'sev_rank';
  const direction = dir === 'asc' ? 'ASC' : 'DESC';
  const rows = await db.query(
    `SELECT id, ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in,
            first_seen, last_seen, acknowledged, ${sevRank('severity')} AS sev_rank
       FROM cve_findings ${clause} ORDER BY ${order} ${direction}, package_name ASC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM cve_findings ${clause}`, params);
  const counts = await db.query('SELECT severity, COUNT(*) AS n FROM cve_findings GROUP BY severity');
  return { rows, total: Number(total.n), counts };
}

function findingById(id) {
  return db.one('SELECT * FROM cve_findings WHERE id = ?', [id]);
}

// every version of one package with a finding
function findingsForPackage(ecosystem, name) {
  return db.query('SELECT version, severity, cves, advisories FROM cve_findings WHERE ecosystem = ? AND package_name = ?', [ecosystem, name]);
}

// the finding on one exact version, if there is one
function findingForVersion(ecosystem, name, version) {
  return db.one('SELECT advisories, cves, severity, summary FROM cve_findings WHERE ecosystem = ? AND package_name = ? AND version = ?', [ecosystem, name, version]);
}

async function setAcknowledged(id, on) {
  return (await db.query('UPDATE cve_findings SET acknowledged = ? WHERE id = ?', [on, id])).affectedRows;
}

function deleteDownloadsOlderThan(days) {
  return db.query('DELETE FROM vuln_downloads WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)', [days]);
}

// findings for a batch of [ecosystem, package] pairs, keep batches to a few hundred
function findingsForPackages(pairs) {
  return db.query(
    `SELECT ecosystem, package_name, version, advisories, cves, severity FROM cve_findings
      WHERE (ecosystem, package_name) IN (${pairs.map(() => '(?, ?)').join(',')})`,
    pairs.flat()
  );
}

module.exports = {
  FINDING_SORTS, scanHistory, downloadsPage, findingClause, findingsPage, findingById, findingsForPackage, findingForVersion, setAcknowledged,
  findingsForPackages, deleteDownloadsOlderThan
};
