// Import and export: what goes out in a file, and the lookups an import needs.
// Author: Tim Rice
// table names come from the fixed lists below, never from a request

const db = require('../../db');
const { sevRank } = require('./severity');

// scope goes out by name, ids mean nothing on another box
const RULE_COLUMNS = ['ecosystem', 'pattern', 'kind', 'version_range', 'application', 'environment', 'note', 'priority', 'enabled'];

const FINDING_COLUMNS = ['ecosystem', 'package_name', 'version', 'severity', 'cves', 'advisories', 'summary',
  'fixed_in', 'first_seen', 'last_seen', 'acknowledged'];

const LABEL_TABLES = { applications: 'applications', environments: 'environments' };
const ACL_TABLES = { ip_acl: 'ip_acl', registry_acl: 'registry_acl' };

// clause comes from the rules repository's filterClause
function rulesExportSql(clause) {
  return `SELECT ecosystem, pattern, kind, version_range,
                 COALESCE((SELECT name FROM applications WHERE id = rules.application_id), '') AS application,
                 COALESCE((SELECT name FROM environments WHERE id = rules.environment_id), '') AS environment,
                 note, priority, enabled
            FROM rules ${clause} ORDER BY ecosystem, kind, pattern, id`;
}

async function countRules(clause = '', params = []) {
  return Number((await db.one(`SELECT COUNT(*) AS n FROM rules ${clause}`, params)).n);
}

function findingsExportSql(clause) {
  return `SELECT ${FINDING_COLUMNS.join(', ')}
            FROM cve_findings ${clause}
           ORDER BY ${sevRank('severity')} DESC, ecosystem, package_name, version`;
}

async function countFindings(clause, params) {
  return Number((await db.one(`SELECT COUNT(*) AS n FROM cve_findings ${clause}`, params)).n);
}

// the whole config file carries rules without scope, same as it always has
const CONFIG_RULES_SQL = 'SELECT ecosystem, pattern, kind, version_range, note, priority, enabled FROM rules ORDER BY ecosystem, kind, pattern, id';

// lower-cased name -> id, looked up once per import
async function labelIds(key) {
  const table = LABEL_TABLES[key];
  if (!table) throw new Error(`there is no label list called ${key}`);
  return new Map((await db.query(`SELECT id, name FROM ${table}`)).map((r) => [String(r.name).toLowerCase(), r.id]));
}

function aclForExport(key) {
  const table = ACL_TABLES[key];
  if (!table) throw new Error(`there is no allowlist called ${key}`);
  return db.query(`SELECT cidr, label, enabled FROM ${table} ORDER BY cidr`);
}

// an imported entry keeps its own enabled flag, unlike one added by hand
function importPortalAcl({ cidr, label, enabled, createdBy }) {
  return db.query(
    `INSERT INTO ip_acl (cidr, label, enabled, created_by) VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE label = VALUES(label), enabled = VALUES(enabled)`,
    [cidr, label, enabled, createdBy]
  );
}

module.exports = {
  RULE_COLUMNS, FINDING_COLUMNS, CONFIG_RULES_SQL,
  rulesExportSql, countRules, findingsExportSql, countFindings, labelIds, aclForExport, importPortalAcl
};
