// Which tables a move to an outside database copies: every one the schema makes.
// Author: Tim Rice

const fs = require('fs');
const path = require('path');

// parents first, only so the copy log reads sensibly. fk checks are off during the copy anyway.
//upstreams HAS to come along, or supplier scopes quietly get pulled off the public registry. Sneaky.
const FIRST = [
  'users', 'settings', 'upstreams', 'rules', 'packages', 'requests', 'tarballs', 'packuments',
  'applications', 'environments',
  'tokens', 'sessions', 'ip_acl', 'registry_acl', 'registry_acl_feed', 'acl_feeds',
  'breakglass_keys', 'bypass_grants',
  'cleared_packages', 'access_log', 'audit_log', 'vuln_downloads',
  'cve_scans', 'cve_advisories', 'cve_findings'
];

function schemaTables(sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8')) {
  return [...sql.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
}

// every schema table exactly once, the FIRST ones leading
function copyOrder(tables = schemaTables()) {
  return [...FIRST.filter((t) => tables.includes(t)), ...tables.filter((t) => !FIRST.includes(t))];
}

// tables on the source the copy would leave behind
function leftBehind(present, order) {
  const known = new Set(order);
  return present.filter((t) => !known.has(t));
}

module.exports = { FIRST, schemaTables, copyOrder, leftBehind };
