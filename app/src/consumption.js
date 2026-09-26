// Consumption intelligence. who took this package, version, file or advisory, from where, and when.
// Author: Tim Rice
// every served download is folded into one row per version per consumer, kept far longer than the raw
// traffic log. months later "is the bad one in production?" is one lookup, not a log dig

const db = require('./db');
const log = require('./logger');
const ecosystems = require('./ecosystems');

const MAX_TARGETS = 500;
const MAX_ROWS = 5000;

// the columns that make two downloads "the same consumer". hashed, so the unique key stays small
const KEY_SQL = "SHA2(CONCAT_WS(CHAR(0), ?, ?, ?, IFNULL(?, ''), IFNULL(?, ''), IFNULL(?, ''), IFNULL(?, ''), IFNULL(?, ''), IFNULL(?, '')), 256)";

// called for every download that was actually served. fire and forget, like the traffic log
function note(row, ci) {
  if (!row || !row.pulled_exact || !row.package_name || !row.pulled_version) return;
  if (!['allow', 'audit'].includes(row.action) || Number(row.status) >= 400) return;
  const key = [row.ecosystem, row.package_name, String(row.pulled_version).slice(0, 128), row.user_id, row.token_name, row.application, row.environment, ci, row.ip];
  db.query(
    `INSERT INTO consumption (fingerprint, ecosystem, package_name, version, user_id, token_name, application, environment, ci, ip, first_seen, last_seen, downloads)
     VALUES (${KEY_SQL}, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1)
     ON DUPLICATE KEY UPDATE last_seen = NOW(), downloads = downloads + 1`,
    [...key, ...key]
  ).catch((err) => log.error('consumption write failed', err.message));
}

// one time, from whatever the traffic log still holds
async function backfill() {
  const done = await db.query(
    `INSERT IGNORE INTO consumption (fingerprint, ecosystem, package_name, version, user_id, token_name, application, environment, ci, ip, first_seen, last_seen, downloads)
     SELECT SHA2(CONCAT_WS(CHAR(0), ecosystem, package_name, LEFT(pulled_version, 128), IFNULL(user_id, ''), IFNULL(token_name, ''), IFNULL(application, ''),
                           IFNULL(environment, ''), IFNULL(ci, ''), IFNULL(ip, '')), 256),
            ecosystem, package_name, LEFT(pulled_version, 128), user_id, token_name, application, environment, ci, ip, MIN(ts), MAX(ts), COUNT(*)
       FROM access_log
      WHERE pulled_exact = 1 AND action IN ('allow', 'audit') AND status < 400 AND package_name IS NOT NULL AND pulled_version IS NOT NULL
      GROUP BY ecosystem, package_name, LEFT(pulled_version, 128), user_id, token_name, application, environment, ci, ip`
  );
  return done.affectedRows;
}

// ---------------------------------------------------------------- what was asked

const HASH = /^[a-f0-9]{64}$/i;
// CVE, GitHub, PyPI and OSV ids. anything else is a package name
const ADVISORY = /^(CVE-\d{4}-\d{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d{1,7}|OSV-\d{4}-\d{1,7})$/i;

function classify(q) {
  const text = String(q || '').trim();
  if (!text) return null;
  if (HASH.test(text)) return { kind: 'hash', sha256: text.toLowerCase() };
  if (ADVISORY.test(text)) return { kind: 'advisory', advisory: text.toUpperCase() };
  return { kind: 'package', name: text };
}

// versions the question points at
async function targets(query) {
  if (query.kind === 'hash') {
    return db.query(
      'SELECT ecosystem, package_name, version, filename FROM artifacts WHERE sha256 = ? ORDER BY ecosystem, package_name, version LIMIT ?',
      [query.sha256, MAX_TARGETS]
    );
  }
  if (query.kind === 'advisory') {
    // ids are kept comma separated, spaces or not
    return db.query(
      `SELECT ecosystem, package_name, version, severity, cves, advisories FROM cve_findings
        WHERE FIND_IN_SET(?, REPLACE(UPPER(cves), ' ', '')) OR FIND_IN_SET(?, REPLACE(UPPER(advisories), ' ', ''))
        ORDER BY ecosystem, package_name, version LIMIT ?`,
      [query.advisory, query.advisory, MAX_TARGETS]
    );
  }
  // a package, maybe narrowed to a version or a range. judged against what was actually consumed
  const seen = await db.query(
    'SELECT DISTINCT ecosystem, package_name, version FROM consumption WHERE ecosystem = ? AND package_name = ? LIMIT 5000',
    [query.ecosystem, query.name]
  );
  if (!query.version) return seen.slice(0, MAX_TARGETS);
  const adapter = ecosystems.adapter(query.ecosystem);
  return seen.filter((r) => {
    if (r.version === query.version) return true;
    try {
      return adapter.satisfies(r.version, query.version);
    } catch (err) {
      return false;
    }
  }).slice(0, MAX_TARGETS);
}

async function find(query) {
  const found = await targets(query);
  const oldest = await db.one('SELECT MIN(first_seen) AS since FROM consumption');
  const out = {
    query, since: oldest ? oldest.since : null, targets: found, consumers: [], applications: [], truncated: false,
    summary: { versions: 0, applications: 0, environments: 0, productionApplications: 0, users: 0, pipelines: 0, addresses: 0, downloads: 0, lastDownload: null }
  };
  if (!found.length) return out;

  const keys = [...new Map(found.map((t) => [`${t.ecosystem}\n${t.package_name}\n${t.version}`, t])).values()];
  const rows = await db.query(
    `SELECT c.ecosystem, c.package_name, c.version, c.application, c.environment, c.token_name, c.ci, c.ip, c.downloads,
            c.first_seen, c.last_seen, u.username, IFNULL(e.production, 0) AS production
       FROM consumption c
       LEFT JOIN users u ON u.id = c.user_id
       LEFT JOIN environments e ON e.name = c.environment
      WHERE (c.ecosystem, c.package_name, c.version) IN (${keys.map(() => '(?, ?, ?)').join(',')})
      ORDER BY c.last_seen DESC LIMIT ${MAX_ROWS + 1}`,
    keys.flatMap((t) => [t.ecosystem, t.package_name, t.version])
  );
  out.truncated = rows.length > MAX_ROWS;
  if (out.truncated) rows.length = MAX_ROWS;

  const apps = new Map();
  const count = { versions: new Set(), envs: new Set(), users: new Set(), pipes: new Set(), ips: new Set() };
  for (const r of rows) {
    const production = !!Number(r.production);
    out.consumers.push({
      ecosystem: r.ecosystem, name: r.package_name, version: r.version, application: r.application, environment: r.environment,
      production, token: r.token_name, user: r.username, ci: r.ci, ip: r.ip, downloads: Number(r.downloads),
      firstSeen: r.first_seen, lastSeen: r.last_seen
    });
    const ak = `${r.application || ''}\n${r.environment || ''}`;
    const a = apps.get(ak) || { application: r.application, environment: r.environment, production, versions: new Set(), downloads: 0, lastSeen: r.last_seen };
    a.versions.add(`${r.package_name} ${r.version}`);
    a.downloads += Number(r.downloads);
    if (String(r.last_seen) > String(a.lastSeen)) a.lastSeen = r.last_seen;
    apps.set(ak, a);

    count.versions.add(`${r.ecosystem}\n${r.package_name}\n${r.version}`);
    if (r.environment) count.envs.add(r.environment);
    // one CI token pulling npm and pip is still one pipeline
    if (r.ci) count.pipes.add(r.token_name ? `token\n${r.token_name}` : `ci\n${r.ci}\n${r.ip || ''}`);
    else if (r.username) count.users.add(r.username);
    if (r.ip) count.ips.add(r.ip);
    out.summary.downloads += Number(r.downloads);
    if (!out.summary.lastDownload || String(r.last_seen) > String(out.summary.lastDownload)) out.summary.lastDownload = r.last_seen;
  }
  out.applications = [...apps.values()]
    .map((a) => ({ ...a, versions: [...a.versions].sort() }))
    .sort((x, y) => String(y.lastSeen).localeCompare(String(x.lastSeen)));
  const named = out.applications.filter((a) => a.application);
  out.summary.versions = count.versions.size;
  out.summary.applications = new Set(named.map((a) => a.application)).size;
  out.summary.productionApplications = new Set(named.filter((a) => a.production).map((a) => a.application)).size;
  out.summary.environments = count.envs.size;
  out.summary.users = count.users.size;
  out.summary.pipelines = count.pipes.size;
  out.summary.addresses = count.ips.size;
  return out;
}

function retentionDays() {
  const n = parseInt(db.settings.get('consumption_retention_days'), 10);
  return Number.isInteger(n) && n >= 0 ? Math.min(n, 3650) : 365;
}

// 0 keeps it forever. a consumer that pulled again recently is kept, only the untouched ones go
async function sweep() {
  const days = retentionDays();
  if (!days) return 0;
  const gone = await db.query('DELETE FROM consumption WHERE last_seen < DATE_SUB(NOW(), INTERVAL ? DAY)', [days]);
  return gone.affectedRows;
}

module.exports = { note, backfill, classify, targets, find, sweep, retentionDays, MAX_ROWS };
