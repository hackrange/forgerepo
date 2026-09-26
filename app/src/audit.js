// npm audit answers (bulk for npm 7+, quick for npm 6) out of cve_findings, plus the vuln download log.
// Author: Tim Rice
// never fails a build, blocking is what rules are for. and empty != clean, a
// version pulled for the first time can be ahead of its scan

const semver = require('semver');
const db = require('./db');

// unrated lands on info, so it won't trip --audit-level=low
const NPM_SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'moderate', LOW: 'low' };

//caps on untrusted payloads
const MAX_PACKAGES = 5000;
const MAX_VERSIONS = 50;
const MAX_DEPTH = 20;
const CHUNK = 400;

function npmSeverity(raw) {
  return NPM_SEVERITY[String(raw || '').toUpperCase()] || 'info';
}

function splitList(text) {
  return String(text || '').split(',').map((s) => s.trim()).filter(Boolean);
}

// cut between entries not through one, half a CVE id is a CVE that doesn't exist
function joinWithin(items, max, sep = ', ') {
  const list = (items || []).filter(Boolean);
  const all = list.join(sep);
  if (all.length <= max) return all;
  for (let kept = list.length - 1; kept >= 0; kept -= 1) {
    const head = list.slice(0, kept).join(sep);
    const tail = `${kept ? ' ' : ''}and ${list.length - kept} more`;
    if (head.length + tail.length <= max) return head + tail;
  }
  return '';
}

// npm wants a numeric id. 48 bit hash, collisions aren't a real worry
function numericId(text) {
  let a = 2166136261;
  let b = 0x9e3779b9;
  for (let i = 0; i < text.length; i += 1) {
    a = Math.imul(a ^ text.charCodeAt(i), 16777619) >>> 0;
    b = Math.imul(b ^ text.charCodeAt(i), 2654435761) >>> 0;
  }
  return (a % 16777216) * 16777216 + (b % 16777216);
}

function advisoryUrl(id) {
  return /^GHSA-/i.test(id) ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${id}`;
}

// ---------------------------------------------------------------- the request

// both payload shapes, capped on the way in
function collect(body) {
  const out = new Map();

  function add(name, version) {
    if (typeof name !== 'string' || !name) return;
    if (typeof version !== 'string' || !semver.valid(version)) return;
    if (!out.has(name)) {
      if (out.size >= MAX_PACKAGES) return;
      out.set(name, new Set());
    }
    const versions = out.get(name);
    if (versions.size < MAX_VERSIONS) versions.add(version);
  }

  function walk(deps, depth) {
    if (!deps || typeof deps !== 'object' || depth > MAX_DEPTH) return;
    for (const [name, meta] of Object.entries(deps)) {
      if (!meta || typeof meta !== 'object') continue;
      add(name, meta.version);
      walk(meta.dependencies, depth + 1);
    }
  }

  if (!body || typeof body !== 'object') return out;
  for (const [name, value] of Object.entries(body)) {
    if (Array.isArray(value)) value.forEach((v) => add(name, String(v)));
  }
  walk(body.dependencies, 0);
  return out;
}

function versionCount(wanted) {
  let n = 0;
  for (const versions of wanted.values()) n += versions.size;
  return n;
}

// ---------------------------------------------------------------- the answer

async function findingsFor(wanted) {
  const pairs = [];
  for (const [name, versions] of wanted) for (const version of versions) pairs.push([name, version]);
  if (!pairs.length) return [];

  const rows = [];
  for (let i = 0; i < pairs.length; i += CHUNK) {
    const chunk = pairs.slice(i, i + CHUNK);
    const marks = chunk.map(() => '(?,?)').join(',');
    const found = await db.query(
      // npm findings only
      `SELECT package_name, version, advisories, cves, severity, summary, fixed_in
         FROM cve_findings WHERE ecosystem = 'npm' AND (package_name, version) IN (${marks})`,
      chunk.flat()
    );
    rows.push(...found);
  }
  return rows;
}

async function advisoryText(ids) {
  const out = new Map();
  for (let i = 0; i < ids.length; i += CHUNK) {
    const chunk = ids.slice(i, i + CHUNK);
    const rows = await db.query(
      `SELECT id, cves, severity, summary FROM cve_advisories WHERE id IN (${chunk.map(() => '?').join(',')})`,
      chunk
    );
    for (const row of rows) out.set(row.id, row);
  }
  return out;
}

// one entry per advisory per package, npm dedupes on the advisory
async function entriesFor(wanted) {
  const findings = await findingsFor(wanted);
  if (!findings.length) return [];

  const ids = [...new Set(findings.flatMap((f) => splitList(f.advisories)))];
  const text = await advisoryText(ids);

  const entries = new Map();
  for (const finding of findings) {
    const advisories = splitList(finding.advisories);
    for (const id of advisories.length ? advisories : [`finding-${finding.package_name}@${finding.version}`]) {
      const detail = text.get(id) || {};
      const key = `${finding.package_name}\n${id}`;
      let entry = entries.get(key);
      if (!entry) {
        entry = {
          package: finding.package_name,
          id,
          severity: npmSeverity(detail.severity || finding.severity),
          title: detail.summary || finding.summary || 'a known advisory covers this version',
          cves: splitList(detail.cves || finding.cves),
          fixed: finding.fixed_in || null,
          versions: []
        };
        entries.set(key, entry);
      }
      if (!entry.versions.includes(finding.version)) entry.versions.push(finding.version);
      if (!entry.fixed && finding.fixed_in) entry.fixed = finding.fixed_in;
    }
  }
  return [...entries.values()];
}

function bulkBody(entries) {
  const out = {};
  for (const entry of entries) {
    if (!out[entry.package]) out[entry.package] = [];
    out[entry.package].push({
      id: numericId(entry.id),
      url: advisoryUrl(entry.id),
      title: entry.title,
      severity: entry.severity,
      vulnerable_versions: entry.versions.join(' || '),
      cwe: [],
      cvss: { score: 0, vectorString: null }
    });
  }
  return out;
}

// npm 6. going quiet here would look like a clean bill of health
function quickBody(entries, wanted) {
  const advisories = {};
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };

  for (const entry of entries) {
    const id = numericId(entry.id);
    counts[entry.severity] += 1;
    advisories[id] = {
      id,
      module_name: entry.package,
      severity: entry.severity,
      title: entry.title,
      overview: entry.title,
      url: advisoryUrl(entry.id),
      cves: entry.cves,
      vulnerable_versions: entry.versions.join(' || '),
      patched_versions: entry.fixed ? `>=${entry.fixed}` : '<0.0.0',
      recommendation: entry.fixed
        ? `Upgrade to ${entry.fixed} or later`
        : 'No patched version has been published yet',
      access: 'public',
      cwe: '',
      findings: entry.versions.map((version) => ({ version, paths: [entry.package] })),
      metadata: { module_type: '', exploitability: 0, affected_components: '' },
      references: ''
    };
  }

  const total = versionCount(wanted);
  return {
    actions: [],
    advisories,
    muted: [],
    metadata: {
      vulnerabilities: counts,
      dependencies: total,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: total
    }
  };
}

// ---------------------------------------------------------------- one version

// no ecosystem = npm, like every caller from before PyPI
function findingFor(name, version, ecosystem = 'npm') {
  return db.one(
    `SELECT ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in
       FROM cve_findings WHERE ecosystem = ? AND package_name = ? AND version = ?`,
    [ecosystem, name, version]
  );
}

async function findingsForPackage(name, ecosystem = 'npm') {
  const rows = await db.query(
    `SELECT ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in
       FROM cve_findings WHERE ecosystem = ? AND package_name = ?`,
    [ecosystem, name]
  );
  const out = new Map();
  for (const row of rows) out.set(row.version, row);
  return out;
}

// short enough that npm prints all of it
function warningLine(finding) {
  const n = splitList(finding.advisories).length || 1;
  const sev = npmSeverity(finding.severity);
  const cves = finding.cves ? ` (${finding.cves})` : '';
  const fix = finding.fixed_in ? `. Fixed in ${finding.fixed_in}` : '. No fixed version is published yet';
  const spelled = finding.ecosystem && finding.ecosystem !== 'npm'
    ? `${finding.package_name}==${finding.version}`
    : `${finding.package_name}@${finding.version}`;
  return `${spelled} has ${n} known ${n === 1 ? 'advisory' : 'advisories'}`
    + ` against it, worst is ${sev}${cves}${fix}`;
}

// keeps what was wrong at the time, so "who pulled that?" survives the finding
// being cleared. future you will receive this gladly
function noteDownload(finding, who) {
  return db.query(
    `INSERT INTO vuln_downloads
       (ecosystem, package_name, version, severity, advisories, cves, ip, user_id, token_name,
        application, environment, cache_hit)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      finding.ecosystem || 'npm',
      finding.package_name,
      finding.version,
      finding.severity || 'unrated',
      joinWithin(splitList(finding.advisories), 512, ','),
      joinWithin(splitList(finding.cves), 512),
      who.ip || null,
      who.userId || null,
      who.tokenName || null,
      who.application || null,
      who.environment || null,
      who.cacheHit ? 1 : 0
    ]
  );
}

module.exports = {
  collect,
  versionCount,
  entriesFor,
  bulkBody,
  quickBody,
  findingFor,
  findingsForPackage,
  warningLine,
  noteDownload,
  npmSeverity,
  joinWithin
};
