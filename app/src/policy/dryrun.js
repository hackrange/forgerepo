// Policy dry run. "what would this break" before anyone switches it on.
// Author: Tim Rice
// replays recent downloads from the traffic log against a proposed rule, vulnerability threshold or
// license lists, and counts who would have been refused. reads only, nothing is saved or enforced

const policy = require('./index');
const ecosystems = require('../ecosystems');
const resolution = require('./resolution');
const waivers = require('./waivers');
const license = require('./licenses');
const spdx = require('./licenses/spdx');
const accessLog = require('../db/repositories/access-log');
const labels = require('../db/repositories/labels');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const artifactsRepo = require('../db/repositories/artifacts');

const KINDS = ['rule', 'severity', 'license'];
const MAX_ROWS = 200000;
const LIST_LIMIT = 200;

// downloads that named a version. metadata answers only guess one, a dry run shouldn't.
// refused downloads never got a file, so they're told apart by the path they asked for
async function traffic(days, action) {
  return accessLog.replayRows(days, action, MAX_ROWS + 1);
}

// the log keeps names, rules keep ids. a renamed application just stops matching, which is honest
async function scopeIds() {
  const [apps, envs] = await Promise.all([
    labels.names('applications'),
    labels.names('environments')
  ]);
  const a = new Map(apps.map((r) => [r.name, Number(r.id)]));
  const e = new Map(envs.map((r) => [r.name, Number(r.id)]));
  const prod = new Set(envs.filter((r) => Number(r.production)).map((r) => r.name));
  const of = (row) => ({ app: a.get(row.application) || 0, env: e.get(row.environment) || 0 });
  // whatever the checkbox says today
  of.production = (name) => prod.has(name);
  return of;
}

// ---------------------------------------------------------------- the judges

function ruleJudge(proposal) {
  const rule = policy.proposedRule(proposal);
  return async (row, scope, adapter) => {
    const now = await policy.checkVersion(row.package_name, row.version, adapter, scope);
    const then = await policy.checkVersionWith(rule, row.package_name, row.version, adapter, scope);
    if (proposal.kind === 'deny') return now.allowed && !then.allowed && then.rule === rule ? then.reason : null;
    return !now.allowed && then.allowed && then.rule === rule ? then.reason : null;
  };
}

async function severityJudge(proposal, rows) {
  const names = [...new Set(rows.map((r) => `${r.ecosystem}\n${r.package_name}`))];
  const findings = new Map();
  for (let i = 0; i < names.length; i += 500) {
    const part = names.slice(i, i + 500).map((k) => k.split('\n'));
    const found = await vulnerabilities.findingsForPackages(part);
    for (const f of found) findings.set(`${f.ecosystem}\n${f.package_name}\n${f.version}`, f);
  }
  const bar = resolution.rank(proposal.severity);
  return async (row, scope) => {
    const f = findings.get(`${row.ecosystem}\n${row.package_name}\n${row.version}`);
    if (!f || resolution.rank(f.severity) < 0 || resolution.rank(f.severity) < bar) return null;
    if (await waivers.advisoryWaived(row.ecosystem, row.package_name, row.version, f, scope)) return null;
    return `${String(f.severity).toLowerCase()} advisory${f.cves ? ` (${f.cves})` : ''}`;
  };
}

async function licenseJudge(proposal) {
  const current = license.lists();
  const lists = spdx.compile({
    allowed: proposal.allowed, review: proposal.review, blocked: proposal.blocked,
    unlisted: proposal.unlisted, unknown: proposal.unknown
  });
  const stored = new Map();
  return async (row) => {
    const key = `${row.ecosystem}\n${row.package_name}\n${row.version}`;
    if (!stored.has(key)) {
      stored.set(key, await artifactsRepo.storedLicense(row.ecosystem, row.package_name, row.version));
    }
    const art = stored.get(key);
    // never read, so nothing honest to say about it
    if (!art) return null;
    const got = license.fromStored(art);
    const then = spdx.evaluate(got, lists);
    if (then.verdict === 'allowed') return null;
    // already held today is not something this change breaks
    if (spdx.evaluate(got, current).verdict !== 'allowed') return null;
    if (await waivers.licenseWaived(row.ecosystem, row.package_name, row.version, then.expression)) return null;
    return `license ${then.expression || 'unknown'} would be ${then.verdict}`;
  };
}

// ---------------------------------------------------------------- the count

async function simulate(proposal, days) {
  const lettingThrough = proposal.type === 'rule' && proposal.kind === 'allow';
  const rows = await traffic(days, lettingThrough ? 'deny' : 'allow');
  const truncated = rows.length > MAX_ROWS;
  if (truncated) rows.length = MAX_ROWS;

  let judge;
  if (proposal.type === 'rule') judge = ruleJudge(proposal);
  else if (proposal.type === 'severity') judge = await severityJudge(proposal, rows);
  else judge = await licenseJudge(proposal);

  const scopeOf = await scopeIds();
  const verdicts = new Map();
  const packages = new Map();
  const apps = new Map();
  const people = new Map();
  const pipelines = new Map();
  let downloads = 0;
  let unattributed = 0;

  for (const row of rows) {
    const adapter = ecosystems.adapter(row.ecosystem);
    if (!adapter) continue;
    const scope = scopeOf(row);
    const key = [row.ecosystem, row.package_name, row.version, scope.app, scope.env].join('\n');
    if (!verdicts.has(key)) verdicts.set(key, await judge(row, scope, adapter));
    const why = verdicts.get(key);
    if (!why) continue;

    downloads += 1;
    const pk = `${row.ecosystem}\n${row.package_name}`;
    const p = packages.get(pk) || { ecosystem: row.ecosystem, name: row.package_name, versions: new Map(), downloads: 0, applications: new Set() };
    p.downloads += 1;
    p.versions.set(row.version, why);
    if (row.application) p.applications.add(row.application);
    packages.set(pk, p);

    if (row.application) {
      const a = apps.get(row.application) || { name: row.application, environments: new Set(), downloads: 0, production: false };
      a.downloads += 1;
      if (row.environment) a.environments.add(row.environment);
      if (scopeOf.production(row.environment)) a.production = true;
      apps.set(row.application, a);
    }
    if (row.ci) {
      const pkey = [row.ci, row.token_name, row.application].join('\n');
      const c = pipelines.get(pkey) || { ci: row.ci, token: row.token_name, application: row.application, downloads: 0 };
      c.downloads += 1;
      pipelines.set(pkey, c);
    } else if (row.username) {
      const d = people.get(row.username) || { username: row.username, downloads: 0 };
      d.downloads += 1;
      people.set(row.username, d);
    }
    if (!row.token_name) unattributed += 1;
  }

  const byDownloads = (a, b) => b.downloads - a.downloads;
  const pkgList = [...packages.values()].sort(byDownloads).map((p) => ({
    ecosystem: p.ecosystem, name: p.name, downloads: p.downloads, applications: [...p.applications].sort(),
    versions: [...p.versions.entries()].map(([version, reason]) => ({ version, reason }))
  }));
  const appList = [...apps.values()].sort(byDownloads).map((a) => ({ ...a, environments: [...a.environments].sort() }));
  return {
    type: proposal.type,
    direction: lettingThrough ? 'allow' : 'block',
    days,
    scanned: rows.length,
    truncated,
    summary: {
      packages: packages.size,
      versions: pkgList.reduce((n, p) => n + p.versions.length, 0),
      applications: apps.size,
      productionApplications: appList.filter((a) => a.production).length,
      developers: people.size,
      pipelines: pipelines.size,
      downloads,
      unattributed
    },
    packages: pkgList.slice(0, LIST_LIMIT),
    applications: appList.slice(0, LIST_LIMIT),
    developers: [...people.values()].sort(byDownloads).slice(0, LIST_LIMIT),
    pipelines: [...pipelines.values()].sort(byDownloads).slice(0, LIST_LIMIT)
  };
}

// npm says ci/github-actions in its user agent, pip puts "ci":true in its json one
function ciOf(userAgent) {
  const ua = String(userAgent || '').slice(0, 1024);
  const named = /(?:^|\s)ci\/([a-z0-9][a-z0-9._-]{0,31})(?:\s|$)/i.exec(ua);
  if (named && named[1].toLowerCase() !== 'false') return named[1].toLowerCase();
  if (/"ci"\s*:\s*true/.test(ua)) return 'ci';
  return null;
}

module.exports = { KINDS, simulate, ciOf, MAX_ROWS };
