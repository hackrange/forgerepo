// Dependency intelligence: what a package drags in behind it, and what this box knows about each one.
// Author: Tim Rice
// a walk, not an install: the newest version each range allows, through the same cache and routing as everything else.
// nothing here approves anything unless an admin switched that on, and then never a blocked or vulnerable one

const db = require('../db');
const policy = require('../policy');
const killswitch = require('../policy/killswitch');
const quarantine = require('../policy/quarantine');
const cvescan = require('../cvescan');
const npmUpstream = require('../registry/npm/upstream');
const pypitree = require('../registry/pypi/tree');
const rules = require('../db/repositories/rules');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const repo = require('../db/repositories/dependencies');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const MAX_NODES = 1500;
const BATCH = 300;
// approving along with one request never writes more rules than this
const MAX_APPROVE = 500;
const LICENSE_RANK = { blocked: 3, review: 2, allowed: 1 };

const key = (eco, name, version) => `${eco}\n${name}\n${version}`;

function walk(type, name, range, { depth = 12, dev = false } = {}) {
  return type.id === 'pypi'
    ? pypitree.resolveTree(name, range, { depth, max: MAX_NODES })
    : npmUpstream.resolveTree(name, range, { depth, dev, max: MAX_NODES });
}

// findings, holds and cached files for every name in the tree, a few queries instead of one per package
async function evidence(type, packages) {
  const pairs = [...new Set(packages.map((p) => p.name))].map((n) => [type.id, n]);
  const findings = new Map();
  const holds = new Map();
  const files = new Map();
  for (let i = 0; i < pairs.length; i += BATCH) {
    const batch = pairs.slice(i, i + BATCH);
    const [found, held, cached] = await Promise.all([
      vulnerabilities.findingsForPackages(batch), repo.holdsFor(batch), repo.artifactsFor(batch)
    ]);
    for (const r of found) findings.set(key(r.ecosystem, r.package_name, r.version), r);
    for (const r of held) {
      const k = key(r.ecosystem, r.package_name, r.version);
      if (holds.get(k) !== 'rejected') holds.set(k, r.status);
    }
    // worst license verdict across the files of a version, '' = cached but not judged
    for (const r of cached) {
      const k = key(r.ecosystem, r.package_name, r.version);
      const was = files.has(k) ? files.get(k) : '';
      files.set(k, (LICENSE_RANK[r.license_verdict] || 0) > (LICENSE_RANK[was] || 0) ? r.license_verdict : was);
    }
  }
  return { findings, holds, files };
}

// most serious first
function statusOf(n) {
  if (n.blocked) return 'blocked';
  if (n.vulnerable) return 'vulnerable';
  if (n.unapproved) return 'unapproved';
  if (n.unknown) return 'unknown';
  return 'clean';
}

async function judge(type, packages, scope) {
  const { findings, holds, files } = await evidence(type, packages);
  const strict = quarantine.mode() === 'strict';
  const out = [];
  for (const p of packages) {
    const k = key(type.id, p.name, p.version);
    const verdict = await policy.checkVersion(p.name, p.version, type.adapter, scope);
    const dead = await killswitch.check(type.id, p.name, p.version);
    const finding = findings.get(k) || null;
    const hold = holds.get(k) || null;
    const license = files.has(k) ? files.get(k) || null : null;
    const why = [];
    if (dead) why.push(dead.reason);
    if (!verdict.allowed) why.push(verdict.reason);
    if (hold === 'rejected') why.push('rejected in quarantine');
    else if (hold) why.push(strict ? 'held in quarantine' : 'held in quarantine, still served in permissive mode');
    if (license === 'blocked') why.push('its license is on the blocked list');
    if (finding) why.push(`${String(finding.severity || 'unrated').toLowerCase()} advisory ${String(finding.advisories || '').split(',')[0]}`.trim());
    const node = {
      ...p,
      allowed: verdict.allowed,
      reason: verdict.reason,
      // deny rule vs nobody approved it yet. pages have to tell them apart
      denied: !!(verdict.rule && verdict.rule.kind === 'deny'),
      killed: !!dead,
      held: hold,
      license,
      severity: finding ? finding.severity : null,
      advisories: finding ? finding.advisories : null,
      blocked: !verdict.allowed || !!dead || hold === 'rejected' || (hold === 'open' && strict) || license === 'blocked',
      // blocked by something other than whitelist mode waiting for a yes. approving can never lift these
      stopped: (!verdict.allowed && !!verdict.rule) || !!dead || hold === 'rejected' || (hold === 'open' && strict) || license === 'blocked',
      vulnerable: !!finding,
      // no allow rule speaks for it. blacklist mode serves it anyway, whitelist mode blocks it
      unapproved: !(verdict.rule && verdict.rule.kind === 'allow'),
      // never cached here, so no scan, license or integrity evidence exists for it yet
      unknown: !files.has(k),
      why
    };
    node.status = statusOf(node);
    out.push(node);
  }
  return out;
}

// what approving along with a request may take: not approved yet, and nothing at all against it.
// whitelist mode blocks every unapproved package, that block is the one approving is for
const approvable = (n) => n.depth > 0 && n.unapproved && !n.stopped && !n.vulnerable && !n.held && !n.killed && !n.denied;

function summarize(nodes) {
  const deps = nodes.filter((n) => n.depth > 0);
  const count = (fn) => deps.filter(fn).length;
  return {
    total: deps.length,
    direct: count((n) => n.depth === 1),
    transitive: count((n) => n.depth > 1),
    blocked: count((n) => n.blocked),
    vulnerable: count((n) => n.vulnerable),
    unapproved: count((n) => n.unapproved),
    unknown: count((n) => n.unknown),
    clean: count((n) => n.status === 'clean'),
    approvable: count(approvable)
  };
}

async function analyze(type, name, range, { depth, dev, scope } = {}) {
  if (type.walks === false) fail(400, 'an image has no dependency tree to walk. what is inside it is scanned when it is pulled');
  const tree = await walk(type, name, range, { depth, dev });
  const packages = await judge(type, tree.packages, scope || null);
  return { packages, problems: tree.problems, truncated: tree.truncated, summary: summarize(packages) };
}

// the range a request walks from. a bare PyPI version is a pin, the same as the Requests page treats it
function requestRange(row) {
  const r = String(row.version_range || '').trim();
  if (!r) return 'latest';
  if ((row.ecosystem || 'npm') === 'pypi' && !/[<>=!~,|]/.test(r)) return `==${r}`;
  return r;
}

async function forRequest(type, row) {
  const range = requestRange(row);
  const result = await analyze(type, row.package_name, range);
  return {
    ecosystem: type.id,
    root: type.id === 'pypi' ? `${row.package_name}${range === 'latest' ? '' : ` ${range}`}` : `${row.package_name}@${range}`,
    summary: result.summary,
    truncated: result.truncated,
    problems: result.problems.slice(0, 50),
    // the clean ones are only counted, the page is about what needs a look
    packages: result.packages.filter((n) => n.depth > 0 && n.status !== 'clean').slice(0, 500)
  };
}

function enabled() {
  return db.settings.getBool('approve_clean_dependencies');
}

// after a request is approved: pinned allow rules for its clean dependencies, each put to the advisory feed first.
// a feed that can't answer about all of them means none get approved, an unanswered question is not a clean answer
async function approveForRequest(actor, type, row) {
  if (!enabled()) fail(400, 'approving dependencies along with a request is switched off in Settings');
  const { packages, truncated } = await analyze(type, row.package_name, requestRange(row));
  const seen = new Set();
  const wanted = [];
  for (const n of packages) {
    if (!approvable(n) || !type.validVersion(n.version)) continue;
    const k = key(type.id, n.name, n.version);
    if (seen.has(k)) continue;
    seen.add(k);
    wanted.push(n);
  }
  const leftOut = packages.filter((n) => n.depth > 0 && !approvable(n)).length;
  const base = { approved: 0, names: [], leftOut, truncated };
  if (!wanted.length) return { ...base, note: 'nothing in the tree was left to approve' };
  if (wanted.length > MAX_APPROVE) {
    return { ...base, note: `the tree has ${wanted.length} dependencies to approve, more than ${MAX_APPROVE} at once, so none were. Use the tree walk on Check a package` };
  }

  const answer = await cvescan.scanPairs(wanted.map((n) => ({ ecosystem: type.id, name: n.name, version: n.version })), { max: MAX_APPROVE });
  // incomplete = the feed found something it then could not describe, which must not read as clean
  if (answer.asked < answer.checked || answer.incomplete) {
    return { ...base, note: 'the advisory feed could not be asked about all of them, so none were approved' };
  }
  const clean = wanted.filter((n) => !answer.found.has(cvescan._internal.findingKey(type.id, n.name, n.version)));
  const note = `clean dependency of ${type.spell(row.package_name, row.version_range || 'latest')}, approved with request #${row.id}`.slice(0, 512);
  await db.transaction(async (q) => {
    for (const n of clean) {
      await rules.upsert(
        { ecosystem: type.id, pattern: n.name, kind: 'allow', version_range: n.version, note, created_by: actor.name },
        { note: 'values', enabled: 1 },
        q
      );
    }
  });
  policy.invalidate();
  const names = clean.map((n) => type.spell(n.name, n.version));
  await audit(actor, 'request.approve.dependencies', row.package_name, `${names.length} clean dependencies: ${names.slice(0, 50).join(', ')}`.slice(0, 4000));
  const flagged = wanted.length - clean.length;
  return {
    approved: clean.length,
    names: names.slice(0, 100),
    leftOut: leftOut + flagged,
    truncated,
    note: flagged ? `${flagged} had an advisory once the feed was asked, and were left out` : null
  };
}

module.exports = { MAX_APPROVE, walk, judge, summarize, analyze, requestRange, forRequest, enabled, approveForRequest, statusOf };
