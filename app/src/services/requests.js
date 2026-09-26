// Approval requests: asking, the advisory preview, and deciding. decisions claim the row first,
// so two approvers clicking at once can't both win.
// Author: Tim Rice

const semver = require('semver');
const db = require('../db');
const auth = require('../security/auth');
const policy = require('../policy');
const upstream = require('../registry/npm/upstream');
const cvescan = require('../cvescan');
const ecosystems = require('../ecosystems');
const pypiVersion = require('../ecosystems/pypi/version');
const pypiupstream = require('../registry/pypi/upstream');
const log = require('../logger');
const requests = require('../db/repositories/requests');
const rules = require('../db/repositories/rules');
const { checkRange } = require('../policy/rulecheck');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

// ---------------------------------------------------------------- reading

function list(filters, paging) {
  return requests.page(filters, paging);
}

// not yours = 404, so no IDOR id-poking
async function load(id, ownerId) {
  const row = await requests.byId(id, ownerId);
  if (!row) fail(404, 'no such request');
  return row;
}

// ---------------------------------------------------------------- what's wrong with the thing they asked for
// approver wants advisories *before* saying yes. versions come from package metadata,
// and none of it lands on the vulns list (not something we'd serve yet)

// newest N versions. answer says how many, so a sample doesn't pass as the whole list
const REQUEST_VERSIONS = 10;

// cache per package for a few minutes, osv doesn't need a trip per page view
const VULN_TTL_MS = 5 * 60000;
const VULN_CACHE_MAX = 500;
const vulnCache = new Map();

// evict expired ones, or the oldest if all fresh
function holdAnswer(key, value, now) {
  vulnCache.set(key, { at: now, value });
  if (vulnCache.size <= VULN_CACHE_MAX) return;
  for (const [held, entry] of vulnCache) {
    if (vulnCache.size <= VULN_CACHE_MAX) break;
    if (now - entry.at >= VULN_TTL_MS || vulnCache.size > VULN_CACHE_MAX) vulnCache.delete(held);
  }
}

const SEVERITY_ORDER = ['critical', 'high', 'moderate', 'low', 'info', 'unrated'];

function worstOf(list) {
  let worst = null;
  for (const f of list) {
    const rank = SEVERITY_ORDER.indexOf(String(f.severity || '').toLowerCase());
    const held = worst === null ? 99 : SEVERITY_ORDER.indexOf(String(worst).toLowerCase());
    if (rank >= 0 && rank < held) worst = String(f.severity).toLowerCase();
  }
  return worst;
}

// newest first, inside the requested range if there is one
async function versionsToCheck(name, range, ecosystem) {
  const kind = require('../registry/kinds').get(ecosystem);
  if (kind) {
    const listed = await kind.versions(name);
    const all = listed.versions.map((v) => v.version);
    if (!all.length) throw new Error('that package has no versions published');
    const matching = range ? all.filter((v) => kind.version.satisfies(v, range, { prereleases: true })) : all;
    return { matched: matching.length, versions: matching.slice().sort((a, b) => kind.version.compare(b, a)).slice(0, REQUEST_VERSIONS), name: listed.id };
  }
  if (ecosystem === 'pypi') {
    // PyPI ranges are specifier sets, read like the rules read them
    const { doc } = await pypiupstream.getJson(name);
    const all = Object.keys(doc.releases || {}).filter((v) => pypiVersion.valid(v));
    if (!all.length) throw new Error('that project has no releases published');
    const adapter = ecosystems.adapter('pypi');
    const matching = range ? all.filter((v) => adapter.satisfies(v, range)) : all;
    if (!matching.length) return { matched: 0, versions: [] };
    const newestFirst = matching.slice().sort((a, b) => pypiVersion.compare(b, a));
    return { matched: matching.length, versions: newestFirst.slice(0, REQUEST_VERSIONS) };
  }
  const { doc } = await upstream.getPackument(name, 'abbreviated');
  const all = Object.keys(doc.versions || {}).filter((v) => semver.valid(v));
  if (!all.length) throw new Error('that package has no versions published');

  let matching = all;
  if (range) {
    matching = all.filter((v) => {
      try {
        return semver.satisfies(v, range, { includePrerelease: true });
      } catch (err) {
        return false;
      }
    });
  }
  if (!matching.length) return { matched: 0, versions: [] };

  const newestFirst = matching.slice().sort(semver.rcompare);
  return { matched: matching.length, versions: newestFirst.slice(0, REQUEST_VERSIONS) };
}

// id -> advisory summary, for the requests the caller may see
async function advisories(ids, ownerId) {
  // same ownership check as the list, no snooping on other people's requests
  const rows = await requests.byIds(ids, ownerId, { brief: true });

  //two requests, same package + range = one question
  const questions = new Map();
  for (const row of rows) {
    const ecosystem = row.ecosystem || 'npm';
    const key = `${ecosystem}:${row.package_name}@${row.version_range || '*'}`;
    if (!questions.has(key)) {
      questions.set(key, { key, ecosystem, name: row.package_name, range: row.version_range || '', ids: [] });
    }
    questions.get(key).ids.push(row.id);
  }

  const now = Date.now();
  const asking = [];
  const answers = new Map();
  for (const q of questions.values()) {
    const held = vulnCache.get(q.key);
    if (held && now - held.at < VULN_TTL_MS) answers.set(q.key, held.value);
    else asking.push(q);
  }

  // one batch to the feed, not a call per package
  const pairs = [];
  for (const q of asking) {
    // a tag has no advisories of its own. what is inside the image is scanned when it is pulled
    if (q.ecosystem === 'oci') {
      q.image = true;
      continue;
    }
    try {
      const { matched, versions, name: spelled } = await versionsToCheck(q.name, q.range, q.ecosystem);
      // a NuGet id is asked about as the feed spells it, the advisory feed minds the case
      if (spelled) q.name = spelled;
      q.matched = matched;
      q.versions = versions;
      for (const version of versions) pairs.push({ ecosystem: q.ecosystem, name: q.name, version });
    } catch (err) {
      q.error = err.message;
    }
  }

  let scan = { found: new Map(), notes: [], asked: 0 };
  if (pairs.length) scan = await cvescan.scanPairs(pairs, { max: 1000 });
  // unanswered falls back to local data - not trustworthy, not cached
  const partial = pairs.length > 0 && scan.asked < pairs.length;

  for (const q of asking) {
    if (q.image) {
      answers.set(q.key, { checked: 0, matched: 0, findings: [], worst: null, error: null,
        note: 'images are scanned for vulnerable packages when they are pulled, the Vulnerabilities page lists what was found' });
      continue;
    }
    if (q.error) {
      answers.set(q.key, { checked: 0, matched: 0, findings: [], worst: null, error: q.error });
      continue;
    }
    const findings = [];
    for (const version of q.versions) {
      const hit = scan.found.get(q.ecosystem === 'npm' ? `${q.name}@${version}` : `${q.ecosystem}:${q.name}@${version}`);
      if (hit) {
        findings.push({
          version,
          severity: String(hit.severity || 'unrated').toLowerCase(),
          cves: hit.cves || '',
          summary: hit.summary || '',
          fixed_in: hit.fixed_in || null
        });
      }
    }
    findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
    const value = {
      checked: q.versions.length,
      matched: q.matched,
      findings,
      worst: worstOf(findings),
      partial,
      error: null
    };
    // silence isn't a clean bill of health. don't cache
    if (!partial) holdAnswer(q.key, value, now);
    answers.set(q.key, value);
  }

  const results = {};
  for (const q of questions.values()) {
    const value = answers.get(q.key);
    if (!value) continue;
    for (const id of q.ids) results[id] = { ecosystem: q.ecosystem, package: q.name, range: q.range, ...value };
  }
  return results;
}

// ---------------------------------------------------------------- asking

// { type, name, range, reason } -> { alreadyAllowed } | { bumped: id } | { created: id }
async function ask(actor, { type, name, range, reason }) {
  const gate = await auth.rateLimit(`req:${actor.id}`, 20, 60 * 60000);
  if (!gate.ok) fail(429, 'that is a lot of requests in one hour, give it a rest');

  const verdict = await policy.checkPackage(name, type.adapter);
  if (verdict.allowed) return { alreadyAllowed: true };

  const dupe = await requests.openFor(type.id, name, actor.id);
  if (dupe) {
    await requests.bump(dupe.id);
    return { bumped: dupe.id };
  }

  const result = await requests.createFromPortal({ ecosystem: type.id, name, range, userId: actor.id, username: actor.name, ip: actor.ip, reason });
  await audit(actor, 'request.create', type.id === 'npm' ? name : `${type.id}:${name}`, reason);
  require('./auto-approve').nudge();
  return { created: result.insertId };
}

// bulk ask, e.g. a lockfile full of blocked stuff. approved skipped, open bumped, one reason for the lot
async function askMany(actor, { type, items, reason }) {
  // own rate limit bucket, one action however many packages
  const gate = await auth.rateLimit(`reqbulk:${actor.id}`, 10, 60 * 60000);
  if (!gate.ok) fail(429, 'that is a lot of asking in one hour, give it a rest');

  const created = [];
  const bumped = [];
  const skipped = [];

  for (const raw of items) {
    const typed = String((raw && raw.name) || '').trim();
    if (!type.validName(typed)) {
      skipped.push({ name: typed || '(blank)', error: type.badName });
      continue;
    }
    const name = type.name(typed);
    let range = '';
    try {
      // a tree hands over the exact release it picked; for PyPI that means a == pin
      const wanted = raw.version_range && type.id === 'pypi' && pypiVersion.valid(String(raw.version_range).trim())
        ? `==${String(raw.version_range).trim()}` : raw.version_range;
      range = checkRange(wanted, type.id);
    } catch (err) {
      range = '';                       // junk range? drop it
    }

    const verdict = await policy.checkPackage(name, type.adapter);
    if (verdict.allowed) {
      skipped.push({ name, error: 'already approved, you can install it now' });
      continue;
    }

    const dupe = await requests.openFor(type.id, name, actor.id);
    if (dupe) {
      await requests.bump(dupe.id);
      bumped.push(name);
      continue;
    }

    await requests.createFromPortal({ ecosystem: type.id, name, range, userId: actor.id, username: actor.name, ip: actor.ip, reason });
    created.push(name);
  }

  if (created.length || bumped.length) {
    await audit(actor, 'request.create.bulk', `${created.length} new, ${bumped.length} bumped`, reason);
  }
  if (created.length) require('./auto-approve').nudge();
  return { created: created.length, bumped: bumped.length, skipped };
}

async function withdraw(actor, row) {
  // staff can see every row, only the asker gets to withdraw
  if (row.user_id !== actor.id) fail(404, 'no such request');
  if (row.status !== 'pending') fail(400, 'that request is already settled');
  if (!(await requests.withdraw(row.id, actor.id))) fail(409, 'that request was settled a moment ago');
  await audit(actor, 'request.withdraw', row.package_name, null);
}

// ---------------------------------------------------------------- deciding

// claim + rule write in one tx, only while pending (used to leave stray allow rules). false = beaten to it
async function claimApproval(actor, row, note, range, addRule) {
  const won = await db.transaction(async (q) => {
    if (!(await requests.settle({ id: row.id, status: 'approved', note, resolvedBy: actor.id }, q))) return false;
    if (addRule) {
      await rules.upsert(
        { ecosystem: row.ecosystem || 'npm', pattern: row.package_name, kind: 'allow', version_range: range, note: note || `approved request #${row.id}`, created_by: actor.name },
        { note: 'values', enabled: 1 },
        q
      );
    }
    return true;
  });
  if (won) {
    require('../integrations/events').emit('package.approved', {
      ecosystem: row.ecosystem || 'npm', package: row.package_name, version: range || null, user: actor.name,
      sourceIp: actor.ip, reason: note || `request #${row.id} approved`, action: addRule ? 'allow rule added' : 'approved'
    });
  }
  return won;
}

// auto approve's way in: the same claim and rule as a person's approval, pinned to what it checked
async function claimAuto(actor, row, note, range) {
  return claimApproval(actor, row, note, range, true);
}

async function approve(actor, row, { note, range, addRule }) {
  if (row.status !== 'pending') fail(400, 'that request is already settled');
  if (!(await claimApproval(actor, row, note, range, addRule))) fail(409, 'somebody settled that request a moment ago');
  if (addRule) policy.invalidate();
  await audit(actor, 'request.approve', row.package_name, note,
    { before: { status: 'pending' }, after: { status: 'approved', allow_rule: addRule ? range || 'every version' : null } });
  if (addRule && !range) {
    require('../warm-latest').queueRules([{ ecosystem: row.ecosystem || 'npm', pattern: row.package_name, kind: 'allow', version_range: '', enabled: 1 }], actor);
  }
}

// non-pending rows are left alone and reported - reopening a colleague's decisions is way worse.
// failures collected, one bad row doesn't stop the rest
async function approveMany(actor, ids, rows, { note, addRule }) {
  const found = new Set(rows.map((r) => r.id));
  const skipped = ids.filter((id) => !found.has(id)).map((id) => ({ id, error: 'no such request' }));
  const approved = [];

  for (const row of rows) {
    if (row.status !== 'pending') {
      skipped.push({ id: row.id, name: row.package_name, error: `already ${row.status}` });
      continue;
    }
    let won;
    try {
      won = await claimApproval(actor, row, note, row.version_range || '', addRule);
    } catch (err) {
      log.error(`bulk approve failed on ${row.package_name}`, err.message);
      skipped.push({ id: row.id, name: row.package_name, error: 'could not approve it' });
      continue;
    }
    if (!won) {
      skipped.push({ id: row.id, name: row.package_name, error: 'settled by somebody else a moment ago' });
      continue;
    }
    approved.push(row);
    // one audit line each
    await audit(actor, 'request.approve', row.package_name, note ? `${note} (in a batch)` : 'in a batch',
      { before: { status: 'pending' }, after: { status: 'approved', allow_rule: addRule ? row.version_range || 'every version' : null } });
  }

  if (addRule && approved.length) {
    policy.invalidate();
    require('../warm-latest').queueRules(approved.filter((r) => !r.version_range)
      .map((r) => ({ ecosystem: r.ecosystem || 'npm', pattern: r.package_name, kind: 'allow', version_range: '', enabled: 1 })), actor);
  }
  await audit(actor, 'request.approve.bulk', `${approved.length} request(s)`,
    approved.map((r) => r.package_name).slice(0, 50).join(', '));
  return { approved, skipped };
}

// reject + deny rule in one move so they can't drift. priority 1000 so a whitelist can't beat it
async function block(actor, row, { note, range }) {
  if (row.status !== 'pending') fail(400, 'that request is already settled');
  // claim + write while pending, same race as an approval
  const won = await db.transaction(async (q) => {
    if (!(await requests.settle({ id: row.id, status: 'blocked', note, resolvedBy: actor.id }, q))) return false;
    await rules.upsert(
      {
        ecosystem: row.ecosystem || 'npm', pattern: row.package_name, kind: 'deny', version_range: range,
        note: `${note} (from request #${row.id})`.slice(0, 512), priority: 1000, enabled: 1, created_by: actor.name
      },
      { note: 'values', priority: 1000, enabled: 1 },
      q
    );
    return true;
  });
  if (!won) fail(409, 'somebody settled that request a moment ago');
  policy.invalidate();
  const target = (row.ecosystem || 'npm') === 'npm'
    ? `${row.package_name}${range ? `@${range}` : ''}`
    : `${row.ecosystem}:${row.package_name}${range ? ` ${range}` : ''}`;
  await audit(actor, 'request.block', target, note, { before: { status: 'pending' }, after: { status: 'blocked', deny_rule: range || 'every version' } });
  return target;
}

// clears without deciding (typos, noise). audit trail keeps who/when.
//not a permanent mute - next blocked install opens a new one. overview stops counting older blocks though
async function clear(actor, ids) {
  if (!ids.length) fail(400, 'nothing was selected');
  const rows = await requests.summaries(ids);
  if (!rows.length) fail(404, 'none of those requests exist');

  await requests.removeMany(rows.map((r) => r.id));
  for (const row of rows) await requests.markCleared(row.package_name, actor.name);
  await audit(actor, 'request.clear', `${rows.length} request(s)`,
    rows.map((r) => r.package_name).slice(0, 50).join(', '));
  return rows;
}

async function reject(actor, row, note) {
  if (row.status !== 'pending') fail(400, 'that request is already settled');
  if (!(await requests.settle({ id: row.id, status: 'rejected', note, resolvedBy: actor.id }))) fail(409, 'somebody settled that request a moment ago');
  await audit(actor, 'request.reject', row.package_name, note, { before: { status: 'pending' }, after: { status: 'rejected' } });
}

module.exports = { list, load, advisories, ask, askMany, withdraw, approve, approveMany, claimAuto, block, clear, reject, worstOf };
