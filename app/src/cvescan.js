// Rechecks allowed versions against osv.dev on a schedule, reports what went bad.
// Author: Tim Rice
//
// the allow list is a photograph, it rots. this never blocks by itself though,
// a 3am job is the wrong thing to be making that call

const https = require('https');
const semver = require('semver');
const db = require('./db');
const policy = require('./policy');
const ecosystems = require('./ecosystems');
const rulecheck = require('./policy/rulecheck');
const pypiName = require('./ecosystems/pypi/name');
const pypiVersion = require('./ecosystems/pypi/version');
const kinds = require('./registry/kinds');
const { joinWithin } = require('./audit');
const log = require('./logger');

const OSV_HOST = 'api.osv.dev';
const BATCH = 500;              // osv takes up to 1000, half that = headroom
const BATCH_PAUSE_MS = 250;
const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, unrated: 0 };

// ---------------------------------------------------------------- ecosystems
// fix maps: bare name for npm, pypi:name for PyPI. npm names can't have a colon so no clashes
const ECO = {
  npm: {
    id: 'npm',
    osv: 'npm',
    adapter: ecosystems.adapter('npm'),
    name: (n) => String(n),
    fixKey: (n) => String(n),
    valid: (v) => !!semver.valid(v),
    gt: (a, b) => semver.gt(a, b),
    rcompare: (a, b) => semver.rcompare(a, b)
  },
  pypi: {
    id: 'pypi',
    osv: 'PyPI',
    adapter: ecosystems.adapter('pypi'),
    name: (n) => pypiName.normalize(n),
    fixKey: (n) => `pypi:${pypiName.normalize(n)}`,
    valid: (v) => pypiVersion.valid(v),
    gt: (a, b) => pypiVersion.gt(a, b),
    rcompare: (a, b) => pypiVersion.rcompare(a, b)
  },
  // the newer types, from their kinds. names go as the feed spells them, the advisory feed minds the case of some
  // a type with no OSV feed (CocoaPods) is left out, it has nothing to ask about
  ...Object.fromEntries(kinds.ids().filter((id) => kinds.get(id).osv).map((id) => {
    const kind = kinds.get(id);
    return [id, {
      id,
      osv: kind.osv.ecosystem,
      adapter: ecosystems.adapter(id),
      name: (n) => String(n),
      // the name the advisory feed files it under, when that is not the name kept here (a Swift package's repository)
      osvName: kind.osv.name || null,
      // how the feed writes a version (RPM feeds always give the epoch), and which feed, when that depends on where the
      // package came from (an RPM mirror of AlmaLinux 9 or of Rocky Linux 9)
      osvVersion: kind.osv.version || null,
      ecosystemOf: kind.osv.ecosystemOf || null,
      canonical: (n) => kind.canonical(n),
      fixKey: kind.osv.fixKey,
      valid: (v) => kind.version.valid(v),
      gt: (a, b) => kind.version.compare(a, b) > 0,
      rcompare: (a, b) => kind.version.compare(b, a)
    }];
  }))
};

const BY_OSV = { npm: 'npm', PyPI: 'pypi', ...Object.fromEntries(kinds.ids().filter((id) => kinds.get(id).osv).map((id) => [kinds.get(id).osv.ecosystem, id])) };

// which of the box's types an OSV ecosystem is, the per distro feeds (AlmaLinux:9, Red Hat) included
function typeOfOsv(ecosystem) {
  if (Object.prototype.hasOwnProperty.call(BY_OSV, ecosystem)) return BY_OSV[ecosystem];
  const id = kinds.ids().find((k) => kinds.get(k).osv && kinds.get(k).osv.matches && kinds.get(k).osv.matches(String(ecosystem || '')));
  return id || null;
}

function eco(id) {
  return ECO[id || 'npm'] || null;
}

//npm stays plain name@version, the file review looks it up that way
function findingKey(ecosystem, name, version) {
  return !ecosystem || ecosystem === 'npm' ? `${name}@${version}` : `${ecosystem}:${name}@${version}`;
}

let job = null;

function idle() {
  return { running: false, phase: null, scanId: null, startedAt: null, finishedAt: null, by: null,
           total: 0, done: 0, vulnerable: 0, fresh: 0, resolved: 0, failed: 0, notes: [], errors: [] };
}

function status() {
  return job ? { ...job, notes: job.notes.slice(0, 50), errors: job.errors.slice(0, 50) } : idle();
}

function running() {
  return !!(job && job.running);
}

// ---------------------------------------------------------------- osv

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = { accept: 'application/json' };
    if (payload) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(payload);
    }
    const req = https.request({ host: OSV_HOST, path, method, headers }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => resolve({ code: res.statusCode, body: text }));
    });
    req.on('error', reject);
    req.setTimeout(60000, () => req.destroy(new Error('osv timed out')));
    if (payload) req.write(payload);
    req.end();
  });
}

// flaky feed slows a scan down, doesn't kill it
async function withRetry(fn, tries = 4) {
  let last = null;
  for (let attempt = 0; attempt < tries; attempt += 1) {
    try {
      const result = await fn();
      if (result) return result;
    } catch (err) {
      last = err;
    }
    await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }
  throw last || new Error('osv would not answer');
}

// no ecosystem = npm
function osvQueries(pairs) {
  return pairs.map((p) => {
    const e = eco(p.ecosystem);
    return {
      version: p.osvAt || (e.osvVersion ? e.osvVersion(p.version) : p.version),
      package: { name: p.osvPackage || (e.osvName ? e.osvName(e.name(p.name)) : e.name(p.name)), ecosystem: p.osvEcosystem || e.osv }
    };
  });
}

// any package osv has a feed for: [{ name, version, ecosystem }] in, the advisory ids for each out, same order.
// throws when a batch does not answer, so nobody reads silence as clean
async function queryRaw(list) {
  const out = [];
  for (let i = 0; i < list.length; i += BATCH) {
    const chunk = list.slice(i, i + BATCH);
    const queries = chunk.map((q) => ({ version: q.version, package: { name: q.name, ecosystem: q.ecosystem } }));
    const res = await withRetry(async () => {
      const r = await request('POST', '/v1/querybatch', { queries });
      return r.code === 200 ? JSON.parse(r.body) : null;
    });
    const results = (res && res.results) || [];
    chunk.forEach((q, n) => {
      const vulns = (results[n] && Array.isArray(results[n].vulns)) ? results[n].vulns : [];
      out.push(vulns.map((v) => v && v.id).filter((id) => typeof id === 'string' && id.length <= 64));
    });
    if (i + BATCH < list.length) await new Promise((r) => setTimeout(r, BATCH_PAUSE_MS));
  }
  return out;
}

async function queryBatch(pairs) {
  // a pair whose feed depends on where it came from, and nobody says, is not asked about. one unknown ecosystem would
  // fail the whole batch
  const ask = [];
  const at = [];
  for (let n = 0; n < pairs.length; n += 1) {
    const p = pairs[n];
    const e = eco(p.ecosystem);
    if (e && e.ecosystemOf) {
      const feed = await e.ecosystemOf(p.name, p.version).catch(() => null);
      if (!feed) continue;
      // a feed alone, or the feed and the name and version it files the package under (a Debian source package)
      if (typeof feed === 'string') {
        p.osvEcosystem = feed;
      } else {
        p.osvEcosystem = feed.ecosystem;
        p.osvPackage = feed.name;
        p.osvAt = feed.version;
      }
    }
    ask.push(p);
    at.push(n);
  }
  const out = pairs.map(() => ({ vulns: [] }));
  if (!ask.length) return out;
  const queries = osvQueries(ask);
  const res = await withRetry(async () => {
    const r = await request('POST', '/v1/querybatch', { queries });
    return r.code === 200 ? JSON.parse(r.body) : null;
  });
  (res.results || []).forEach((r, i) => { out[at[i]] = r; });
  return out;
}

// ---------------------------------------------------------------- advisory text

// where each package got fixed. real versions only, good luck pinning to a commit hash
function fixesFrom(record) {
  const fixes = {};
  for (const affected of (record && record.affected) || []) {
    const pkg = affected.package || {};
    const e = ECO[typeOfOsv(pkg.ecosystem)];
    if (!e || !pkg.name) continue;
    const key = e.fixKey(pkg.name);
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (!event.fixed || !e.valid(event.fixed)) continue;
        if (!fixes[key] || e.gt(event.fixed, fixes[key])) fixes[key] = event.fixed;
      }
    }
  }
  return fixes;
}

// where each OS package got fixed, keyed by the feed. no version rules to compare with here, the last fix listed wins
function osFixesFrom(record, fixes) {
  for (const affected of (record && record.affected) || []) {
    const pkg = affected.package || {};
    if (!pkg.name || !pkg.ecosystem || typeOfOsv(pkg.ecosystem)) continue;
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (typeof event.fixed === 'string' && event.fixed && event.fixed.length <= 128) {
          const key = `os:${pkg.ecosystem}:${pkg.name}`;
          const had = fixes[key];
          if (!had || require('./images/versions').compare(event.fixed, had) > 0) fixes[key] = event.fixed;
        }
      }
    }
  }
  return fixes;
}

// fetch advisories we haven't seen. old npm-only rows get refetched once for a PyPI hit
async function ensureAdvisories(ids, refreshOld) {
  if (!ids.length) return;
  const rows = await db.query(
    `SELECT id, aliases FROM cve_advisories WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
  const known = new Map(rows.map((r) => [r.id, r]));
  const missing = ids.filter((id) => {
    const row = known.get(id);
    return !row || (row.aliases === null && refreshOld && refreshOld.has(id));
  });

  for (const id of missing) {
    try {
      const r = await withRetry(async () => {
        const res = await request('GET', `/v1/vulns/${encodeURIComponent(id)}`);
        return res.code === 200 ? JSON.parse(res.body) : null;
      }, 3);

      await db.query(
        `INSERT INTO cve_advisories (id, cves, aliases, severity, summary, fixes, fetched_at)
         VALUES (?, ?, ?, ?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE cves = VALUES(cves), aliases = VALUES(aliases), severity = VALUES(severity),
           summary = VALUES(summary), fixes = VALUES(fixes), fetched_at = NOW()`,
        [
          id,
          // distribution advisories name the CVE as upstream, not as an alias
          joinWithin([...new Set([...(r.aliases || []), ...(r.upstream || [])])].filter((a) => typeof a === 'string' && a.startsWith('CVE-')), 512),
          // stored even when empty so "no aliases" reads as checked, not as an old row
          (r.aliases || []).join(','),
          // the advisory's own rating first, then the distribution's, then the CVSS vector
          require('./images/severity').ofRecord(r),
          String(r.summary || '').replace(/\s+/g, ' ').trim().slice(0, 512),
          JSON.stringify(osFixesFrom(r, fixesFrom(r)))
        ]
      );
    } catch (err) {
      log.warn(`could not read advisory ${id}`, err.message);
    }
    await new Promise((r) => setTimeout(r, 60));
  }
}

// ---------------------------------------------------------------- what to check

// every exact version the rules would serve today. denied pins are just noise
async function whatToCheck() {
  const seen = new Set();
  const out = [];
  const on = new Set(ecosystems.enabled((k) => db.settings.getBool(k)).map((e) => e.id));

  const consider = async (ecosystem, rawName, version) => {
    const e = eco(ecosystem);
    if (!e || !on.has(e.id)) return;
    //exact versions only, can't ask osv about a range
    if (!version || !e.valid(version)) return;
    const name = e.canonical ? await e.canonical(rawName) : e.name(rawName);
    const key = findingKey(e.id, name, version);
    if (seen.has(key)) return;
    seen.add(key);
    const verdict = await policy.allowedAnywhere(name, version, e.adapter);
    if (verdict.allowed) out.push({ ecosystem: e.id, name, version });
  };

  const rules = await db.query(
    `SELECT ecosystem, pattern, version_range FROM rules
      WHERE kind = 'allow' AND enabled = 1 AND version_range <> ''
        AND pattern NOT LIKE '%*%'`
  );
  for (const rule of rules) {
    const ecosystem = rule.ecosystem || 'npm';
    for (const version of rulecheck.exactPins(rule.version_range, ecosystem)) {
      await consider(ecosystem, rule.pattern, version);
    }
  }

  // plus everything pulled. rules say MAY install, the cache says DID
  for (const row of await db.query('SELECT DISTINCT package_name, version FROM tarballs')) {
    await consider('npm', row.package_name, row.version);
  }
  for (const row of await db.query("SELECT DISTINCT project, version FROM pypi_files WHERE version <> ''")) {
    await consider('pypi', row.project, row.version);
  }
  // the newer types keep everything in artifacts
  for (const id of kinds.ids().filter((k) => kinds.get(k).osv)) {
    for (const row of await db.query("SELECT DISTINCT package_name, version FROM artifacts WHERE ecosystem = ? AND version <> ''", [id])) {
      await consider(id, row.package_name, row.version);
    }
  }

  return out;
}

// ---------------------------------------------------------------- findings

async function loadAdvisories(ids) {
  const out = {};
  if (!ids.length) return out;
  const rows = await db.query(
    `SELECT id, cves, aliases, severity, summary, fixes FROM cve_advisories WHERE id IN (${ids.map(() => '?').join(',')})`,
    ids
  );
  for (const row of rows) out[row.id] = { ...row, fixes: JSON.parse(row.fixes || '{}') };
  return out;
}

// one vuln, several ids (GHSA + PYSEC). aliases merge via a little union-find,
// keep the copy with a severity, then GHSA, then lowest id
function distinctAdvisories(ids, adv) {
  const present = new Set(ids);
  const parent = new Map(ids.map((id) => [id, id]));
  const find = (x) => {
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root);
    return root;
  };
  for (const id of ids) {
    const record = adv[id];
    if (!record || !record.aliases) continue;
    for (const alias of String(record.aliases).split(',')) {
      const other = alias.trim();
      if (!other || !present.has(other)) continue;
      const a = find(id);
      const b = find(other);
      if (a !== b) parent.set(b, a);
    }
  }

  const groups = new Map();
  for (const id of ids) {
    const root = find(id);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(id);
  }

  const rank = (id) => {
    const record = adv[id] || {};
    const rated = record.severity && record.severity !== 'unrated' ? 1 : 0;
    return [rated, /^GHSA-/i.test(id) ? 1 : 0];
  };
  return [...groups.values()].map((group) => group.slice().sort((x, y) => {
    const [ra, ga] = rank(x);
    const [rb, gb] = rank(y);
    return (rb - ra) || (gb - ga) || (x < y ? -1 : x > y ? 1 : 0);
  })[0]);
}

// Separate from the write so report-only callers get the same answer the row would
function composeFinding(ecosystem, name, ids, adv) {
  const e = eco(ecosystem) || ECO.npm;
  const kept = distinctAdvisories(ids, adv);
  // every copy still counts for severity, dedupe never makes it look nicer
  const records = ids.map((id) => adv[id]).filter(Boolean);
  const severity = records.map((r) => r.severity)
    .sort((a, b) => (SEV_ORDER[b] || 0) - (SEV_ORDER[a] || 0))[0] || 'unrated';
  const worst = kept.map((id) => adv[id]).filter(Boolean)
    .sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0))[0];
  //"and N more" is not a CVE
  const cves = joinWithin([...new Set(records.flatMap((r) => (r.cves ? r.cves.split(', ') : [])))]
    .filter((c) => /^CVE-/.test(c)), 512);

  const key = e.fixKey(name);
  const fixedIn = records
    .map((r) => (r.fixes || {})[key])
    .filter((v) => v && e.valid(v))
    .sort(e.rcompare)[0] || null;

  return { severity, cves, summary: worst ? worst.summary : '', fixed_in: fixedIn, advisories: kept.join(',') };
}

async function saveFinding(ecosystem, name, version, ids, adv) {
  const { severity, cves, summary, fixed_in: fixedIn, advisories } = composeFinding(ecosystem, name, ids, adv);

  const result = await db.query(
    `INSERT INTO cve_findings (ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in, first_seen, last_seen)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
     ON DUPLICATE KEY UPDATE advisories = VALUES(advisories), cves = VALUES(cves),
       severity = VALUES(severity), summary = VALUES(summary), fixed_in = VALUES(fixed_in), last_seen = NOW()`,
    [ecosystem || 'npm', name, version, advisories, cves, severity, summary, fixedIn]
  );
  await killMalicious(ids);
  //mysql says 1 for a fresh insert, 2 for an update. yes, 2.
  if (result.affectedRows === 1) {
    // what CISA and FIRST already say about it. not on a list we have is null, not a promise it is safe
    const known = await require('./integrations/intel').summarize(cves).catch(() => ({}));
    require('./integrations/events').emit('vulnerability.discovered', {
      ecosystem: ecosystem || 'npm', package: name, version, severity, cve: cves, advisories, reason: summary, action: 'recorded',
      epss: known.epss, cisaKev: known.kev ? true : null
    });
  }
  return result.affectedRows === 1;
}

function nonNpmIds(hits) {
  return new Set(hits.filter((h) => h.ecosystem && h.ecosystem !== 'npm').flatMap((h) => h.ids));
}

// check versions as they first come down the wire. queued + batched, since a cold
// install is thousands at once and osv would rate limit us. never throws, never holds up a download
const QUEUE_WAIT_MS = 2000;
const QUEUE_MAX = 2000;

const queued = new Map();
let flushTimer = null;
let flushing = false;
let dropped = 0;

function scheduleFlush() {
  if (flushTimer || flushing) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flush().catch((err) => log.error('the new version check failed', err.message));
  }, QUEUE_WAIT_MS);
  // don't keep the process alive just for this
  if (flushTimer.unref) flushTimer.unref();
}

function checkVersion(rawName, version, ecosystem = 'npm') {
  if (db.settings.getInt('cve_scan_hours', 24) <= 0) return Promise.resolve(null);
  const e = eco(ecosystem);
  if (!e || !e.valid(version)) return Promise.resolve(null);
  const name = e.name(rawName);

  const key = findingKey(e.id, name, version);
  const waiting = queued.get(key);
  if (waiting) return waiting.promise;

  // cold cache filling, the scan will get there. log once
  if (queued.size >= QUEUE_MAX) {
    dropped += 1;
    if (dropped === 1) {
      log.warn(`more than ${QUEUE_MAX} new versions are waiting to be checked, leaving the rest to the next scan`);
    }
    return Promise.resolve(null);
  }

  const item = { key, ecosystem: e.id, name, version, settled: false };
  item.promise = new Promise((resolve) => {
    item.resolve = (value) => {
      if (item.settled) return;
      item.settled = true;
      resolve(value);
    };
  });
  queued.set(key, item);
  scheduleFlush();
  return item.promise;
}

async function flush() {
  if (flushing || !queued.size) return;
  // the scan writes and deletes findings wholesale, stay out of its way (race)
  if (running()) {
    scheduleFlush();
    return;
  }

  flushing = true;
  const batch = [...queued.values()].slice(0, BATCH);
  for (const item of batch) queued.delete(item.key);

  try {
    // Already on the list? no need to ask
    const fresh = [];
    for (const item of batch) {
      try {
        const already = await db.one(
          'SELECT id FROM cve_findings WHERE ecosystem = ? AND package_name = ? AND version = ?',
          [item.ecosystem, item.name, item.version]);
        if (already) item.resolve(null);
        else fresh.push(item);
      } catch (err) {
        item.resolve(null);
      }
    }
    if (!fresh.length) return;

    let results = [];
    try {
      results = await queryBatch(fresh);
    } catch (err) {
      log.error(`could not ask the feed about ${fresh.length} newly pulled version(s)`, err.message);
      return;
    }

    const hits = [];
    fresh.forEach((item, n) => {
      const ids = ((results[n] && results[n].vulns) || []).map((v) => v.id);
      if (ids.length) hits.push({ item, ecosystem: item.ecosystem, ids });
      else item.resolve(null);
    });
    if (!hits.length) return;

    const ids = [...new Set(hits.flatMap((h) => h.ids))];
    await ensureAdvisories(ids, nonNpmIds(hits));
    const adv = await loadAdvisories(ids);

    for (const { item, ids: hitIds } of hits) {
      try {
        await saveFinding(item.ecosystem, item.name, item.version, hitIds, adv);
        const row = await db.one(
          `SELECT ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in
             FROM cve_findings WHERE ecosystem = ? AND package_name = ? AND version = ?`,
          [item.ecosystem, item.name, item.version]
        );
        const count = row ? row.advisories.split(',').filter(Boolean).length : hitIds.length;
        log.warn(`${item.name} ${item.version} (${item.ecosystem}) was pulled and has ${count} known advisory/advisories against it`);
        item.resolve(row);
      } catch (err) {
        item.resolve(null);
      }
    }
  } finally {
    // whatever blew up above, nobody waits forever
    for (const item of batch) item.resolve(null);
    flushing = false;
    dropped = 0;
    if (queued.size) scheduleFlush();
  }
}

// ---------------------------------------------------------------- checking a list on demand

// ask about a list right now, for the Check page (someone's tapping their foot).
// saves findings but never deletes, never throws, falls back to what we knew
async function scanPairs(pairs, options = {}) {
  const max = options.max || 2000;
  const notes = [];
  const found = new Map();

  const wanted = [];
  const seen = new Set();
  for (const p of pairs) {
    const e = eco(p.ecosystem);
    if (!e || !e.valid(p.version)) continue;
    const name = e.name(p.name);
    const key = findingKey(e.id, name, p.version);
    if (seen.has(key)) continue;
    seen.add(key);
    wanted.push({ ecosystem: e.id, name, version: p.version, key });
  }
  if (!wanted.length) return { found, notes, asked: 0, checked: 0 };

  let ask = wanted;
  if (wanted.length > max) {
    ask = wanted.slice(0, max);
    notes.push(`asked the feed about the first ${max} of ${wanted.length} pinned versions, the rest are answered from what was already known`);
  }

  // what the box already knows, also the fallback
  const readBack = async (list) => {
    for (let i = 0; i < list.length; i += 500) {
      const batch = list.slice(i, i + 500);
      const rows = await db.query(
        `SELECT ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in
           FROM cve_findings WHERE (ecosystem, package_name, version) IN (${batch.map(() => '(?,?,?)').join(',')})`,
        batch.flatMap((p) => [p.ecosystem, p.name, p.version])
      );
      for (const row of rows) found.set(findingKey(row.ecosystem, row.package_name, row.version), row);
    }
  };
  await readBack(wanted);

  // scan bulk-deletes at the end, don't write under it
  if (running()) {
    notes.push('a full scan is running, so these versions were answered from what the box already knew rather than asked about again');
    return { found, notes, asked: 0, checked: wanted.length };
  }

  const hits = [];
  let asked = 0;
  // something was found and could not be described. callers approving things must not read that as clean
  let incomplete = false;
  for (let i = 0; i < ask.length; i += BATCH) {
    const chunk = ask.slice(i, i + BATCH);
    try {
      const results = await queryBatch(chunk);
      results.forEach((r, n) => {
        const vulns = (r && r.vulns) || [];
        if (vulns.length) hits.push({ ...chunk[n], ids: vulns.map((v) => v.id) });
        // "nothing found" is still an answer, drop any stale row
        else found.delete(chunk[n].key);
      });
      asked += chunk.length;
    } catch (err) {
      notes.push(`the advisory feed did not answer about ${chunk.length} version(s), they are reported from what was already known`);
      log.warn('the review could not reach the advisory feed', err.message);
    }
    if (i + BATCH < ask.length) await new Promise((r) => setTimeout(r, BATCH_PAUSE_MS));
  }

  if (hits.length) {
    const ids = [...new Set(hits.flatMap((h) => h.ids))];
    try {
      await ensureAdvisories(ids, nonNpmIds(hits));
      const adv = await loadAdvisories(ids);

      // only save what we'd serve, another team's lockfile isn't our exposure
      let fresh = 0;
      let ours = 0;
      for (const hit of hits) {
        //caller hears about every hit either way
        found.set(hit.key, {
          ecosystem: hit.ecosystem,
          package_name: hit.name,
          version: hit.version,
          ...composeFinding(hit.ecosystem, hit.name, hit.ids, adv)
        });
        const verdict = await policy.allowedAnywhere(hit.name, hit.version, eco(hit.ecosystem).adapter);
        if (!verdict.allowed) continue;
        ours += 1;
        if (await saveFinding(hit.ecosystem, hit.name, hit.version, hit.ids, adv)) fresh += 1;
      }
      if (fresh) notes.push(`${fresh} of these were not on this registry's vulnerabilities list before and are now`);
      if (hits.length > ours) {
        notes.push(`${hits.length - ours} of the versions with advisories are not ones this registry would serve, so they are reported here but not added to the vulnerabilities list`);
      }
    } catch (err) {
      incomplete = true;
      notes.push('the advisory detail could not be read, so some findings are reported without their text');
      log.warn('the review could not read advisory detail', err.message);
    }
  }

  return { found, notes, asked, checked: wanted.length, incomplete };
}

// ---------------------------------------------------------------- the scan

async function run(actor, current) {
  const scan = await db.query('INSERT INTO cve_scans (started_by, status) VALUES (?, ?)', [actor, 'running']);
  const scanId = scan.insertId;
  //start() normally sets job, this is just in case
  if (!current) job = { ...idle(), running: true, startedAt: new Date().toISOString(), by: actor };
  job.scanId = scanId;

  // IMPORTANT: db time, not JS. last_seen is whole seconds, a JS time with ms made a
  // fast scan delete everything it just found. Fun bug.
  const markedAt = (await db.one('SELECT NOW() AS t')).t;

  try {
    const pairs = await whatToCheck();
    job.total = pairs.length;
    job.phase = 'checking';
    const byType = {};
    for (const p of pairs) byType[p.ecosystem] = (byType[p.ecosystem] || 0) + 1;
    log.info(`vulnerability scan ${scanId}: checking ${pairs.length} allowed versions`
      + ` (${Object.entries(byType).map(([k, n]) => `${n} ${k}`).join(', ') || 'none'})`);

    const hits = [];
    for (let i = 0; i < pairs.length; i += BATCH) {
      if (!job.running) break;
      const chunk = pairs.slice(i, i + BATCH);
      try {
        const results = await queryBatch(chunk);
        results.forEach((r, n) => {
          const vulns = (r && r.vulns) || [];
          if (vulns.length) hits.push({ ...chunk[n], ids: vulns.map((v) => v.id) });
        });
      } catch (err) {
        job.failed += chunk.length;
        job.errors.push(`batch at ${i}: ${err.message}`);
      }
      job.done = Math.min(i + BATCH, pairs.length);
      await new Promise((r) => setTimeout(r, BATCH_PAUSE_MS));
    }

    job.vulnerable = hits.length;
    const ids = [...new Set(hits.flatMap((h) => h.ids))];
    await ensureAdvisories(ids, nonNpmIds(hits));

    const adv = await loadAdvisories(ids);

    let fresh = 0;
    for (const hit of hits) {
      if (await saveFinding(hit.ecosystem, hit.name, hit.version, hit.ids, adv)) fresh += 1;
    }
    job.fresh = fresh;

    // untouched = fixed. BUT a canceled or partly failed scan clears nothing. images keep their own list, below
    if (job.running && !job.failed) {
      const clearing = await db.query("SELECT ecosystem, package_name, version, severity, cves, advisories FROM cve_findings WHERE last_seen < ? AND ecosystem <> 'oci' LIMIT 1000", [markedAt]);
      for (const f of clearing) {
        require('./integrations/events').emit('vulnerability.remediated', {
          ecosystem: f.ecosystem, package: f.package_name, version: f.version, severity: f.severity, cve: f.cves, advisories: f.advisories,
          reason: 'no longer matched by any advisory', action: 'cleared'
        });
      }
      const gone = await db.query("DELETE FROM cve_findings WHERE last_seen < ? AND ecosystem <> 'oci'", [markedAt]);
      job.resolved = gone.affectedRows;
    } else {
      job.notes.push('the scan did not check everything, so no earlier finding was cleared');
    }

    // the packages inside pulled images, asked about again. a feed that does not answer leaves an image as it was
    if (job.running) {
      job.phase = 'images';
      const images = await require('./images/scanner').recheck(job);
      if (images.images) job.notes.push(`${images.images} pulled image(s) checked again`);
      if (images.failed) job.notes.push(`${images.failed} image(s) could not be checked again and keep what was known`);
    }

    await db.query(
      `UPDATE cve_scans SET finished_at = NOW(), checked = ?, vulnerable = ?, fresh = ?, resolved = ?,
              failed = ?, status = ? WHERE id = ?`,
      [job.done, job.vulnerable, job.fresh, job.resolved, job.failed, job.running ? 'done' : 'canceled', scanId]
    );

    if (fresh) job.notes.push(`${fresh} finding(s) are new since the last scan`);
    if (job.resolved) job.notes.push(`${job.resolved} earlier finding(s) no longer apply`);
    if (!hits.length) job.notes.push('nothing on the allow list has a known advisory against it');
    log.info(`vulnerability scan ${scanId} done: ${job.vulnerable} vulnerable, ${fresh} new, ${job.resolved} cleared`);
  } catch (err) {
    job.errors.push(err.message);
    await db.query('UPDATE cve_scans SET finished_at = NOW(), status = ? WHERE id = ?', ['failed', scanId])
      .catch(() => {});
    log.error('vulnerability scan failed', err.message);
  }

  job.running = false;
  job.finishedAt = new Date().toISOString();
  return job;
}

function start(actor) {
  if (running()) {
    const e = new Error('a vulnerability scan is already running');
    e.status = 409;
    throw e;
  }
  // mark it running HERE before any await, or an impatient second click starts a twin scan. Whoops
  job = { ...idle(), running: true, phase: 'preparing', startedAt: new Date().toISOString(), by: actor };
  const mine = job;
  run(actor, mine).catch((err) => {
    log.error('vulnerability scan blew up', err.message);
    mine.running = false;
    mine.errors.push(err.message);
    mine.finishedAt = new Date().toISOString();
  });
  return status();
}

function cancel() {
  if (job && job.running) {
    job.running = false;
    job.notes.push('canceled');
  }
  return status();
}

// ---------------------------------------------------------------- schedule

// called hourly. cve_scan_hours = 0 turns it off
async function maybeRun() {
  const hours = db.settings.getInt('cve_scan_hours', 24);
  if (!hours || running()) return;
  const last = await db.one("SELECT finished_at FROM cve_scans WHERE status = 'done' ORDER BY id DESC LIMIT 1");
  if (last && last.finished_at) {
    const age = Date.now() - new Date(last.finished_at).getTime();
    if (age < hours * 3600000) return;
  }
  log.info('vulnerability scan is due, starting it');
  start('schedule');
}

// for the image scanner, which asks about packages the allow list never has
const osv = { queryRaw, ensureAdvisories, loadAdvisories, ecosystem: (id) => eco(id) };

// the advisory ids OSV has for each { ecosystem, name, version }, same order. throws when the feed does not answer
async function advisoryIds(pairs) {
  const out = [];
  for (let i = 0; i < pairs.length; i += BATCH) {
    const chunk = pairs.slice(i, i + BATCH).map((p) => ({ ...p }));
    const results = await queryBatch(chunk);
    chunk.forEach((p, n) => {
      const vulns = results[n] && Array.isArray(results[n].vulns) ? results[n].vulns : [];
      out.push(vulns.map((v) => v && v.id).filter((id) => typeof id === 'string' && id.length <= 64));
    });
  }
  return out;
}

// a MAL- advisory is a package known to be malicious. it goes on the kill switch as soon as it is recorded, whatever
// else the policy says, and admins hear about it. an advisory kill covers every version the scan records against it
async function killMalicious(ids) {
  if (!db.settings.getBool('malicious_auto_kill')) return;
  const killswitch = require('./policy/killswitch');
  const kills = require('./db/repositories/killswitch');
  for (const id of ids.filter((x) => /^MAL-/.test(x))) {
    // once only. an admin who lifted it looked at it, the next scan doesn't get to put it back
    if (await kills.everKilled('advisory', id)) continue;
    try {
      await killswitch.kill({ kind: 'advisory', subject: id, reason: `a known-malicious package (${id} in the OSV malicious-packages feed), killed by the vulnerability scan`, user: 'vulnerability scan' });
    } catch (err) {
      if (err.status !== 409) log.error(`${id} could not go on the kill switch`, err.message);
    }
  }
}

module.exports = {
  start, status, cancel, running, maybeRun, checkVersion, scanPairs, osv, advisoryIds, killMalicious,
  // pure bits (no db, no network) so the tests can poke them
  _internal: { osvQueries, fixesFrom, osFixesFrom, distinctAdvisories, composeFinding, findingKey }
};
