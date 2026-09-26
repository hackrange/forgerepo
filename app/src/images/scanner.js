// Scanning the images pulled through here for vulnerable packages, the way the allow list is scanned for vulnerable versions.
// Author: Tim Rice
//
// a digest never changes what is inside it, so each one is read once. what does change is what is known about those
// packages, and the scheduled scan asks about the stored list again without touching a layer.
// a pull never waits on this. what a finding does to the next pull is the gate's call, not the scanner's

const path = require('path');
const db = require('../db');
const config = require('../config');
const log = require('../logger');
const ociName = require('../ecosystems/oci/name');
const artifacts = require('../storage/artifacts');
const { joinWithin } = require('../audit');
const repo = require('../db/repositories/image-scans');
const tar = require('./tar');
const inventory = require('./inventory');
const rpmdb = require('./rpmdb');
const versions = require('./versions');
const severity = require('./severity');

const MAX_LAYERS = 256;
const MAX_QUEUE = 200;
const KNOWN_MAX = 5000;
const RECHECK_IMAGES = 1000;
const workDir = path.join(config.cacheDir, 'tmp');
// bug fix and enhancement errata ride along on the Red Hat feed. not advisories
const NOT_SECURITY = /^(RHBA|RHEA)-/i;
const LAYER_TYPE = /^application\/vnd\.(oci\.image\.layer\.v1\.tar|docker\.image\.rootfs\.diff\.tar)(\+gzip|\.gzip|\+zstd)?$/;

function enabled() {
  return db.settings.getBool('oci_enabled') && db.settings.getBool('oci_scan');
}

function maxGb() {
  const n = db.settings.getInt('oci_scan_max_gb', 16);
  return n >= 1 && n <= 256 ? n : 16;
}

// ---------------------------------------------------------------- the queue

const queued = new Map();
const order = [];
// scanned already, so a busy image does not cost a query on every pull
const known = new Set();
let working = false;
let full = false;

const keyOf = (repository, digest) => `${repository}\n${digest}`;

function remember(key) {
  if (known.size >= KNOWN_MAX) known.delete(known.values().next().value);
  known.add(key);
}

function queue(repository, digest, options = {}) {
  if (!enabled() || !ociName.valid(repository) || !ociName.isDigest(digest)) return false;
  const key = keyOf(repository, digest);
  if (!options.force && known.has(key)) return false;
  const waiting = queued.get(key);
  if (waiting) {
    if (options.force) waiting.force = true;
    return true;
  }
  if (queued.size >= MAX_QUEUE) {
    if (!full) log.warn(`more than ${MAX_QUEUE} images are waiting to be scanned, the rest are picked up later`);
    full = true;
    return false;
  }
  queued.set(key, { key, repository, digest, force: !!options.force });
  order.push(key);
  setImmediate(() => drain().catch((err) => log.error('the image scan queue failed', err.message)));
  return true;
}

async function drain() {
  if (working) return;
  working = true;
  try {
    while (order.length) {
      const key = order.shift();
      const item = queued.get(key);
      if (!item) continue;
      try {
        await scanOne(item);
      } catch (err) {
        log.error(`scanning ${item.repository}@${item.digest} failed`, err.message);
      } finally {
        queued.delete(key);
      }
    }
  } finally {
    working = false;
    full = false;
  }
}

function pending() {
  return queued.size;
}

// ---------------------------------------------------------------- reading an image

async function readImage(repository, digest) {
  const upstream = require('../registry/oci/upstream');
  const got = await upstream.getManifest(repository, digest);
  const doc = got.doc;
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('the manifest is not a json object');
  if (Array.isArray(doc.manifests)) return { skipped: 'this is a list of platforms. each platform image is scanned when it is pulled' };
  if (!Array.isArray(doc.layers)) return { skipped: 'the manifest lists no layers' };

  const layers = doc.layers.filter((l) => l && typeof l === 'object' && typeof l.mediaType === 'string'
    && LAYER_TYPE.test(l.mediaType) && ociName.isDigest(l.digest));
  if (!layers.length) return { skipped: 'nothing in it is a filesystem layer, so it is an attestation or some other kind of artifact' };
  if (layers.length > MAX_LAYERS) throw new Error(`it has ${layers.length} layers, more than the ${MAX_LAYERS} a scan reads`);
  const bytes = layers.reduce((n, l) => n + (Number.isSafeInteger(l.size) && l.size > 0 ? l.size : 0), 0);
  if (bytes > maxGb() * 1073741824) {
    throw new Error(`its layers add up to ${(bytes / 1073741824).toFixed(1)} GB, more than the ${maxGb()} GB a scan is allowed to read`);
  }

  const notes = [];
  if (doc.layers.length !== layers.length) notes.push(`${doc.layers.length - layers.length} entries in the manifest are not filesystem layers and were not read`);
  const stack = inventory.stacker();
  for (const layer of layers) {
    // cached like any pulled layer, and checked against its digest again as it is read
    const blob = await upstream.getBlob(repository, layer.digest);
    await stack.layer((options) => tar.walkStream(artifacts.open(blob), options));
  }
  return inventory.inventory(stack.files, [...notes, ...stack.notes], (buf, format) => rpmdb.read(buf, format, workDir));
}

// ---------------------------------------------------------------- matching packages to advisories

const RANK = (s) => severity.ORDER.indexOf(s);

function worstOf(list) {
  return list.filter((s) => RANK(s) >= 0).sort((a, b) => RANK(b) - RANK(a))[0] || null;
}

// where a record keeps the fix for this package. npm and PyPI the way the allow list scan keys them, the rest by feed
function fixKeys(c) {
  if (c.type === 'npm') return [c.name];
  if (c.type === 'pypi') return [`pypi:${c.name}`];
  return inventory.feedsFor(c.ecosystem).map((feed) => `os:${feed}:${c.name}`);
}

function newest(c, list) {
  const cvescan = require('../cvescan');
  const eco = c.type === 'npm' || c.type === 'pypi' ? cvescan.osv.ecosystem(c.type) : null;
  // rpm advisories write a zero epoch the database leaves off, 0:2.28-251 is 2.28-251
  const usable = eco ? list.filter((v) => eco.valid(v)) : list.map((v) => (c.type === 'rpm' ? v.replace(/^0:/, '') : v));
  const compare = eco ? (a, b) => eco.rcompare(b, a) : versions.compare;
  return usable.slice().sort((a, b) => compare(b, a))[0] || null;
}

/** every component, with what is known against it filled in. throws when the feed does not answer */
async function match(components) {
  const cvescan = require('../cvescan');
  const asks = [];
  components.forEach((c, n) => {
    for (const feed of inventory.feedsFor(c.ecosystem)) asks.push({ n, name: c.name, version: c.version, ecosystem: feed });
  });
  const answers = await cvescan.osv.queryRaw(asks);
  const hits = new Map();
  answers.forEach((ids, i) => {
    const { n } = asks[i];
    for (const id of ids) {
      if (NOT_SECURITY.test(id)) continue;
      if (!hits.has(n)) hits.set(n, new Set());
      hits.get(n).add(id);
    }
  });
  const allIds = [...new Set([...hits.values()].flatMap((s) => [...s]))];
  await cvescan.osv.ensureAdvisories(allIds);
  const adv = await cvescan.osv.loadAdvisories(allIds);

  return components.map((c, n) => {
    const base = { type: c.type, name: c.name, version: c.version, ecosystem: c.ecosystem || null, binaries: c.binaries || [] };
    const ids = hits.get(n);
    if (!ids) return { ...base, advisories: '', cves: '', severity: '', fixable_severity: '', fixed_in: null, summary: '' };
    const records = [...ids].map((id) => ({ id, ...(adv[id] || { severity: 'unrated', cves: '', summary: '', fixes: {} }) }));
    const keys = fixKeys(c);
    const fixOf = (r) => keys.map((k) => (r.fixes || {})[k]).find((v) => typeof v === 'string' && v && v.length <= 128) || null;
    const fixes = records.map(fixOf).filter(Boolean);
    const worst = records.slice().sort((a, b) => RANK(b.severity) - RANK(a.severity))[0];
    return {
      ...base,
      advisories: [...ids].sort().join(','),
      cves: joinWithin([...new Set(records.flatMap((r) => (r.cves ? r.cves.split(', ') : [])))].filter((x) => /^CVE-/.test(x)).sort(), 512),
      severity: worstOf(records.map((r) => r.severity)) || 'unrated',
      // how bad it is counting only what an upgrade fixes today
      fixable_severity: worstOf(records.filter(fixOf).map((r) => r.severity)) || '',
      fixed_in: newest(c, fixes),
      summary: worst && worst.summary ? worst.summary : ''
    };
  });
}

// ---------------------------------------------------------------- the image's line on the vulnerabilities list

function describe(c) {
  return `${c.name} ${c.version}${c.fixed_in ? ` (fixed in ${c.fixed_in})` : ''}`;
}

async function rollup(repository, digest, components) {
  const bad = components.filter((c) => c.advisories);
  const existing = await db.one("SELECT id FROM cve_findings WHERE ecosystem = 'oci' AND package_name = ? AND version = ?", [repository, digest]);
  if (!bad.length) {
    if (existing) {
      await db.query('DELETE FROM cve_findings WHERE id = ?', [existing.id]);
      require('../integrations/events').emit('vulnerability.remediated', {
        ecosystem: 'oci', package: repository, version: digest, reason: 'no package in the image matches an advisory any more', action: 'cleared'
      });
    }
    return { vulnerable: 0, severity: '', fixable: '' };
  }
  const sorted = bad.slice().sort((a, b) => RANK(b.severity) - RANK(a.severity) || a.name.localeCompare(b.name));
  const unfixed = bad.filter((c) => !c.fixed_in).length;
  const worst = worstOf(bad.map((c) => c.severity)) || 'unrated';
  const advisories = [...new Set(bad.flatMap((c) => c.advisories.split(',')))].sort();
  const cves = joinWithin([...new Set(bad.flatMap((c) => (c.cves ? c.cves.split(', ') : [])))].filter((x) => /^CVE-/.test(x)).sort(), 512);
  let summary = `${bad.length} vulnerable package${bad.length === 1 ? '' : 's'}${unfixed ? `, ${unfixed} with no fix yet` : ''}: `;
  summary += sorted.slice(0, 6).map(describe).join(', ') + (sorted.length > 6 ? ' and more' : '');
  if (summary.length > 512) summary = `${summary.slice(0, 509)}...`;

  await db.query(
    `INSERT INTO cve_findings (ecosystem, package_name, version, advisories, cves, severity, summary, fixed_in, first_seen, last_seen)
     VALUES ('oci', ?, ?, ?, ?, ?, ?, NULL, NOW(), NOW())
     ON DUPLICATE KEY UPDATE advisories = VALUES(advisories), cves = VALUES(cves), severity = VALUES(severity),
       summary = VALUES(summary), last_seen = NOW()`,
    [repository, digest, advisories.join(',').slice(0, 60000), cves, worst, summary]
  );
  if (!existing) {
    log.warn(`${repository}@${digest} was pulled and has ${bad.length} vulnerable package(s) in it, the worst ${worst.toLowerCase()}`);
    const intel = await require('../integrations/intel').summarize(cves).catch(() => ({}));
    require('../integrations/events').emit('vulnerability.discovered', {
      ecosystem: 'oci', package: repository, version: digest, severity: worst, cve: cves, advisories: advisories.slice(0, 50).join(','),
      reason: summary, action: 'recorded', epss: intel.epss, cisaKev: intel.kev ? true : null
    });
  }
  return { vulnerable: bad.length, severity: worst, fixable: worstOf(bad.map((c) => c.fixable_severity)) || '' };
}

// ---------------------------------------------------------------- one image

async function scanOne({ key, repository, digest, force }) {
  const row = await repo.ensure(repository, digest);
  if (!force && (row.status === 'done' || row.status === 'skipped')) {
    remember(key);
    return row;
  }
  if (!force && row.status === 'failed' && row.attempts >= 5) return row;
  if (!(await repo.claim(row.id))) return row;

  const started = Date.now();
  try {
    const inv = await readImage(repository, digest);
    if (inv.skipped) {
      await repo.finish(row.id, { status: 'skipped', notes: [inv.skipped] });
      remember(key);
      return repo.byKey(repository, digest);
    }
    const matched = await match(inv.components);
    await repo.saveComponents(row.id, matched);
    const rolled = await rollup(repository, digest, matched);
    await repo.finish(row.id, {
      status: 'done', os: inv.os ? inv.os.name : '', feed: inv.feed, components: matched.length,
      vulnerable: rolled.vulnerable, severity: rolled.severity, fixable: rolled.fixable, notes: inv.notes
    });
    remember(key);
    log.info(`scanned ${repository}@${digest.slice(0, 19)}: ${matched.length} packages, ${rolled.vulnerable} vulnerable, ${Math.round((Date.now() - started) / 1000)}s`);
  } catch (err) {
    await repo.finish(row.id, { status: 'failed', error: err.message }).catch(() => {});
    log.warn(`could not scan ${repository}@${digest}`, err.message);
  }
  return repo.byKey(repository, digest);
}

// ---------------------------------------------------------------- scheduled

// the list of packages stays, what is known about them is asked again. never clears on a feed that did not answer
async function recheck(job) {
  if (!enabled()) return { images: 0, failed: 0 };
  let images = 0;
  let failed = 0;
  for (const s of await repo.done(RECHECK_IMAGES)) {
    if (job && !job.running) break;
    try {
      const stored = await repo.components(s.id);
      const matched = await match(stored);
      await repo.saveComponents(s.id, matched);
      const rolled = await rollup(s.repository, s.digest, matched);
      await repo.checked(s.id, rolled.vulnerable, rolled.severity, rolled.fixable);
      images += 1;
    } catch (err) {
      failed += 1;
      if (failed === 1) log.warn('rechecking an image against the advisory feed failed', err.message);
    }
  }
  return { images, failed };
}

// images a node died on, never got to, or failed on a while back
async function resume() {
  if (!enabled()) return 0;
  let n = 0;
  for (const r of await repo.resumable(20)) if (queue(r.repository, r.digest, { force: true })) n += 1;
  return n;
}

module.exports = {
  enabled, queue, pending, scanOne, recheck, resume,
  _internal: { readImage, match, rollup, fixKeys, LAYER_TYPE, drain }
};
