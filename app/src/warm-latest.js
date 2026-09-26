// When an allow rule covers every version of a package and nothing of that package is cached yet, cache the version
// that is current right then. rules naming exact versions have the warm job, this is for the any-version ones.
// Author: Tim Rice
// one package at a time in the background. nothing here holds up the approval that asked for it

const db = require('./db');
const policy = require('./policy');
const killswitch = require('./policy/killswitch');
const registryMode = require('./policy/mode');
const npmUpstream = require('./registry/npm/upstream');
const pypi = require('./registry/pypi/upstream');
const ecosystems = require('./ecosystems');
const simple = require('./ecosystems/pypi/simple');
const { pickVersion } = require('./registry/pypi/tree');
const repo = require('./db/repositories/warm-latest');
const { audit } = require('./lib/actor');
const log = require('./logger');

// a release with a wheel for every platform there is, and then some
const MAX_FILES = 60;
// something that could not be cached is not tried again by the sweep for a day
const RETRY_MS = 24 * 3600000;
const SWEEP_LIMIT = 25;
const SYSTEM = { id: null, name: 'system', username: 'system', ip: null };

const queue = [];
const queued = new Set();
const tried = new Map();
let working = null;

function enabled() {
  return db.settings.getBool('cache_latest_on_allow');
}

// what stops it before upstream is asked anything
function blocker() {
  if (!enabled()) return 'switched off in Settings';
  if (registryMode.noNewNames()) return `the registry is in ${registryMode.current()} mode`;
  if (!npmUpstream.upstreamEnabled()) return 'the upstream registry is switched off';
  if (!db.settings.getBool('cache_tarballs')) return 'keep tarballs on disk is off';
  return null;
}

// allow, enabled, every version, one real name, a kind of package this box caches
function eligible(rule) {
  if (!rule) return false;
  const eco = rule.ecosystem || 'npm';
  if (eco !== 'npm' && eco !== 'pypi') return false;
  if (eco === 'pypi' && !db.settings.getBool('pypi_enabled')) return false;
  return rule.kind === 'allow' && (rule.enabled === undefined || Number(rule.enabled) === 1) &&
    !String(rule.version_range || '').trim() && typeof rule.pattern === 'string' && !!rule.pattern && !rule.pattern.includes('*');
}

const keyOf = (rule) => `${rule.ecosystem || 'npm'}\n${rule.pattern}`;
const label = (eco, name, version) => `${eco === 'npm' ? '' : `${eco}:`}${name}${version ? `@${version}` : ''}`;

async function record(actor, rule, version, result, detail) {
  const target = label(rule.ecosystem, rule.pattern, version);
  try {
    await audit(actor || SYSTEM, 'cache.current', target, detail, { result });
  } catch (err) {
    log.warn(`could not audit caching ${target}`, err.message);
  }
  if (result === 'success') log.info(`cached ${target} for its any-version allow rule: ${detail}`);
  return { result, version, detail };
}

async function npmCurrent(name) {
  const { doc } = await npmUpstream.getPackument(name, 'full');
  const latest = doc && doc['dist-tags'] && doc['dist-tags'].latest;
  if (typeof latest !== 'string' || !doc.versions || !Object.prototype.hasOwnProperty.call(doc.versions, latest)) return null;
  return { version: latest, dist: doc.versions[latest].dist };
}

// the newest release pip would pick without a range: stable, not yanked, has files
async function pypiCurrent(name) {
  const page = await pypi.getProject(name);
  const releases = new Map();
  for (const f of (page.doc && page.doc.files) || []) {
    const v = simple.releaseOf(f.filename, name);
    if (!v) continue;
    if (!releases.has(v)) releases.set(v, []);
    releases.get(v).push(f);
  }
  const version = pickVersion(Object.fromEntries(releases), '');
  if (!version) return null;
  return { version, files: releases.get(version).filter((f) => !f.yanked) };
}

async function cacheCurrent(rule, actor) {
  const why = blocker();
  if (why) return { result: 'skipped', detail: why };
  const eco = rule.ecosystem || 'npm';
  const name = rule.pattern;
  if (await repo.anyCached(eco, name)) return { result: 'skipped', detail: 'something of it is cached already' };

  let picked;
  try {
    picked = eco === 'pypi' ? await pypiCurrent(name) : await npmCurrent(name);
  } catch (err) {
    return record(actor, { ...rule, ecosystem: eco }, null, 'failure', `could not read it from upstream: ${err.message}`);
  }
  if (!picked) return record(actor, { ...rule, ecosystem: eco }, null, 'failure', 'upstream has no current version to cache');

  // same veto as everything else, for the rule's own application and environment
  if (await killswitch.check(eco, name, picked.version)) {
    return record(actor, { ...rule, ecosystem: eco }, picked.version, 'denied', 'the current version is on the kill switch');
  }
  const scope = { app: Number(rule.application_id) || 0, env: Number(rule.environment_id) || 0 };
  const verdict = await policy.checkVersion(name, picked.version, ecosystems.adapter(eco), scope);
  if (!verdict.allowed) return record(actor, { ...rule, ecosystem: eco }, picked.version, 'denied', `not cached: ${verdict.reason}`);

  let files = 0;
  const errors = [];
  if (eco === 'pypi') {
    for (const f of picked.files.slice(0, MAX_FILES)) {
      try {
        await pypi.getFile(name, f.filename, picked.version);
        files += 1;
        // pip reads the metadata file first when the index offers one
        if (f.coreMetadata) await pypi.getFile(name, f.filename, picked.version, { metadata: true });
      } catch (err) {
        errors.push(`${f.filename}: ${err.message}`);
      }
    }
  } else {
    try {
      await npmUpstream.getTarball(name, picked.version, picked.dist);
      files = 1;
    } catch (err) {
      errors.push(err.message);
    }
  }
  const more = picked.files && picked.files.length > MAX_FILES ? `, the first ${MAX_FILES} of ${picked.files.length} files` : '';
  if (!files) return record(actor, { ...rule, ecosystem: eco }, picked.version, 'failure', `nothing cached: ${errors[0] || 'the release has no files'}`);
  return record(actor, { ...rule, ecosystem: eco }, picked.version, 'success',
    `${files} file(s)${more}${errors.length ? `, ${errors.length} failed: ${errors[0]}` : ''}`);
}

function drain() {
  if (working) return working;
  working = (async () => {
    while (queue.length) {
      const item = queue.shift();
      try {
        await cacheCurrent(item.rule, item.actor);
      } catch (err) {
        log.warn(`caching the current version of ${item.rule.pattern} failed`, err.message);
      }
      queued.delete(keyOf(item.rule));
      if (tried.size > 5000) tried.clear();
      tried.set(keyOf(item.rule), Date.now());
    }
  })().finally(() => {
    working = null;
    if (queue.length) drain();
  });
  return working;
}

// an approval hands its rules over and carries on. the sweep passes retry so a package that failed waits a day
function queueRules(rules, actor, { retry = false } = {}) {
  if (blocker()) return 0;
  let added = 0;
  for (const rule of rules || []) {
    if (!eligible(rule)) continue;
    const key = keyOf(rule);
    if (queued.has(key)) continue;
    const last = tried.get(key);
    if (retry && last && Date.now() - last < RETRY_MS) continue;
    queued.add(key);
    queue.push({ rule: { ...rule, ecosystem: rule.ecosystem || 'npm' }, actor: actor || null });
    added += 1;
  }
  if (added) drain();
  return added;
}

// the job: any-version allow rules that still have nothing cached, a few at a time
async function sweep() {
  if (blocker()) return 0;
  const rows = await repo.uncachedAnyVersion(SWEEP_LIMIT * 4);
  return queueRules(rows.slice(0, SWEEP_LIMIT * 4), null, { retry: true });
}

// for tests and shutdown: resolves once the queue is empty
function settled() {
  return working || Promise.resolve();
}

module.exports = { MAX_FILES, RETRY_MS, SWEEP_LIMIT, enabled, blocker, eligible, cacheCurrent, queueRules, sweep, settled };
