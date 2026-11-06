// The cache follows the rules. when a rule goes away, gets denied, expires or is narrowed, anything cached that the rules
// now block is removed, so a blocked package isn't sitting on disk waiting for a backup or a scan to trip over it.
// Author: Tim Rice
//
// the engine hands over what changed on each reload, which catches every way a rule changes (pages, the API, imports,
// requests, expiry, even a hand edit in the db). each name is judged by the engine itself, the same answer serving gives,
// so a version still allowed anywhere stays. published here (pushed, deployed) is never touched, there's no upstream to
// bring that back from

const db = require('../db');
const log = require('../logger');
const ecosystems = require('../ecosystems');
const kinds = require('../registry/kinds');

const PUBLISHED = 'published:here';
// a bulk import of 10k rules is fine, it just gets worked through in the background
const MAX_QUEUED = 50000;

const queue = new Map();
let running = false;
const stats = { checked: 0, removed: 0, lastRun: null, lastError: null };

const keyOf = (r) => `${r.ecosystem || 'npm'}\n${r.pattern}`;

// what a rule row looks like for comparing two loads
const sig = (r) => [r.ecosystem || 'npm', r.pattern, r.kind, r.version_range || '', r.application_id || 0, r.environment_id || 0, r.priority].join('\0');

// old and new engine rows. only changes that could block something get queued: a new allow for every version can't,
// and neither can a deny going away. everything else (an allow removed, disabled or expired, a new deny, a range
// narrowed, a priority moved) gets its name looked at
function changed(before, after) {
  const old = new Map((before || []).map((r) => [r.id, r]));
  const now = new Map((after || []).map((r) => [r.id, r]));
  const touch = (r) => {
    if (queue.size >= MAX_QUEUED) return;
    queue.set(keyOf(r), { ecosystem: r.ecosystem || 'npm', pattern: String(r.pattern) });
  };
  for (const [id, r] of old) {
    const next = now.get(id);
    if (!next) {
      if (r.kind === 'allow') touch(r);
    } else if (sig(next) !== sig(r)) {
      touch(r);
      touch(next);
    }
  }
  for (const [id, r] of now) {
    if (old.has(id)) continue;
    if (r.kind === 'deny' || r.version_range) touch(r);
  }
  return queue.size;
}

// a rule's pattern as a LIKE. * is the only wildcard a rule has, the rest is taken literally
function likeOf(pattern) {
  return String(pattern).replace(/[\\%_]/g, (c) => `\\${c}`).replace(/\*/g, '%');
}

// ---------------------------------------------------------------- per kind of registry

async function npmBlocked(pattern, policy) {
  const rows = await db.query(
    "SELECT package_name, version FROM tarballs WHERE package_name LIKE ? AND COALESCE(source, '') <> ?", [likeOf(pattern), PUBLISHED]
  );
  const cache = require('../registry/npm/cache');
  let n = 0;
  for (const r of rows) {
    if ((await policy.allowedAnywhere(r.package_name, r.version)).allowed) continue;
    await cache.dropTarball(r.package_name, r.version);
    n += 1;
  }
  return { n, names: [...new Set(rows.map((r) => r.package_name))] };
}

async function pypiBlocked(pattern, policy) {
  const rows = await db.query(
    "SELECT project, version, filename FROM pypi_files WHERE project LIKE ? AND COALESCE(source, '') <> ? AND filename NOT LIKE '%.metadata'",
    [likeOf(pattern), PUBLISHED]
  );
  const pypi = require('../registry/pypi/upstream');
  const adapter = ecosystems.adapter('pypi');
  const verdicts = new Map();
  let n = 0;
  for (const r of rows) {
    // no version on file, no way to ask, so it stays
    if (!r.version) continue;
    const k = `${r.project}\n${r.version}`;
    if (!verdicts.has(k)) verdicts.set(k, (await policy.allowedAnywhere(r.project, r.version, adapter)).allowed);
    if (verdicts.get(k)) continue;
    await pypi.dropFile(r.project, r.filename);
    n += 1;
  }
  return { n, names: [...new Set(rows.map((r) => r.project))] };
}

// images: judged by tag. a manifest another allowed tag still points at stays, and so does any repository pushed here
async function ociBlocked(pattern, policy) {
  const adapter = ecosystems.adapter('oci');
  const repos = await db.query('SELECT DISTINCT repository FROM oci_tags WHERE repository LIKE ?', [likeOf(pattern)]);
  const { dropImages } = require('../registry/oci/cache');
  let n = 0;
  for (const { repository } of repos) {
    const own = await db.one('SELECT 1 AS yes FROM oci_manifests WHERE repository = ? AND upstream = ? LIMIT 1', [repository, PUBLISHED]);
    if (own) continue;
    const tags = await db.query('SELECT tag, digest FROM oci_tags WHERE repository = ?', [repository]);
    const keep = new Set();
    const blocked = [];
    for (const t of tags) {
      if ((await policy.allowedAnywhere(repository, t.tag, adapter)).allowed) keep.add(t.digest);
      else blocked.push(t);
    }
    const doomed = new Set(blocked.filter((t) => !keep.has(t.digest)).map((t) => t.tag));
    if (!doomed.size) continue;
    n += await dropImages(repository, (ref) => doomed.has(ref));
  }
  return { n, names: repos.map((r) => r.repository) };
}

// nuget, maven, gems and the rest keep their files in the artifact store and nowhere else
async function kindBlocked(ecosystem, pattern, policy) {
  const adapter = ecosystems.adapter(ecosystem);
  const rows = await db.query(
    "SELECT package_name, version, filename FROM artifacts WHERE ecosystem = ? AND package_name LIKE ? AND COALESCE(upstream, '') <> ? AND version <> ''",
    [ecosystem, likeOf(pattern), PUBLISHED]
  );
  const artifacts = require('../storage/artifacts');
  const verdicts = new Map();
  let n = 0;
  for (const r of rows) {
    const k = `${r.package_name}\n${r.version}`;
    if (!verdicts.has(k)) verdicts.set(k, (await policy.allowedAnywhere(r.package_name, r.version, adapter)).allowed);
    if (verdicts.get(k)) continue;
    n += await artifacts.forgetFile(ecosystem, r.package_name, r.filename);
  }
  return { n, names: [...new Set(rows.map((r) => r.package_name))] };
}

async function purgeOne(item, policy) {
  if (item.ecosystem === 'npm') return npmBlocked(item.pattern, policy);
  if (item.ecosystem === 'pypi') return pypiBlocked(item.pattern, policy);
  if (item.ecosystem === 'oci') return ociBlocked(item.pattern, policy);
  if (kinds.get(item.ecosystem)) return kindBlocked(item.ecosystem, item.pattern, policy);
  return { n: 0, names: [] };
}

// ---------------------------------------------------------------- the worker

async function drain() {
  if (running || !queue.size) return stats;
  running = true;
  const policy = require('.');
  const auth = require('../security/auth');
  let removed = 0;
  try {
    await policy.reload();
    while (queue.size) {
      const [k, item] = queue.entries().next().value;
      queue.delete(k);
      try {
        const { n, names } = await purgeOne(item, policy);
        stats.checked += 1;
        if (n) {
          removed += n;
          stats.removed += n;
          const what = item.ecosystem === 'npm' ? item.pattern : `${item.ecosystem}:${item.pattern}`;
          log.info(`rules now block ${what}, removed ${n} cached file(s)`);
          await auth.audit(null, 'system', null, 'cache.purge.rules', what,
            `${n} cached file(s) the rules now block, ${names.slice(0, 10).join(', ')}`).catch(() => {});
        }
      } catch (err) {
        stats.lastError = `${item.pattern}: ${err.message}`;
        log.warn(`could not clear the cache for ${item.pattern} after a rule change`, err.message);
      }
    }
    if (removed) {
      // documents for a package with nothing left on disk go too, same as the purge button
      await require('../db/repositories/packuments').forgetUncached().catch(() => {});
      await require('../db/repositories/pypi-documents').forgetUncached().catch(() => {});
    }
  } finally {
    stats.lastRun = new Date().toISOString();
    running = false;
  }
  return stats;
}

// the timer's job: reload (which notices expiry and changes made elsewhere), then work the queue
async function tick() {
  await require('.').reload();
  return drain();
}

function status() {
  return { ...stats, queued: queue.size, running };
}

module.exports = { changed, drain, tick, status, likeOf };
