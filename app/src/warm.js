// Pulls the files an allow rule pins into the local cache before anybody
// asks for them. Meal prep, but for packages.
// Author: Tim Rice
//
// an allow rule doesn't put anything on disk, and once the upstream is off you only
// serve what's cached. one job at a time in memory, a restart just means run it again.

const semver = require('semver');
const db = require('./db');
const policy = require('./policy');
const upstream = require('./registry/npm/upstream');
const pypi = require('./registry/pypi/upstream');
const ecosystems = require('./ecosystems');
const pypiVersion = require('./ecosystems/pypi/version');
const simple = require('./ecosystems/pypi/simple');
const log = require('./logger');

const ECOSYSTEMS = ['npm', 'pypi', 'oci', ...require('./registry/kinds').ids()];

// exact versions only. a range is not a shopping list: @tailwindcss/oxide-freebsd-x64 has
// 1337 versions (yes really), mostly nightlies, 1.6GB nobody wanted. warm guarantees what's written down
const MAX_TARBALLS = 2000;

let job = null;

function idle() {
  return { running: false, startedAt: null, finishedAt: null, by: null,
           total: 0, done: 0, cached: 0, already: 0, failed: 0, current: null, notes: [], errors: [] };
}

function status() {
  return job ? { ...job, notes: job.notes.slice(0, 50), errors: job.errors.slice(0, 50) } : idle();
}

function running() {
  return !!(job && job.running);
}

// exact versions from "4.1.12 || 4.2.0" (npm) or "==2.5.3 || ==2.5.4" (PyPI), or null
function pinsFor(range, ecosystem = 'npm') {
  const raw = String(range || '').trim();
  if (!raw) return null;
  const pins = [];
  for (const token of raw.split('||')) {
    const t = token.trim();
    if (ecosystem === 'oci') {
      // a tag or a digest. a tag glob names nothing in particular
      const ociName = require('./ecosystems/oci/name');
      if (!ociName.validTag(t) && !ociName.isDigest(t)) return null;
      pins.push(t);
    } else if (ecosystem === 'pypi') {
      const m = /^(?:==\s*)?([^\s,*<>=!~;]+)$/.exec(t);
      if (!m || !pypiVersion.valid(m[1])) return null;
      pins.push(m[1]);
    } else if (require('./registry/kinds').get(ecosystem)) {
      const exact = require('./registry/kinds').get(ecosystem).exactPins(t);
      if (!exact) return null;
      pins.push(...exact);
    } else {
      // semver.valid since prerelease tags can contain an x
      const version = semver.valid(t);
      if (!version) return null;
      pins.push(version);
    }
  }
  return [...new Set(pins)];
}

// can Cache now do anything with this range? exact pins, and for npm and PyPI any range or none at all (the newest
// version it allows, or the current release). an image tag pattern like 1.27.* names nothing the box can list
function cacheable(range, ecosystem = 'npm') {
  if (pinsFor(range, ecosystem)) return true;
  if (ecosystem === 'oci') return !String(range || '').trim();
  return true;
}

// no exact versions: the one release to cache for it. what npm install would pick with no range (the latest tag),
// the newest stable PyPI release, the newest version a range allows. null when nothing matches
function newestFor(ecosystem, range, versions, latest) {
  const r = String(range || '').trim();
  const kind = require('./registry/kinds').get(ecosystem);
  if (kind) return kind.version.maxSatisfying(versions, r);
  if (ecosystem === 'pypi') {
    const adapter = ecosystems.adapter('pypi');
    const ok = versions.filter((v) => pypiVersion.valid(v) && (r ? adapter.satisfies(v, r) : !pypiVersion.isPrerelease(v)));
    return ok.length ? ok.sort((a, b) => pypiVersion.compare(b, a))[0] : null;
  }
  if (!r) return latest && semver.valid(latest) ? latest : semver.maxSatisfying(versions, '*');
  try {
    return semver.maxSatisfying(versions, r);
  } catch (err) {
    return null;
  }
}

function notExact(rule) {
  return rule.version_range
    ? `${rule.version_range} is a range, not exact versions, so there is nothing definite to pull`
    : 'no version range, so there is nothing exact to pull';
}

// pins decide what to fetch, policy only gets a veto. checkVersion alone says yes to everything in blacklist mode
async function npmVersionsFor(rule) {
  let pins = pinsFor(rule.version_range, 'npm');

  const { doc } = await upstream.getPackument(rule.pattern, 'full');
  const published = doc.versions || {};
  if (!pins) {
    const newest = newestFor('npm', rule.version_range, Object.keys(published), doc['dist-tags'] && doc['dist-tags'].latest);
    if (!newest) return { versions: [], skipped: `nothing published matches ${rule.version_range || 'any version'}` };
    job.notes.push(`${rule.pattern}: ${rule.version_range ? `the newest version ${rule.version_range} allows` : 'any version, so the current release'}, ${newest}`);
    pins = [newest];
  }

  const versions = [];
  const missing = [];
  const blocked = [];
  for (const version of pins.sort(semver.rcompare)) {
    const meta = published[version];
    if (!meta) {
      missing.push(version);
      continue;
    }
    if (await require('./policy/killswitch').check('npm', rule.pattern, version)) {
      blocked.push(`${version} (on the kill switch)`);
      continue;
    }
    // judged for the rule's own application and environment, or a dev only rule would warm nothing
    const verdict = await policy.checkVersion(rule.pattern, version, undefined, { app: Number(rule.application_id) || 0, env: Number(rule.environment_id) || 0 });
    if (!verdict.allowed) {
      blocked.push(`${version} (${verdict.reason})`);
      continue;
    }
    versions.push({ version, dist: meta.dist });
  }
  return { versions, missing, blocked };
}

function sameRelease(a, b) {
  try {
    return pypiVersion.compare(a, b) === 0;
  } catch (err) {
    return false;
  }
}

// a PyPI release is every file of it: wheels for each platform plus the sdist. no telling
// which one a client needs, so all of them (and their metadata files, pip reads those first)
async function pypiVersionsFor(rule) {
  let pins = pinsFor(rule.version_range, 'pypi');
  if (!db.settings.getBool('pypi_enabled')) return { versions: [], skipped: 'PyPI is switched off in Settings' };

  const page = await pypi.getProject(rule.pattern);
  const files = (page.doc && page.doc.files) || [];
  const adapter = ecosystems.adapter('pypi');
  if (!pins) {
    const releases = [...new Set(files.map((f) => simple.releaseOf(f.filename, rule.pattern)).filter(Boolean))];
    const newest = newestFor('pypi', rule.version_range, releases);
    if (!newest) return { versions: [], skipped: `no release matches ${rule.version_range || 'any version'}` };
    job.notes.push(`${rule.pattern}: ${rule.version_range ? `the newest release ${rule.version_range} allows` : 'any version, so the current release'}, ${newest}`);
    pins = [newest];
  }

  const versions = [];
  const missing = [];
  const blocked = [];
  for (const pin of pins) {
    const matching = files
      .map((f) => ({ file: f, version: simple.releaseOf(f.filename, rule.pattern) }))
      .filter((x) => x.version && sameRelease(x.version, pin));
    if (!matching.length) {
      missing.push(pin);
      continue;
    }
    if (await require('./policy/killswitch').check('pypi', rule.pattern, pin)) {
      blocked.push(`${pin} (on the kill switch)`);
      continue;
    }
    const verdict = await policy.checkVersion(rule.pattern, pin, adapter, { app: Number(rule.application_id) || 0, env: Number(rule.environment_id) || 0 });
    if (!verdict.allowed) {
      blocked.push(`${pin} (${verdict.reason})`);
      continue;
    }
    versions.push({ version: pin, files: matching });
  }
  return { versions, missing, blocked };
}

// the newer types: the pins, or the newest listed version the range allows (the current release for no range)
async function kindVersionsFor(rule, eco) {
  const type = ecosystems.get(eco);
  if (type.setting && !db.settings.getBool(type.setting)) return { versions: [], skipped: `${type.name} is switched off in Settings` };
  const doc = await require('./registry/kinds').get(eco).versions(rule.pattern);
  let pins = pinsFor(rule.version_range, eco);
  if (!pins) {
    const newest = newestFor(eco, rule.version_range, doc.versions.filter((v) => v.listed).map((v) => v.version));
    if (!newest) return { versions: [], skipped: `no version matches ${rule.version_range || 'any version'}` };
    job.notes.push(`${doc.id}: ${rule.version_range ? `the newest version ${rule.version_range} allows` : 'any version, so the current release'}, ${newest}`);
    pins = [newest];
  }
  const adapter = ecosystems.adapter(eco);
  const versions = [];
  const missing = [];
  const blocked = [];
  for (const pin of pins) {
    if (!doc.versions.some((v) => v.version === pin)) {
      missing.push(pin);
      continue;
    }
    if (await require('./policy/killswitch').check(eco, doc.id, pin)) {
      blocked.push(`${pin} (on the kill switch)`);
      continue;
    }
    const verdict = await policy.checkVersion(doc.id, pin, adapter, { app: Number(rule.application_id) || 0, env: Number(rule.environment_id) || 0 });
    if (!verdict.allowed) {
      blocked.push(`${pin} (${verdict.reason})`);
      continue;
    }
    versions.push({ version: pin, id: doc.id });
  }
  return { versions, missing, blocked };
}

// an image tag or digest is one pull: the manifest, the platform images of a list, their config and layers
async function ociVersionsFor(rule) {
  // no tag named: latest, what a pull with no tag gets
  const pins = pinsFor(rule.version_range, 'oci') || (String(rule.version_range || '').trim() ? null : ['latest']);
  if (!pins) return { versions: [], skipped: notExact(rule) };
  if (!db.settings.getBool('oci_enabled')) return { versions: [], skipped: 'container images are switched off in Settings' };
  const versions = [];
  const blocked = [];
  const adapter = ecosystems.adapter('oci');
  for (const pin of pins) {
    if (await require('./policy/killswitch').check('oci', rule.pattern, pin)) {
      blocked.push(`${pin} (on the kill switch)`);
      continue;
    }
    const verdict = await policy.checkVersion(rule.pattern, pin, adapter, { app: Number(rule.application_id) || 0, env: Number(rule.environment_id) || 0 });
    if (!verdict.allowed) {
      blocked.push(`${pin} (${verdict.reason})`);
      continue;
    }
    versions.push({ version: pin });
  }
  return { versions, missing: [], blocked };
}

// platform images of a list past this are left, nobody ships more
const MAX_PLATFORMS = 64;

async function warmImage(repository, reference, spelled) {
  const ociName = require('./ecosystems/oci/name');
  const images = require('./registry/oci/upstream');
  const refs = require('./db/repositories/oci-refs');
  const top = await images.getManifest(repository, reference);
  job.already += top.cached ? 1 : 0;
  job.cached += top.cached ? 0 : 1;
  const platforms = [];
  if (Array.isArray(top.doc.manifests)) {
    const children = top.doc.manifests.map((m) => m && m.digest).filter((d) => ociName.isDigest(d)).slice(0, MAX_PLATFORMS);
    await refs.recordChildren(repository, top.digest, children);
    for (const child of children) {
      if (!job.running || ceiling()) return;
      const got = await images.getManifest(repository, child);
      job.already += got.cached ? 1 : 0;
      job.cached += got.cached ? 0 : 1;
      platforms.push(got);
    }
  } else {
    platforms.push(top);
  }
  for (const image of platforms) {
    const blobs = [
      ...(image.doc.config ? [image.doc.config] : []),
      ...(Array.isArray(image.doc.layers) ? image.doc.layers : [])
    ].map((b) => b && b.digest).filter((d) => ociName.isDigest(d));
    await refs.recordChildren(repository, image.digest, blobs);
    for (const blob of blobs) {
      if (!job.running || ceiling()) return;
      job.current = `${spelled}: ${blob.slice(0, 19)}`;
      await fetchOne(`${spelled} ${blob}`, () => images.getBlob(repository, blob));
    }
  }
}

function ceiling() {
  if (job.cached + job.already < MAX_TARBALLS) return false;
  job.notes.push(`stopped at the ${MAX_TARBALLS} file ceiling, run it again to carry on`);
  job.running = false;
  return true;
}

async function fetchOne(label, work) {
  try {
    const result = await work();
    if (result.cacheHit) job.already += 1;
    else job.cached += 1;
  } catch (err) {
    job.failed += 1;
    job.errors.push(`${label}: ${err.message}`);
  }
}

async function run(rules, actor) {
  job = { ...idle(), running: true, startedAt: new Date().toISOString(), by: actor, total: rules.length };

  for (const rule of rules) {
    if (!job.running) break;                       // canceled
    const eco = rule.ecosystem || 'npm';
    job.current = rule.pattern;
    try {
      const { versions, skipped, missing, blocked } = eco === 'pypi' ? await pypiVersionsFor(rule)
        : eco === 'oci' ? await ociVersionsFor(rule) : require('./registry/kinds').get(eco) ? await kindVersionsFor(rule, eco) : await npmVersionsFor(rule);
      if (skipped) job.notes.push(`${rule.pattern}: ${skipped}`);
      if (missing && missing.length) {
        job.notes.push(`${rule.pattern}: ${missing.join(', ')} not published upstream`);
      }
      if (blocked && blocked.length) {
        job.notes.push(`${rule.pattern}: ${blocked.join(', ')} not allowed, left alone`);
      }
      for (let i = 0; i < versions.length; i += 1) {
        if (!job.running || ceiling()) break;
        const { version, dist, files } = versions[i];
        const spelled = eco === 'pypi' ? `${rule.pattern}==${version}`
          : require('./registry/kinds').get(eco) ? require('./registry/kinds').get(eco).spell(versions[i].id, version)
          : eco === 'oci' ? `${rule.pattern}${version.startsWith('sha256:') ? '@' : ':'}${version}` : `${rule.pattern}@${version}`;
        // per version so the status line doesn't look frozen
        job.current = spelled + (versions.length > 1 ? ` (${i + 1} of ${versions.length})` : '');

        if (eco === 'oci') {
          try {
            await warmImage(rule.pattern, version, spelled);
          } catch (err) {
            job.failed += 1;
            job.errors.push(`${spelled}: ${err.message}`);
          }
        } else if (require('./registry/kinds').get(eco)) {
          // a version of a newer type is its files (a .nupkg, a pom and a jar), counted as one
          await fetchOne(spelled, async () => {
            const files = await require('./registry/kinds').get(eco).fetch(versions[i].id, version);
            return { cacheHit: files.every((f) => f.cacheHit) };
          });
        } else if (eco === 'pypi') {
          for (const { file, version: fileVersion } of files) {
            if (!job.running || ceiling()) break;
            job.current = `${spelled}: ${file.filename}`;
            await fetchOne(file.filename, () => pypi.getFile(rule.pattern, file.filename, fileVersion));
            if (file.coreMetadata) {
              await fetchOne(`${file.filename}.metadata`, () => pypi.getFile(rule.pattern, file.filename, fileVersion, { metadata: true }));
            }
          }
        } else {
          //dist from the packument we already have, saves a reparse per version
          await fetchOne(spelled, () => upstream.getTarball(rule.pattern, version, dist));
        }
      }
    } catch (err) {
      job.failed += 1;
      job.errors.push(`${rule.pattern}: ${err.message}`);
    }
    job.done += 1;
  }

  job.running = false;
  job.current = null;
  job.finishedAt = new Date().toISOString();
  log.info(`cache warm finished: ${job.cached} downloaded, ${job.already} already there, ${job.failed} failed`);
  return job;
}

// kicks off the job and returns right away. caller polls status() like an impatient kid in a car
function start(rules, actor) {
  if (running()) {
    const e = new Error('a cache warm is already running, wait for it to finish');
    e.status = 409;
    throw e;
  }
  if (require('./policy/mode').noNewNames()) {
    const e = new Error(`the registry is in ${require('./policy/mode').current()} mode, and a warm would fetch from upstream`);
    e.status = 409;
    throw e;
  }
  if (!upstream.upstreamEnabled()) {
    const e = new Error('the upstream registry is switched off, so there is nothing to download from');
    e.status = 409;
    throw e;
  }
  if (!db.settings.getBool('cache_tarballs')) {
    const e = new Error('keep tarballs on disk is off, so a warm would download and throw it all away');
    e.status = 409;
    throw e;
  }
  run(rules, actor).catch((err) => {
    log.error('cache warm blew up', err.message);
    if (job) {
      job.running = false;
      job.errors.push(err.message);
      job.finishedAt = new Date().toISOString();
    }
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

module.exports = { ECOSYSTEMS, start, status, cancel, running, pinsFor, cacheable, newestFor, MAX_TARBALLS };
