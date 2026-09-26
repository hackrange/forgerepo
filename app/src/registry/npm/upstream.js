// Talks to the public registry and keeps the cache toasty.
// only file allowed to call out to the internet
// Author: Tim Rice

const fsp = require('fs/promises');
const semver = require('semver');
const db = require('../../db');
const cache = require('./cache');
const upstreams = require('../shared/upstreams');
const mirrorOptions = require('../shared/mirror-options');
const safefetch = require('../../security/safefetch');
const log = require('../../logger');
const config = require('../../config');

const USER_AGENT = `ForgeRepo/${config.version} (+private registry mirror)`;

// npm name rules, roughly. uppercase HAS to stay allowed, old stuff like JSONStream still uses it
const NAME_RE = /^(?:@[A-Za-z0-9-][A-Za-z0-9._-]*\/)?[A-Za-z0-9-][A-Za-z0-9._-]*$/;

function validName(name) {
  if (!name || name.length > 214) return false;
  if (name.startsWith('.') || name.startsWith('_')) return false;
  return NAME_RE.test(name);
}

// default registry's address, display only. routing goes through upstreams.forPackage
async function upstreamBase() {
  const up = await upstreams.defaultUpstream();
  return up ? up.url : String(config.upstreamRegistry).replace(/\/+$/, '');
}

// the kill switch. covers every upstream, a switch some of them ignore isn't a switch
function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !require('../../policy/mode').lockdown();
}

function offline(what) {
  const e = new Error(`${require('../../policy/mode').offlineReason()} and ${what} is not in the cache`);
  e.status = 503;
  return e;
}

// cached from a registry this name doesn't use anymore, and we can't refetch
function sourceMoved(what, was, up) {
  const e = new Error(
    `${what} is cached from ${was || 'an unknown registry'} but now comes from `
    + `${up ? up.name : 'nowhere'}, and the upstream registries are switched off, so it cannot be refetched`
  );
  e.status = 503;
  return e;
}

function noRoute(name) {
  const e = new Error(`no upstream registry is configured to serve ${name}`);
  e.status = 502;
  return e;
}

// disabled upstream means STOP, not "try somewhere else"
function checkUsable(up, name) {
  if (!up) throw noRoute(name);
  if (!up.enabled) {
    const e = new Error(`the ${up.name} registry, which serves ${name}, is switched off`);
    e.status = 503;
    throw e;
  }
}

function headers(extra, up) {
  const h = { 'user-agent': USER_AGENT, ...(extra || {}) };
  const token = up && up.token ? up.token : '';
  if (token) h.authorization = `Bearer ${token}`;
  return h;
}

// upstream url for a package. scoped names get their slash encoded
function metaUrl(name, up) {
  return `${up.url}/${name.replace('/', '%2f')}`;
}

// safefetch checks the real address, redirects and size. see safefetch.js
async function fetchWithTimeout(url, options, ms) {
  return safefetch.request(url, { headers: (options && options.headers) || {}, timeoutMs: ms || 30000 });
}

// what a registry sends has to look like a packument before anything reads it or keeps it. a string where versions should be
// sailed through as {"0": "x"}, since Object.entries walks strings too
const plain = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
function packumentOrRefuse(doc, name) {
  const broken = !plain(doc)
    || (doc.versions !== undefined && (!plain(doc.versions) || Object.values(doc.versions).some((meta) => !plain(meta))))
    || (doc['dist-tags'] !== undefined && !plain(doc['dist-tags']))
    || (doc.time !== undefined && !plain(doc.time));
  if (broken) {
    const e = new Error(`the upstream registry sent metadata for ${name} that is not shaped like a package document`);
    e.status = 502;
    throw e;
  }
  return doc;
}

// stampede control, for when the whole CI fleet wants the same package at the same second
const inFlight = new Map();

function coalesce(key, fn) {
  if (inFlight.has(key)) return inFlight.get(key);
  const p = fn().finally(() => inFlight.delete(key));
  inFlight.set(key, p);
  return p;
}

// packument, cache first. returns { doc, cacheHit, stale }
// fresh metadata vs what we recorded for versions we hold. off the request path
function checkIntegrity(name, doc, source) {
  require('../../policy/integrity').checkNpm(name, doc, source)
    .catch((err) => log.warn(`integrity check on ${name} failed`, err.message));
}

async function refuseReserved(ecosystem, name) {
  const hit = await require('../../policy/private-names').reservedBy(ecosystem, name);
  if (!hit) return;
  const e = new Error(`${name} is reserved (${hit.pattern}) for packages published on this registry, and nothing like that is published here. It is never fetched from an upstream`);
  e.status = 404;
  e.reserved = true;
  throw e;
}

async function getPackument(name, variant) {
  const key = `meta:${variant}:${name}`;
  return coalesce(key, async () => {
    const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
    const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
    // reserved names are only what is published here, never a copy from outside, however old
    if (await require('../../policy/private-names').isPrivate('npm', name)) {
      const own = await cache.getPackument(name, variant);
      if (own && require('../shared/published').isPublished(own)) return { doc: own.doc, cacheHit: true, stale: false };
      await refuseReserved('npm', name);
    }
    const up = await upstreams.forPackage(name);
    const stored = await cache.getPackument(name, variant);
    // degraded or lockdown: a name this box has never held anything for is not fetched
    if (!stored && require('../../policy/mode').noNewNames() && !(await cache.getPackument(name, variant === 'full' ? 'abbreviated' : 'full'))) {
      throw require('../../policy/mode').newName(name);
    }

    // a copy from a registry that no longer serves this name is never the answer. refetch or refuse
    const cached = stored && upstreams.sameSource(stored.source, up) ? stored : null;
    if (stored && !cached && !upstreamEnabled()) throw sourceMoved(name, stored.source, up);
    if (stored && !cached) {
      log.warn(`${name} was cached from ${stored.source || 'an unknown registry'},`,
        `refetching it from ${up ? up.name : 'nowhere'}`);
    }

    if (cached && Date.now() - cached.fetchedAt.getTime() < ttl) {
      return { doc: cached.doc, cacheHit: true, stale: false };
    }

    // locked down, cached is all we've got whatever its age
    if (!upstreamEnabled()) {
      if (cached) return { doc: cached.doc, cacheHit: true, stale: true, offline: true };
      // nothing can be fetched, so the other shape will do. npm reads what it needs from either
      const other = await cache.getPackument(name, variant === 'full' ? 'abbreviated' : 'full');
      if (other && upstreams.sameSource(other.source, up)) return { doc: other.doc, cacheHit: true, stale: true, offline: true };
      throw offline(name);
    }

    checkUsable(up, name);

    const accept =
      variant === 'abbreviated'
        ? 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*'
        : 'application/json';

    const extra = { accept };
    if (cached && cached.etag) extra['if-none-match'] = cached.etag;

    let res;
    try {
      res = await fetchWithTimeout(metaUrl(name, up), { headers: headers(extra, up) }, 30000);
    } catch (err) {
      // upstream down or blocked. serve what we have (if not too stale) instead of breaking the build
      if (cached && Date.now() - cached.fetchedAt.getTime() < staleOk) {
        log.warn('upstream unreachable, serving stale metadata for', name, err.message);
        return { doc: cached.doc, cacheHit: true, stale: true };
      }
      const e = new Error(`cannot reach the upstream registry: ${err.message}`);
      e.status = 502;
      throw e;
    }

    if (res.status === 304 && cached) {
      await cache.touchPackumentTime(name, variant);
      return { doc: cached.doc, cacheHit: true, stale: false };
    }

    if (res.status === 404) {
      // ONLY if this upstream opted in. off by default, that's the dependency confusion hole
      if (up.fallback && !up.isDefault) {
        const fallback = await upstreams.defaultUpstream();
        if (fallback && fallback.enabled && fallback.name !== up.name) {
          log.info(`${name} is not on ${up.name}, asking ${fallback.name} as well`);
          const second = await fetchWithTimeout(
            metaUrl(name, fallback), { headers: headers({ accept }, fallback) }, 30000);
          if (second.ok) {
            const doc = packumentOrRefuse(await second.json(), name);
            await cache.putPackument(name, variant, doc, second.headers.get('etag'), fallback.name);
            checkIntegrity(name, doc, fallback.name);
            return { doc, cacheHit: false, stale: false };
          }
        }
      }
      const e = new Error(`package not found on the ${up.name} registry`);
      e.status = 404;
      throw e;
    }

    if (!res.ok) {
      if (cached && Date.now() - cached.fetchedAt.getTime() < staleOk) {
        log.warn(`upstream returned ${res.status} for ${name}, serving stale metadata`);
        return { doc: cached.doc, cacheHit: true, stale: true };
      }
      const e = new Error(`upstream registry said ${res.status}`);
      e.status = 502;
      throw e;
    }

    const doc = packumentOrRefuse(await res.json(), name);
    await cache.putPackument(name, variant, doc, res.headers.get('etag'), up.name);
    checkIntegrity(name, doc, up.name);
    return { doc, cacheHit: false, stale: false };
  });
}

// options.serve: the caller sends the bytes, so an unkept download is lent to it as a temp file it deletes after sending.
// without it, an unkept download is thrown away as soon as it has been checked
async function getTarball(name, version, distInfo, options = {}) {
  if (await require('../../policy/private-names').isPrivate('npm', name)) {
    const own = await cache.getTarball(name, version);
    if (own && require('../shared/published').isPublished(own)) {
      await cache.touchTarball(name, version);
      return { ...own, cacheHit: true };
    }
    await refuseReserved('npm', name);
  }
  const up = await upstreams.forPackage(name);
  const usable = (file) => file && upstreams.sameSource(file.source, up);

  const hit = await cache.getTarball(name, version);
  if (usable(hit)) {
    await cache.touchTarball(name, version);
    return { ...hit, cacheHit: true };
  }
  if (hit && !upstreamEnabled()) throw sourceMoved(`${name}@${version}`, hit.source, up);
  if (hit) {
    log.warn(`${name}@${version} was downloaded from ${hit.source || 'an unknown registry'},`,
      `fetching it again from ${up ? up.name : 'nowhere'}`);
  }

  // scan before serve can only hold a file it kept, so it keeps them whatever the cache setting says
  const keep = db.settings.getBool('cache_tarballs')
    || (db.settings.getBool('malware_scanning') && db.settings.getBool('malware_scan_before_serve'));
  const fetchIt = async () => {
    // check again, someone else might have finished downloading while we waited in line
    const second = await cache.getTarball(name, version);
    if (usable(second)) return { ...second, cacheHit: true };

    if (!upstreamEnabled()) throw offline(`${name}@${version}`);
    checkUsable(up, name);

    let dist = distInfo;
    if (!dist || !dist.tarball) {
      const { doc } = await getPackument(name, 'full');
      const meta = doc.versions && doc.versions[version];
      if (!meta || !meta.dist) {
        const e = new Error('that version does not exist upstream');
        e.status = 404;
        throw e;
      }
      dist = meta.dist;
    }

    // only ever download from the registry this package is routed to
    const url = rewriteToUpstream(dist.tarball, name, version, up);
    // streamed to disk and hashed on the way, a big tarball costs disk space rather than the box's memory
    const res = await safefetch.request(url, { headers: headers({ accept: 'application/octet-stream' }, up), timeoutMs: 120000, stream: true });
    if (!res.ok) {
      if (res.stream) res.stream.resume();
      const e = new Error(`upstream returned ${res.status} for the tarball`);
      e.status = res.status === 404 ? 404 : 502;
      throw e;
    }

    let got;
    try {
      got = await cache.spoolTarball(res.stream, name, version);
    } catch (err) {
      const e = new Error(`the tarball download did not complete: ${err.message}`);
      e.status = 502;
      throw e;
    }
    let lent = false;
    try {
      if (!dist.integrity && !dist.shasum && mirrorOptions.requiresHash(up)) {
        const e = new Error(`the ${up.name} registry publishes no checksum for ${name}@${version}, so it can not be checked and was not kept`);
        e.status = 502;
        throw e;
      }
      if (!cache.spooledMatches(got, dist.integrity, dist.shasum)) {
        log.error('checksum mismatch on', `${name}@${version}`, 'refusing to cache it');
        const e = new Error('the tarball checksum did not match what the registry published');
        e.status = 502;
        throw e;
      }
      if (keep) {
        const saved = await cache.putTarballFile(name, version, got, dist.integrity || null, up.name);
        await cache.touchTarball(name, version);
        return { ...saved, cacheHit: false };
      }
      if (options.serve) {
        lent = true;
        return { file: got.tmp, sha256: got.sha256, size: got.size, cacheHit: false, temporary: true };
      }
      return { sha256: got.sha256, size: got.size, cacheHit: false };
    } finally {
      // the blob store adopted it, or it was refused, or nobody is sending it: either way the temp file is done with
      if (!lent) await fsp.unlink(got.tmp).catch(() => {});
    }
  };

  // share a download only when it is kept, an unkept file belongs to the one request that deletes it after sending
  return keep ? coalesce(`tgz:${name}@${version}`, fetchIt) : fetchIt();
}

// never trust the host in a published tarball url, always use the routed registry
function rewriteToUpstream(tarballUrl, name, version, up) {
  const base = up.url;
  try {
    const u = new URL(tarballUrl);
    return `${base}${u.pathname}${u.search || ''}`;
  } catch (err) {
    const short = name.includes('/') ? name.split('/')[1] : name;
    return `${base}/${name}/-/${short}-${version}.tgz`;
  }
}

// ask every enabled upstream. one that's down gets skipped
async function search(text, size) {
  // search is how new names get found, so degraded turns it off too
  if (!upstreamEnabled() || require('../../policy/mode').noNewNames()) {
    const e = new Error(require('../../policy/mode').noNewNames()
      ? `the registry is in ${require('../../policy/mode').current()} mode, so search is unavailable`
      : 'the upstream registry is switched off, so search is unavailable');
    e.status = 503;
    throw e;
  }

  // npm search, npm registries. a PyPI index would just stare blankly at this
  const list = (await upstreams.all('npm')).filter((u) => u.enabled);
  if (!list.length) {
    const e = new Error('no upstream registry is switched on');
    e.status = 502;
    throw e;
  }

  const results = await Promise.all(list.map(async (up) => {
    const url = `${up.url}/-/v1/search?text=${encodeURIComponent(text)}&size=${size || 20}`;
    try {
      const res = await fetchWithTimeout(url, { headers: headers({ accept: 'application/json' }, up) }, 20000);
      if (!res.ok) throw new Error(`said ${res.status}`);
      return { up, body: await res.json() };
    } catch (err) {
      log.warn(`search on ${up.name} failed, leaving it out:`, err.message);
      return null;
    }
  }));

  const answered = results.filter(Boolean);
  if (!answered.length) {
    const e = new Error('search failed on every upstream registry');
    e.status = 502;
    throw e;
  }

  // whichever upstream owns the name wins, no dupes
  const seen = new Map();
  for (const { up, body } of answered) {
    for (const obj of (body && body.objects) || []) {
      const pkgName = obj.package && obj.package.name;
      if (!pkgName) continue;
      const owner = await upstreams.forPackage(pkgName);
      if (owner && owner.name !== up.name) continue;
      // a public package under one of our reserved names is exactly what must not be suggested
      if (await require('../../policy/private-names').isPrivate('npm', pkgName)) continue;
      if (!seen.has(pkgName)) seen.set(pkgName, obj);
    }
  }

  return { objects: [...seen.values()].slice(0, size || 20) };
}

// walks a dependency tree, capped because some trees are enormous
async function resolveTree(name, range, opts) {
  const options = { depth: 12, max: 1500, dev: false, ...(opts || {}) };
  const seen = new Map();
  const queue = [{ name, range: range || 'latest', depth: 0, via: null }];
  const problems = [];

  while (queue.length && seen.size < options.max) {
    const item = queue.shift();
    if (!validName(item.name)) continue;

    let doc;
    try {
      doc = (await getPackument(item.name, 'abbreviated')).doc;
    } catch (err) {
      problems.push({ name: item.name, error: err.message });
      continue;
    }

    const version = pickVersion(doc, item.range);
    if (!version) {
      problems.push({ name: item.name, error: `nothing matches ${item.range}` });
      continue;
    }

    const key = `${item.name}@${version}`;
    if (seen.has(key)) continue;
    seen.set(key, { name: item.name, version, depth: item.depth, via: item.via });

    if (item.depth >= options.depth) continue;

    const meta = doc.versions[version] || {};
    const deps = { ...(meta.dependencies || {}) };
    if (options.dev && item.depth === 0) Object.assign(deps, meta.devDependencies || {});
    for (const [dep, depRange] of Object.entries(deps)) {
      queue.push({ name: dep, range: depRange, depth: item.depth + 1, via: key });
    }
  }

  return { packages: [...seen.values()], problems, truncated: seen.size >= options.max };
}

function pickVersion(doc, range) {
  const tags = doc['dist-tags'] || {};
  if (!range || range === 'latest' || range === '*' || range === '') {
    return tags.latest || Object.keys(doc.versions || {}).sort(semver.rcompare)[0] || null;
  }
  if (tags[range]) return tags[range];
  const list = Object.keys(doc.versions || {});
  try {
    return semver.maxSatisfying(list, range, { includePrerelease: false }) || null;
  } catch (err) {
    return null;
  }
}

module.exports = {
  packumentOrRefuse,
  validName,
  getPackument,
  getTarball,
  search,
  resolveTree,
  pickVersion,
  upstreamBase,
  upstreamEnabled
};
