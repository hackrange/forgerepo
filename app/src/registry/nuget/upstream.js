// Talking to a NuGet v3 feed: its service index, the registration pages every version is listed on, and the packages.
// Author: Tim Rice
//
// the feed's own service index says where its flat container and registrations live, so nuget.org, Azure Artifacts and
// GitHub Packages all work the same. a package is summed up once (its real id, every version, listed or not, when it was
// published, its license and dependencies) and everything this box answers comes from that summary

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const db = require('../../db');
const config = require('../../config');
const safefetch = require('../../security/safefetch');
const upstreams = require('../shared/upstreams');
const mirrorOptions = require('../shared/mirror-options');
const artifacts = require('../../storage/artifacts');
const docs = require('../../db/repositories/package-documents');
const nugetName = require('../../ecosystems/nuget/name');
const nugetVersion = require('../../ecosystems/nuget/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'nuget';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (NuGet)`;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 1024 * 1024 * 1024;
const MAX_PAGES = 200;
const MAX_VERSIONS = 10000;
const INDEX_TTL_MS = 60 * 60 * 1000;
// every .nupkg is a zip, and a zip starts PK 3 4
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
// the registration flavors a feed can offer, the one with semver 2 and gzip first
const REGISTRATION_TYPES = ['RegistrationsBaseUrl/3.6.0', 'RegistrationsBaseUrl/Versioned', 'RegistrationsBaseUrl/3.4.0', 'RegistrationsBaseUrl/3.0.0-rc', 'RegistrationsBaseUrl/3.0.0-beta', 'RegistrationsBaseUrl'];

const workDir = path.join(config.cacheDir, 'tmp');
const indexes = new Map();

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

// the feed's address as people paste it: https://api.nuget.org, .../v3/index.json, an Azure Artifacts feed url
function indexUrl(up) {
  const u = String(up.url).replace(/\/+$/, '');
  return /\.json$/i.test(u) ? u : `${u}/v3/index.json`;
}

const slash = (u) => (String(u).endsWith('/') ? String(u) : `${u}/`);

// what the feed's own service index says: where the flat container and the registrations are. an address it hands
// back has to be https (or http when the feed itself is), anything else is not followed
async function endpoints(up) {
  const key = `${up.name}\n${up.url}`;
  const held = indexes.get(key);
  if (held && held.until > Date.now()) return held.value;
  const url = indexUrl(up);
  const res = await safefetch.request(url, { headers: upstreams.headersFor(up, { accept: 'application/json', 'user-agent': USER_AGENT }), timeoutMs: 30000, maxBytes: MAX_JSON_BYTES });
  if (!res.ok) throw httpError(502, `the ${up.name} feed said ${res.status} for its service index`);
  let doc;
  try {
    doc = await res.json();
  } catch (err) {
    throw httpError(502, `the ${up.name} feed answered its service index with something that is not json`);
  }
  const resources = Array.isArray(doc && doc.resources) ? doc.resources : [];
  const find = (types) => {
    for (const t of types) {
      const r = resources.find((x) => x && x['@type'] === t && typeof x['@id'] === 'string');
      if (r) return r['@id'];
    }
    return null;
  };
  const scheme = new URL(url).protocol;
  const ok = (u) => {
    try {
      const p = new URL(u).protocol;
      return p === 'https:' || (p === 'http:' && scheme === 'http:');
    } catch (err) {
      return false;
    }
  };
  const flat = find(['PackageBaseAddress/3.0.0']);
  const registration = find(REGISTRATION_TYPES);
  if (!flat || !registration || !ok(flat) || !ok(registration)) {
    throw httpError(502, `the ${up.name} feed's service index does not name a package address and a registration address this box can use`);
  }
  const value = { flat: slash(flat), registration: slash(registration) };
  indexes.set(key, { value, until: Date.now() + INDEX_TTL_MS });
  return value;
}

function checkUsable(up, id) {
  if (!up) throw httpError(502, `no feed is set up to serve ${id}. Add a NuGet registry under Settings, Registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} feed, which serves ${id}, is switched off`);
}

async function getJson(up, url, what) {
  const res = await safefetch.request(url, { headers: upstreams.headersFor(up, { accept: 'application/json', 'user-agent': USER_AGENT }), timeoutMs: 30000, maxBytes: MAX_JSON_BYTES });
  if (res.status === 404) throw httpError(404, `${what} is not on the ${up.name} feed`);
  if (!res.ok) throw httpError(502, `the ${up.name} feed said ${res.status} for ${what}`);
  try {
    return await res.json();
  } catch (err) {
    throw httpError(502, `the ${up.name} feed answered ${what} with something that is not json`);
  }
}

// a page the index points at must be on the same host as the registrations, nothing the feed says sends us elsewhere
function sameHost(base, url) {
  try {
    return new URL(url).origin === new URL(base).origin;
  } catch (err) {
    return false;
  }
}

function compactDeps(groups) {
  if (!Array.isArray(groups)) return [];
  return groups.slice(0, 50).map((g) => ({
    framework: typeof g.targetFramework === 'string' ? g.targetFramework.slice(0, 64) : '',
    dependencies: (Array.isArray(g.dependencies) ? g.dependencies : []).slice(0, 200)
      .filter((d) => d && nugetName.valid(d.id))
      .map((d) => ({ id: d.id, range: typeof d.range === 'string' ? d.range.slice(0, 128) : '' }))
  }));
}

// one package summed up from its registration: its real id and every version with what matters about it
async function fetchSummary(up, folded) {
  const where = await endpoints(up);
  const index = await getJson(up, `${where.registration}${encodeURIComponent(folded)}/index.json`, folded);
  const pages = Array.isArray(index && index.items) ? index.items.slice(0, MAX_PAGES) : [];
  const entries = [];
  for (const page of pages) {
    let items = Array.isArray(page && page.items) ? page.items : null;
    if (!items) {
      const at = page && page['@id'];
      if (typeof at !== 'string' || !sameHost(where.registration, at)) continue;
      items = ((await getJson(up, at, `${folded}, one page of its versions`)) || {}).items || [];
    }
    for (const item of items) {
      const c = item && item.catalogEntry;
      if (c && typeof c === 'object') entries.push(c);
    }
  }
  const id = (entries.find((c) => typeof c.id === 'string' && nugetName.fold(c.id) === folded) || {}).id;
  if (!id) throw httpError(404, `${folded} is not on the ${up.name} feed`);
  const versions = [];
  const seen = new Set();
  for (const c of entries.slice(0, MAX_VERSIONS)) {
    if (nugetName.fold(c.id) !== folded) continue;
    const v = nugetVersion.normalize(c.version);
    if (!v || seen.has(v)) continue;
    seen.add(v);
    versions.push({
      version: v,
      listed: c.listed !== false,
      // where the feed says what this version really is. the hash lives here, not in the registration
      catalog: typeof c['@id'] === 'string' && sameHost(where.registration, c['@id']) ? c['@id'] : null,
      published: typeof c.published === 'string' && !c.published.startsWith('1900') ? c.published : null,
      license: typeof c.licenseExpression === 'string' ? c.licenseExpression.slice(0, 255) : null,
      deprecated: c.deprecation && typeof c.deprecation === 'object' ? String(c.deprecation.message || (c.deprecation.reasons || []).join(', ') || 'deprecated').slice(0, 500) : null,
      deps: compactDeps(c.dependencyGroups)
    });
  }
  versions.sort((a, b) => nugetVersion.compare(a.version, b.version));
  return { id, versions };
}

// the summary of a package, from the cache while it is fresh, from the feed otherwise. { doc, cacheHit, stale }
async function summary(rawId) {
  if (!nugetName.valid(rawId)) throw httpError(400, 'that is not a NuGet package id');
  const folded = nugetName.fold(rawId);
  // a reserved id is only what was pushed here, never a copy from outside, however old
  const reserved = await require('../../policy/private-names').reservedBy(ECO, folded);
  if (reserved) {
    const own = await docs.get(ECO, folded, 'summary');
    if (own && own.source === require('../shared/published').SOURCE) return { doc: own.doc, cacheHit: true, stale: false };
    throw httpError(404, `${folded} is reserved (${reserved.pattern}) for packages pushed to this feed, and nothing is pushed under it yet. It is never fetched from an upstream`);
  }
  const up = await upstreams.forPackage(folded, ECO);
  const held = await docs.get(ECO, folded, 'summary');
  const usable = held && up && upstreams.sameSource(held.source, up) ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { doc: usable.doc, cacheHit: true, stale: false };
  if (!upstreamEnabled()) {
    if (held) return { doc: held.doc, cacheHit: true, stale: true };
    throw httpError(503, `${mode.offlineReason()} and ${folded} is not in the cache`);
  }
  if (!held && mode.noNewNames()) throw mode.newName(folded);
  checkUsable(up, folded);
  try {
    const doc = await fetchSummary(up, folded);
    await docs.put(ECO, folded, 'summary', doc, up.name);
    return { doc, cacheHit: false, stale: false };
  } catch (err) {
    // down or broken: a summary checked recently enough still answers. a 404 is an answer, never covered up
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} feed failed for ${folded}, answering from the cache`, err.message);
      return { doc: usable.doc, cacheHit: true, stale: true };
    }
    throw err;
  }
}

const fileName = (id, version) => `${nugetName.fold(id)}.${nugetVersion.normalize(version)}.nupkg`;

// what the feed publishes about the exact bytes of a version: { sha512, size } from its catalog entry, or null when
// the feed keeps no catalog (plenty do not, and then there is nothing to check against)
async function publishedHash(up, folded, v) {
  const held = await docs.get(ECO, folded, 'summary').catch(() => null);
  const entry = held && held.doc && Array.isArray(held.doc.versions) ? held.doc.versions.find((x) => x.version === v) : null;
  if (!entry || !entry.catalog) return null;
  const where = await endpoints(up);
  if (!sameHost(where.registration, entry.catalog)) return null;
  let leaf;
  try {
    leaf = await getJson(up, entry.catalog, `${folded} ${v}, what the feed says about it`);
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
  const algorithm = String((leaf && leaf.packageHashAlgorithm) || '').toUpperCase();
  const hash = leaf && typeof leaf.packageHash === 'string' ? leaf.packageHash : '';
  if (algorithm !== 'SHA512' || !hash) return null;
  return { sha512: hash, size: Number.isSafeInteger(leaf.packageSize) ? leaf.packageSize : null };
}

// a .nupkg, from the store or the feed. streamed to disk, hashed on the way, and it has to be a zip
async function getPackage(id, version) {
  const v = nugetVersion.normalize(version);
  const filename = fileName(id, v);
  const folded = nugetName.fold(id);
  // a reserved id is only what was pushed here. a copy fetched from outside before it was reserved is never served
  const reserved = await require('../../policy/private-names').reservedBy(ECO, folded);
  const held = await artifacts.locate(ECO, id, v, filename);
  if (held && (!reserved || held.upstream === require('../shared/published').SOURCE)) {
    // a copy from a feed this id is no longer routed to is not this id anymore
    const routed = reserved || (await upstreams.fromRoute(held.upstream, folded, ECO));
    if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
    if (!upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, folded, ECO));
  }
  if (reserved) throw httpError(404, `${filename} is reserved and was never pushed here. It is never fetched from an upstream`);
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(folded, ECO);
  checkUsable(up, folded);
  const where = await endpoints(up);
  const url = `${where.flat}${encodeURIComponent(folded)}/${encodeURIComponent(v)}/${encodeURIComponent(filename)}`;
  const res = await safefetch.request(url, { headers: upstreams.headersFor(up, { accept: '*/*', 'user-agent': USER_AGENT }), timeoutMs: 600000, maxBytes: MAX_PACKAGE_BYTES, stream: true });
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} feed said ${res.status} for ${filename}`);
  }
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `nuget.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  const sha512 = crypto.createHash('sha512');
  const want = await publishedHash(up, folded, v);
  let size = 0;
  let head = Buffer.alloc(0);
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        sha256.update(chunk);
        sha512.update(chunk);
        size += chunk.length;
        if (head.length < 4) head = Buffer.concat([head, chunk.subarray(0, 4 - head.length)]);
      });
      res.stream.on('error', (err) => {
        out.destroy();
        reject(err);
      });
      out.on('error', reject);
      out.on('finish', resolve);
      res.stream.pipe(out);
    });
    // a nupkg is a zip. an html error page or anything else is not kept
    if (!head.equals(ZIP_MAGIC)) throw httpError(502, `the ${up.name} feed answered ${filename} with something that is not a package`);
    // and it has to be the bytes the feed says it is
    if (want) {
      const got = sha512.digest('base64');
      if (got !== want.sha512) {
        log.error(`${filename} came back with a different SHA512 than the ${up.name} feed publishes, not keeping it`);
        throw httpError(502, `${filename} does not match the SHA512 the ${up.name} feed publishes for it, so it was not kept`);
      }
      if (want.size !== null && want.size !== size) {
        throw httpError(502, `${filename} is ${size} bytes, and the ${up.name} feed says it is ${want.size}, so it was not kept`);
      }
    } else if (mirrorOptions.requiresHash(up)) {
      log.error(`${filename} has no SHA512 published for it (the ${up.name} feed keeps no catalog entry for it), so there was nothing to check it against. refusing it`);
      throw httpError(502, `the ${up.name} feed publishes no hash for ${filename}, so it can not be checked and was not kept`);
    }
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: id, version: v, filename, upstream: up.name }, { tmp, sha256: sha256.digest('hex') });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } catch (err) {
    if (err.status) throw err;
    throw httpError(502, `the download of ${filename} did not complete: ${err.message}`);
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

const open = (got) => artifacts.open(got);

// the id as the feed spells it (Newtonsoft.Json), from the summary this box keeps. as typed when it has none yet.
// the advisory feed minds the case, everything else here ignores it
async function canonical(raw) {
  const held = await docs.get(ECO, nugetName.fold(raw), 'summary').catch(() => null);
  return held && held.doc && typeof held.doc.id === 'string' ? held.doc.id : String(raw || '').trim();
}

module.exports = { ECO, MAX_PACKAGE_BYTES, indexUrl, endpoints, upstreamEnabled, summary, canonical, fileName, getPackage, open };
