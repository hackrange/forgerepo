// Talking to a Maven repository: a package's maven-metadata.xml, and its files with the checksums they are published with.
// Author: Tim Rice
//
// Maven Central, Nexus, Artifactory and the rest all lay packages out the same way, so a repository is just a base
// address. a file is streamed to disk and hashed on the way in, and when the repository publishes a .sha1 next to it
// the bytes have to match it or they are not kept. that is Maven's own integrity check, done before anything is served

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
const mavenName = require('../../ecosystems/maven/name');
const mavenVersion = require('../../ecosystems/maven/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'maven';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (Maven)`;
const MAX_METADATA_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_VERSIONS = 10000;
// how many of the newest versions get their publish time read, for cooling off. the rest are old news
const TIMED = 5;

const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const base = (up) => String(up.url).replace(/\/+$/, '');

function checkUsable(up, name) {
  if (!up) throw httpError(502, `no repository is set up to serve ${name}. Add a Maven registry under Settings, Registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} repository, which serves ${name}, is switched off`);
}

const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

// the text inside every <tag>...</tag>, for the few plain elements maven-metadata.xml has. no entities, no nesting
function texts(xml, tag) {
  const out = [];
  const re = new RegExp(`<${tag}>\\s*([^<>]{1,200}?)\\s*</${tag}>`, 'g');
  let m;
  while ((m = re.exec(xml)) && out.length < MAX_VERSIONS) out.push(m[1]);
  return out;
}

function parseMetadata(xml, name) {
  const c = mavenName.split(name);
  const group = texts(xml, 'groupId')[0];
  const artifact = texts(xml, 'artifactId')[0];
  if ((group && group !== c.groupId) || (artifact && artifact !== c.artifactId)) {
    throw httpError(502, `the repository answered ${name} with the metadata of ${group}:${artifact}`);
  }
  const versioning = (/<versioning>([\s\S]*?)<\/versioning>/.exec(xml) || [])[1] || '';
  const listed = (/<versions>([\s\S]*?)<\/versions>/.exec(versioning) || [])[1] || '';
  const versions = [...new Set(texts(listed, 'version').filter((v) => mavenVersion.valid(v) && !mavenVersion.isSnapshot(v)))];
  versions.sort(mavenVersion.compare);
  const lastUpdated = (texts(versioning, 'lastUpdated')[0] || '').replace(/\D/g, '').slice(0, 14);
  return { name, versions, lastUpdated };
}

// the Last-Modified of a version's pom, the nearest thing Maven has to a publish time
async function publishedAt(up, name, v) {
  const url = `${base(up)}/${mavenName.pathOf(name)}/${encodeURIComponent(v)}/${encodeURIComponent(mavenName.split(name).artifactId)}-${encodeURIComponent(v)}.pom`;
  try {
    const res = await safefetch.request(url, { method: 'HEAD', headers: headers(up), timeoutMs: 15000, maxBytes: 1024 });
    const at = res.ok && res.headers.get('last-modified');
    return at && Number.isFinite(Date.parse(at)) ? new Date(at).toISOString() : null;
  } catch (err) {
    return null;
  }
}

// a package's version list, from the cache while it is fresh. { doc, cacheHit, stale }. doc.times holds the publish
// times read so far, for the newest versions only and only when cooling off wants them
// what was deployed here, as a version list. a reserved coordinate is only ever this
async function deployed(name) {
  const own = await require('../../db/repositories/package-documents').get(ECO, name, require('../shared/published').KIND).catch(() => null);
  if (!own || !own.doc || !Array.isArray(own.doc.versions)) return null;
  const versions = own.doc.versions.map((v) => v.version).filter((v) => mavenVersion.valid(v)).sort(mavenVersion.compare);
  return {
    versions,
    times: Object.fromEntries(own.doc.versions.map((v) => [v.version, v.published || null])),
    lastUpdated: own.doc.lastUpdated || null
  };
}

async function metadata(name) {
  if (!mavenName.valid(name)) throw httpError(400, 'that is not a Maven groupId:artifactId');
  if (await require('../../policy/private-names').isPrivate(ECO, name)) {
    const mine = await deployed(name);
    if (mine && mine.versions.length) return { doc: mine, cacheHit: true, stale: false };
    throw httpError(404, `${name} is a reserved coordinate and nothing has been deployed to it yet. It is never fetched from an upstream`);
  }
  const up = await upstreams.forPackage(name, ECO);
  const held = await docs.get(ECO, name, 'summary');
  const usable = held && up && upstreams.sameSource(held.source, up) ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { doc: usable.doc, cacheHit: true, stale: false };
  if (!upstreamEnabled()) {
    if (held) return { doc: held.doc, cacheHit: true, stale: true };
    throw httpError(503, `${mode.offlineReason()} and ${name} is not in the cache`);
  }
  if (!held && mode.noNewNames()) throw mode.newName(name);
  checkUsable(up, name);
  try {
    const url = `${base(up)}/${mavenName.pathOf(name)}/maven-metadata.xml`;
    const res = await safefetch.request(url, { headers: headers(up, { accept: 'application/xml, text/xml' }), timeoutMs: 30000, maxBytes: MAX_METADATA_BYTES });
    if (res.status === 404) throw httpError(404, `${name} is not on the ${up.name} repository`);
    if (!res.ok) throw httpError(502, `the ${up.name} repository said ${res.status} for ${name}`);
    const doc = parseMetadata((await res.arrayBuffer()).toString('utf8'), name);
    doc.times = (usable && usable.doc.times) || {};
    if (require('../../policy/cooloff').enabled()) {
      for (const v of doc.versions.slice(-TIMED)) {
        if (!doc.times[v]) doc.times[v] = await publishedAt(up, name, v);
      }
    }
    await docs.put(ECO, name, 'summary', doc, up.name);
    return { doc, cacheHit: false, stale: false };
  } catch (err) {
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} repository failed for ${name}, answering from the cache`, err.message);
      return { doc: usable.doc, cacheHit: true, stale: true };
    }
    throw err;
  }
}

// the .sha1 the repository publishes for a file, or null when it has none (or it could not be had)
async function publishedSha1(up, url) {
  try {
    const res = await safefetch.request(`${url}.sha1`, { headers: headers(up), timeoutMs: 30000, maxBytes: 1024 });
    if (!res.ok) return null;
    const m = /^\s*([0-9a-f]{40})\b/i.exec((await res.arrayBuffer()).toString('utf8'));
    return m ? m[1].toLowerCase() : null;
  } catch (err) {
    return null;
  }
}

// one file of a release, from the store or the repository
async function getFile(name, v, filename) {
  const held = await artifacts.locate(ECO, name, v, filename);
  // a reserved coordinate is only ever what was deployed here, never a copy fetched before it was reserved
  if (await require('../../policy/private-names').isPrivate(ECO, name)) {
    if (held && held.upstream === require('../shared/published').SOURCE) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
    throw httpError(404, `${filename} is reserved and was not deployed here. It is never fetched from an upstream`);
  }
  // a copy from a registry this name is no longer routed to is not this name anymore
  const routed = held && (await upstreams.fromRoute(held.upstream, name, ECO));
  if (held && !routed && !upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, name, ECO));
  if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(name, ECO);
  checkUsable(up, name);
  const url = `${base(up)}/${mavenName.pathOf(name)}/${encodeURIComponent(v)}/${encodeURIComponent(filename)}`;
  const res = await safefetch.request(url, { headers: headers(up, { accept: '*/*' }), timeoutMs: 600000, maxBytes: MAX_FILE_BYTES, stream: true });
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} repository said ${res.status} for ${filename}`);
  }
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `maven.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  const sha1 = crypto.createHash('sha1');
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        sha256.update(chunk);
        sha1.update(chunk);
      });
      res.stream.on('error', (err) => {
        out.destroy();
        reject(err);
      });
      out.on('error', reject);
      out.on('finish', resolve);
      res.stream.pipe(out);
    });
    const got = sha1.digest('hex');
    const said = await publishedSha1(up, url);
    if (said && said !== got) {
      log.error(`${name} ${filename} came back as sha1 ${got}, the repository publishes ${said}. not keeping it`);
      throw httpError(502, `${filename} does not match the sha1 the ${up.name} repository publishes for it, so it was not kept`);
    }
    // a .sha1 that is missing and one that could not be fetched look the same here, and neither is something to check against
    if (!said && mirrorOptions.requiresHash(up)) {
      log.error(`${name} ${filename} came with no .sha1 from the ${up.name} repository, so there was nothing to check it against. refusing it`);
      throw httpError(502, `the ${up.name} repository publishes no hash for ${filename}, so it can not be checked and was not kept`);
    }
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: name, version: v, filename, upstream: up.name }, { tmp, sha256: sha256.digest('hex') });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } catch (err) {
    if (err.status) throw err;
    throw httpError(502, `the download of ${filename} did not complete: ${err.message}`);
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

// a checksum of a stored file, the kind Maven asks for next to every download
function checksum(got, algorithm) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(algorithm);
    const stream = artifacts.open(got);
    stream.on('data', (c) => hash.update(c));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

// the pom of a version, parsed just enough to read its licenses. null when it can not be had
async function pomText(name, v) {
  const c = mavenName.split(name);
  const got = await getFile(name, v, `${c.artifactId}-${v}.pom`);
  const text = await new Promise((resolve, reject) => {
    const parts = [];
    let size = 0;
    const stream = artifacts.open(got);
    stream.on('data', (chunk) => {
      size += chunk.length;
      if (size <= MAX_METADATA_BYTES) parts.push(chunk);
    });
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
  });
  return text;
}

// the licenses are near the top of any real pom, so this much of it is plenty to look through
const MAX_LICENSE_SCAN = 256 * 1024;

async function pomLicenses(name, v) {
  const text = (await pomText(name, v)).slice(0, MAX_LICENSE_SCAN);
  // the first <licenses> and the first close after it. found with indexOf, since a lazy regex over a pom with a lot of
  // openings and no close takes time that grows with the square of its length
  const start = text.indexOf('<licenses>');
  const end = start === -1 ? -1 : text.indexOf('</licenses>', start + 10);
  const block = end === -1 ? '' : text.slice(start + 10, end);
  return texts(block, 'name').slice(0, 10);
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, MAX_FILE_BYTES, upstreamEnabled, parseMetadata, metadata, deployed, getFile, checksum, pomText, pomLicenses, open };
