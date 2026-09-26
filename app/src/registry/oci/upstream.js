// Fetching image metadata and layers from a registry that speaks the v2 API.
// Author: Tim Rice
//
// a manifest is small json we read and keep; a layer is large, so it streams to disk and is checked against the digest
// the manifest named before anything is stored. a tag is resolved to a digest and the digest is what everything else uses
//
// safefetch hands back a small facade, not a node response: headers come through headers.get() and the bytes are
// awaited. reach for res.body and you get undefined, which is a quiet way to skip a check that matters

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const db = require('../../db');
const config = require('../../config');
const safefetch = require('../../security/safefetch');
const upstreams = require('../shared/upstreams');
const artifacts = require('../../storage/artifacts');
const ociName = require('../../ecosystems/oci/name');
const tags = require('../../db/repositories/oci-tags');
const kept = require('../../db/repositories/oci-manifests');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const USER_AGENT = `ForgeRepo/${require('../../../package.json').version}`;
// a manifest or an index, never a layer
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_LAYER_BYTES = 10 * 1024 * 1024 * 1024;
const MANIFEST_TYPES = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json'
].join(', ');

// only a scratch folder for a download in flight. where the bytes end up is the blob store's business
const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !require('../../policy/mode').lockdown();
}

function checkUsable(up, repository) {
  if (!up) throw httpError(502, `no registry is set up to serve ${repository}. Add one under External registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} registry, which serves ${repository}, is switched off`);
}

const DOCKER_HUB = /(^|\.)docker\.io$|(^|\/\/)(registry-1\.|index\.)?docker\.io(\/|$)/;

// the name as that registry spells it: Docker Hub keeps its own images under library/
function remoteName(repository, up) {
  return DOCKER_HUB.test(String(up.url)) ? ociName.official(repository) : repository;
}

// nginx and library/nginx are one image on Docker Hub, so they are one name here too: the short one, and both are
// asked of the rules. anywhere else library/ is just a folder (Harbor's default project is called library)
async function canonicalName(repository) {
  const m = /^library\/([^/]+)$/.exec(repository);
  const short = m ? m[1] : repository;
  if (short.includes('/')) return { name: repository, aliases: [repository] };
  const up = await upstreams.forPackage(short, 'oci').catch(() => null);
  if (!up || !DOCKER_HUB.test(String(up.url))) return { name: repository, aliases: [repository] };
  return { name: short, aliases: [short, `library/${short}`] };
}

const base = (up) => String(up.url).replace(/\/+$/, '');

// safefetch's headers are a getter, never a plain object
const headerOf = (res, name) => (res && res.headers && typeof res.headers.get === 'function' ? res.headers.get(name) : null);

function headersFor(up, extra) {
  const h = { 'user-agent': USER_AGENT, ...(extra || {}) };
  // "Bearer x" as it is, username:access-token as basic auth, and anything else taken to be that already encoded
  if (up.token) {
    h.authorization = up.token.includes(' ') ? up.token
      : up.token.includes(':') ? `Basic ${Buffer.from(up.token, 'utf8').toString('base64')}` : `Basic ${up.token}`;
  }
  return h;
}

// registries answer an anonymous request with a challenge naming where to get a token. one round, then we give up
const tokens = new Map();

async function bearerFor(up, repository, challenge) {
  const key = `${up.name}\n${repository}`;
  const held = tokens.get(key);
  if (held && held.until > Date.now()) return held.token;

  const params = {};
  for (const m of String(challenge).matchAll(/([a-z_]+)="([^"]*)"/gi)) params[m[1].toLowerCase()] = m[2];
  if (!params.realm) return null;
  let url;
  try {
    url = new URL(params.realm);
  } catch (err) {
    return null;
  }
  if (params.service) url.searchParams.set('service', params.service);
  url.searchParams.set('scope', params.scope || `repository:${repository}:pull`);

  const res = await safefetch.request(url.href, {
    headers: headersFor(up, { accept: 'application/json' }), timeoutMs: 30000, maxBytes: 256 * 1024
  });
  if (!res.ok) return null;
  let body;
  try {
    body = await res.json();
  } catch (err) {
    return null;
  }
  const token = body.token || body.access_token;
  if (!token) return null;
  // registries say 300 seconds when they say anything. a minute short of it, so a fetch never runs out mid flight
  const seconds = Number.isFinite(Number(body.expires_in)) ? Math.max(60, Number(body.expires_in)) : 300;
  tokens.set(key, { token, until: Date.now() + (seconds - 30) * 1000 });
  return token;
}

// one request, and if the registry asks for a token, the same request again carrying one
async function ask(up, repository, url, options) {
  const first = await safefetch.request(url, { ...options, headers: headersFor(up, options.headers) });
  if (first.status !== 401) return first;
  const challenge = headerOf(first, 'www-authenticate');
  if (first.stream) first.stream.resume();
  if (!challenge || !/^bearer/i.test(String(challenge))) return first;
  const token = await bearerFor(up, repository, challenge);
  if (!token) return first;
  return safefetch.request(url, { ...options, headers: headersFor(up, { ...options.headers, authorization: `Bearer ${token}` }) });
}

// what the registry says it sent us, against what it actually sent
function digestOf(res, body) {
  const said = headerOf(res, 'docker-content-digest');
  const got = `sha256:${crypto.createHash('sha256').update(body).digest('hex')}`;
  if (said && String(said).trim() !== got) {
    throw httpError(502, 'the registry answered with a manifest that does not match the digest it claimed');
  }
  return got;
}

// a kept manifest, only if its bytes still hash to the digest it is kept under
function fromKept(row) {
  if (!row || !row.body) return null;
  const body = Buffer.isBuffer(row.body) ? row.body : Buffer.from(row.body);
  if (`sha256:${crypto.createHash('sha256').update(body).digest('hex')}` !== row.digest) {
    log.error(`the kept manifest for ${row.repository}@${row.digest} does not match its digest, ignoring it`);
    return null;
  }
  let doc;
  try {
    doc = JSON.parse(body.toString('utf8'));
  } catch (err) {
    return null;
  }
  return { body, digest: row.digest, contentType: row.media_type || null, doc, upstream: row.upstream, moved: false, cached: true };
}

// what this box can answer without the registry. a tag only while its last check is recent enough, unless anyAge
async function keptFor(repository, reference, { anyAge }) {
  if (ociName.isDigest(reference)) return fromKept(await kept.get(repository, reference));
  const pointer = await tags.get(repository, reference);
  if (!pointer) return null;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (!anyAge && Date.now() - new Date(pointer.checked_at).getTime() > staleOk) return null;
  return fromKept(await kept.get(repository, pointer.digest));
}

// a manifest by tag or digest. the answer is the bytes, their digest and what kind of document it is
async function getManifest(repository, reference) {
  // a reserved name is what was pushed here and nothing else, however the upstream is set
  const reserved = await require('./published').reservedBy([repository]);
  if (reserved) return require('./published').manifest(repository, reference, reserved, fromKept);
  // by digest the kept copy is the answer, no need to ask anyone
  if (ociName.isDigest(reference)) {
    const held = fromKept(await kept.get(repository, reference));
    if (held) return held;
  }
  if (!upstreamEnabled()) {
    const offline = await keptFor(repository, reference, { anyAge: true });
    if (offline) return offline;
    throw httpError(503, `${require('../../policy/mode').offlineReason()} and ${repository}:${reference} is not in the cache`);
  }
  // degraded mode: an image this box has never held a manifest of is not fetched
  if (require('../../policy/mode').noNewNames() && !(await tags.forRepository(repository)).length && !(await kept.anyFor(repository))) {
    throw require('../../policy/mode').newName(repository);
  }
  const up = await upstreams.forPackage(repository, 'oci');
  checkUsable(up, repository);
  const remote = remoteName(repository, up);
  const url = `${base(up)}/v2/${remote}/manifests/${encodeURIComponent(reference)}`;

  let res;
  try {
    res = await ask(up, remote, url, { timeoutMs: 30000, maxBytes: MAX_MANIFEST_BYTES, headers: { accept: MANIFEST_TYPES } });
  } catch (err) {
    res = null;
    log.warn(`the ${up.name} registry could not be reached for ${repository}:${reference}`, err.message);
  }
  // down, rate limited or broken: a tag checked recently enough still answers from what is kept
  if (!res || res.status === 429 || res.status >= 500) {
    const stale = await keptFor(repository, reference, { anyAge: false });
    if (stale) return stale;
    throw httpError(502, res ? `the ${up.name} registry said ${res.status} for ${repository}:${reference}` : `the ${up.name} registry could not be reached`);
  }
  if (res.status === 404) throw httpError(404, `${repository}:${reference} is not on the ${up.name} registry`);
  if (!res.ok) throw httpError(502, `the ${up.name} registry said ${res.status} for ${repository}:${reference}`);

  const body = await res.arrayBuffer();
  if (!body || !body.length) throw httpError(502, `the ${up.name} registry answered with an empty manifest`);
  const digest = digestOf(res, body);
  const contentType = String(headerOf(res, 'content-type') || '').split(';')[0].trim();
  let doc;
  try {
    doc = JSON.parse(body.toString('utf8'));
  } catch (err) {
    throw httpError(502, `the ${up.name} registry answered with a manifest that is not json`);
  }

  // a digest someone asked for has to be what they got
  if (ociName.isDigest(reference) && reference !== digest) {
    throw httpError(502, `the ${up.name} registry answered ${reference} with a different manifest`);
  }
  await kept.put(repository, digest, contentType || doc.mediaType || '', body, up.name).catch((err) => {
    log.warn(`could not keep the manifest for ${repository}@${digest}`, err.message);
  });
  // a tag is a label somebody can move, so record where it points now and whether that changed
  if (!ociName.isDigest(reference)) {
    const moved = await tags.point(repository, reference, digest, up.name);
    if (moved.moved) log.warn(`${repository}:${reference} now points at ${digest}, it moved`);
  }
  return { body, digest, contentType, doc, upstream: up.name, moved: !ociName.isDigest(reference) };
}

// a layer or a config blob. streamed, hashed on the way past, and thrown away unless it is what the manifest asked for
async function getBlob(repository, digest) {
  if (!ociName.isDigest(digest)) throw httpError(400, 'that is not a digest');
  const reserved = await require('./published').reservedBy([repository]);
  if (reserved) return require('./published').blob(repository, digest, reserved);
  const held = await artifacts.locate('oci', repository, '', digest);
  if (held) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true };

  if (!upstreamEnabled()) throw httpError(503, `${require('../../policy/mode').offlineReason()} and ${digest} is not in the cache`);
  const up = await upstreams.forPackage(repository, 'oci');
  checkUsable(up, repository);
  const remote = remoteName(repository, up);
  const url = `${base(up)}/v2/${remote}/blobs/${digest}`;

  const res = await ask(up, remote, url, { timeoutMs: 600000, maxBytes: MAX_LAYER_BYTES, stream: true, headers: { accept: '*/*' } });
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} registry said ${res.status} for ${digest}`);
  }
  if (!res.stream) throw httpError(502, `the ${up.name} registry sent no bytes for ${digest}`);

  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `oci.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  let size = 0;
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        size += chunk.length;
        sha256.update(chunk);
      });
      res.stream.on('error', (err) => {
        out.destroy();
        reject(err);
      });
      out.on('error', reject);
      out.on('finish', resolve);
      res.stream.pipe(out);
    });
  } catch (err) {
    await fsp.unlink(tmp).catch(() => {});
    throw httpError(502, `the download of ${digest} did not complete: ${err.message}`);
  }

  const got = `sha256:${sha256.digest('hex')}`;
  if (got !== digest) {
    await fsp.unlink(tmp).catch(() => {});
    log.error(`${repository} blob ${digest} came back as ${got}, refusing it`);
    throw httpError(502, 'the blob did not match the digest it was asked for, so it was not served');
  }

  let kept;
  try {
    kept = await artifacts.keep(
      { ecosystem: 'oci', packageName: repository, version: '', filename: digest, upstream: up.name },
      { tmp, sha256: got.slice(7) }
    );
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
  return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false };
}

module.exports = { headersFor, MAX_MANIFEST_BYTES, MAX_LAYER_BYTES, MANIFEST_TYPES, upstreamEnabled, remoteName, canonicalName, fromKept, keptFor, getManifest, getBlob };
