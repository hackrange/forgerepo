// Talks to PyPI registries and keeps the Python side of the cache.
// Author: Tim Rice
//
// upstream.js for Python, same promises. files often live on another host, so the token
// only goes to the registry's own origin and every file is checked against its published hash.
// files stream to disk, a CUDA wheel can be gigabytes

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');
const config = require('../../config');
const db = require('../../db');
const pypiFiles = require('../../db/repositories/pypi-files');
const pypiDocs = require('../../db/repositories/pypi-documents');
const upstreams = require('../shared/upstreams');
const safefetch = require('../../security/safefetch');
const mirrorOptions = require('../shared/mirror-options');
const simple = require('../../ecosystems/pypi/simple');
const artifacts = require('../../storage/artifacts');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

const USER_AGENT = `ForgeRepo/${config.version} (+private registry mirror)`;
const fileDir = path.join(config.cacheDir, 'pypi');

const MAX_PAGE_BYTES = 64 * 1024 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024;

const SIMPLE_ACCEPT = 'application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1';

// hashes an index might publish, strongest first, plus what node calls each one
const HASHES = [
  ['sha256', 'sha256'], ['sha512', 'sha512'], ['sha384', 'sha384'], ['sha3_256', 'sha3-256'],
  ['blake2b', 'blake2b512'], ['sha224', 'sha224'], ['sha1', 'sha1'], ['md5', 'md5']
];

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !require('../../policy/mode').lockdown();
}

async function init() {
  await fsp.mkdir(fileDir, { recursive: true });
}

// https://pypi.org or https://pypi.org/simple, same registry
function indexBase(up) {
  return /\/simple$/i.test(up.url) ? up.url : `${up.url}/simple`;
}

function jsonBase(up) {
  return `${up.url.replace(/\/simple$/i, '')}/pypi`;
}

// user:password goes as Basic, anything else as a bearer token
function authorization(token) {
  return token.includes(':') ? `Basic ${Buffer.from(token, 'utf8').toString('base64')}` : `Bearer ${token}`;
}

function headersFor(up, url, extra) {
  const h = { 'user-agent': USER_AGENT, ...(extra || {}) };
  if (up.token) {
    try {
      if (new URL(url).origin === new URL(up.url).origin) h.authorization = authorization(up.token);
    } catch (err) {
      // an address that won't parse gets no credentials, and will fail on its own
    }
  }
  return h;
}

function checkUsable(up, project) {
  if (!up) throw httpError(502, `no PyPI registry is set up to serve ${project}. Add one under External registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} registry, which serves ${project}, is switched off`);
}

// where a cached copy may have come from: its registry, plus the default if it falls back
// reserved projects are only what is published here, never a copy from outside, however old
async function refuseReserved(project) {
  const hit = await require('../../policy/private-names').reservedBy('pypi', project);
  if (!hit) return;
  const e = new Error(`${project} is reserved (${hit.pattern}) for packages published on this registry, and nothing like that is uploaded here. It is never fetched from an upstream`);
  e.status = 404;
  e.reserved = true;
  throw e;
}

async function acceptableSources(up) {
  if (!up) return [];
  const names = [up.name];
  if (up.fallback && !up.isDefault) {
    const fallback = await upstreams.defaultUpstream('pypi');
    if (fallback) names.push(fallback.name);
  }
  return names;
}

const inFlight = new Map();

function coalesce(key, fn) {
  if (inFlight.has(key)) return inFlight.get(key);
  const p = fn().finally(() => inFlight.delete(key));
  inFlight.set(key, p);
  return p;
}

// ---------------------------------------------------------------- pages and documents

async function readDoc(project, kind, version) {
  const row = await pypiDocs.get(project, kind, version);
  if (!row) return null;
  try {
    return {
      doc: JSON.parse((await gunzip(row.body)).toString('utf8')),
      etag: row.etag,
      source: row.source,
      fetchedAt: new Date(row.fetched_at)
    };
  } catch (err) {
    log.warn(`could not read the cached ${kind} page for ${project}`, err.message);
    return null;
  }
}

async function writeDoc(project, kind, version, doc, etag, source) {
  const body = await gzip(Buffer.from(JSON.stringify(doc), 'utf8'));
  await pypiDocs.put(project, kind, version, body, source || null, etag ? String(etag).slice(0, 128) : null);
}

// cache first. returns { doc, cacheHit, stale, source }
function getDoc({ project, kind, version, urlFor, accept, parse }) {
  return coalesce(`${kind}:${project}:${version}`, async () => {
    const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
    const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
    if (await require('../../policy/private-names').isPrivate('pypi', project)) {
      // only the project page is kept for an upload, the JSON API has nothing to say about it
      const own = kind === 'simple' && !version ? await require('./published-pages').read(project) : null;
      if (own) return { doc: own, cacheHit: true, stale: false, source: require('../shared/published').SOURCE };
      await refuseReserved(project);
    }
    const up = await upstreams.forPackage(project, 'pypi');
    const sources = await acceptableSources(up);
    const stored = await readDoc(project, kind, version);
    // degraded or lockdown: a project this box has never held a page for is not fetched
    if (!stored && require('../../policy/mode').noNewNames() && !(await readDoc(project, 'simple', '')) && !(await readDoc(project, 'json', ''))) {
      throw require('../../policy/mode').newName(project);
    }
    const cached = stored && sources.includes(stored.source) ? stored : null;
    const age = cached ? Date.now() - cached.fetchedAt.getTime() : Infinity;
    const staleCopy = () => ({ doc: cached.doc, cacheHit: true, stale: true, source: cached.source });

    if (stored && !cached && !upstreamEnabled()) {
      throw httpError(503, `${project} is cached from ${stored.source || 'an unknown registry'} but now comes from `
        + `${up ? up.name : 'nowhere'}, and the upstream registries are switched off, so it cannot be refetched`);
    }
    if (cached && age < ttl) return { doc: cached.doc, cacheHit: true, stale: false, source: cached.source };
    if (!upstreamEnabled()) {
      if (cached) return staleCopy();
      throw httpError(503, `${require('../../policy/mode').offlineReason()} and ${project} is not in the cache`);
    }
    checkUsable(up, project);

    const ask = async (registry, withEtag) => {
      const target = urlFor(registry);
      const extra = { accept };
      if (withEtag && cached && cached.etag && cached.source === registry.name) extra['if-none-match'] = cached.etag;
      const res = await safefetch.request(target, {
        headers: headersFor(registry, target, extra), timeoutMs: 30000, maxBytes: MAX_PAGE_BYTES
      });
      return { registry, target, res };
    };

    let first;
    try {
      first = await ask(up, true);
    } catch (err) {
      if (cached && age < staleOk) {
        log.warn(`the ${up.name} registry is unreachable, serving the cached page for ${project}`, err.message);
        return staleCopy();
      }
      throw httpError(502, `cannot reach the ${up.name} registry: ${err.message}`);
    }

    if (first.res.status === 304 && cached) {
      await pypiDocs.touch(project, kind, version);
      return { doc: cached.doc, cacheHit: true, stale: false, source: cached.source };
    }

    let answer = first;
    if (first.res.status === 404 && up.fallback && !up.isDefault) {
      // off unless configured. a miss falling through to the public index is dependency confusion
      const fallback = await upstreams.defaultUpstream('pypi');
      if (fallback && fallback.enabled && fallback.name !== up.name) {
        log.info(`${project} is not on ${up.name}, asking ${fallback.name} as well`);
        try {
          answer = await ask(fallback, false);
        } catch (err) {
          answer = first;
        }
      }
    }

    if (answer.res.status === 404) throw httpError(404, `${project} is not on the ${up.name} registry`);
    if (!answer.res.ok) {
      if (cached && age < staleOk) {
        log.warn(`the ${answer.registry.name} registry said ${answer.res.status} for ${project}, serving the cached page`);
        return staleCopy();
      }
      throw httpError(502, `the ${answer.registry.name} registry said ${answer.res.status}`);
    }

    let doc;
    try {
      doc = await parse(answer.res, answer.target);
    } catch (err) {
      throw httpError(502, `the ${answer.registry.name} registry answered with something that is not a PyPI page: ${err.message}`);
    }
    await writeDoc(project, kind, version, doc, answer.res.headers.get('etag'), answer.registry.name);
    return { doc, cacheHit: false, stale: false, source: answer.registry.name };
  });
}

async function parseSimple(res, target) {
  const type = String(res.headers.get('content-type') || '').toLowerCase();
  const pageUrl = res.url || target;
  if (type.includes('json')) return simple.fromJson(await res.json(), pageUrl);
  return simple.fromHtml(await res.text(), pageUrl);
}

function getProject(project) {
  return getDoc({
    project,
    kind: 'simple',
    version: '',
    urlFor: (up) => `${indexBase(up)}/${project}/`,
    accept: SIMPLE_ACCEPT,
    parse: parseSimple
  }).then((page) => {
    // fresh page, so check its hashes against files we already hold
    if (!page.cacheHit) {
      require('../../policy/integrity').checkPypi(project, page.doc, page.source)
        .catch((err) => log.warn(`integrity check on the ${project} page failed`, err.message));
    }
    return page;
  });
}

// Warehouse JSON API. private indexes 404 and we pass that along
function getJson(project, version) {
  return getDoc({
    project,
    kind: 'json',
    version: version || '',
    urlFor: (up) => `${jsonBase(up)}/${project}/${version ? `${encodeURIComponent(version)}/` : ''}json`,
    accept: 'application/json',
    parse: async (res) => {
      const doc = await res.json();
      if (!doc || typeof doc !== 'object' || !doc.info) throw new Error('there is no info in it');
      return doc;
    }
  });
}

async function knownProjects() {
  const rows = await pypiFiles.knownProjects();
  return rows.map((r) => r.name);
}

// ---------------------------------------------------------------- files

// hashed, so no clever filename can ever ../ its way out of the cache directory
function filePath(project, filename) {
  const hash = crypto.createHash('sha256').update(`${project}/${filename}`).digest('hex');
  return path.join(fileDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.bin`);
}

async function cachedFile(project, filename, version) {
  try {
    const row = await pypiFiles.sourceOf(project, filename);
    // no known origin, not handed out
    if (!row) return null;
    const found = await artifacts.locate('pypi', project, version || '', filename, filePath(project, filename));
    if (!found) return null;
    return { file: found.path || null, size: found.size, source: row.source, sha256: found.sha256 || row.sha256, artifactId: found.id };
  } catch (err) {
    return null;
  }
}

// file + its .metadata sidekick, disk and every table
async function dropFile(project, filename) {
  const names = filename.endsWith('.metadata') ? [filename] : [filename, `${filename}.metadata`];
  for (const name of names) {
    await fsp.unlink(filePath(project, name)).catch(() => {});
    await pypiFiles.deleteFile(project, name);
    await artifacts.forgetFile('pypi', project, name);
  }
}

function expectedHash(hashes) {
  for (const [name, nodeName] of HASHES) {
    if (hashes && hashes[name]) return { name, nodeName, hex: String(hashes[name]).toLowerCase() };
  }
  return null;
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch (err) {
    return false;
  }
}

// downloads to a temp file hashing as it receives, nothing served until the hash matches.
// off-origin urls came from the page, so public addresses only (SSRF). the hash
// can't save us there, the same page supplies it
async function download(registry, url, filename, hashes, into) {
  const res = await safefetch.request(url, {
    headers: headersFor(registry, url, { accept: '*/*' }),
    timeoutMs: 120000,
    maxBytes: MAX_FILE_BYTES,
    stream: true,
    publicOnly: !sameOrigin(url, registry.url)
  });
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${registry.name} registry said ${res.status} for ${filename}`);
  }

  const want = expectedHash(hashes);
  const sha256 = crypto.createHash('sha256');
  const other = want && want.name !== 'sha256' ? crypto.createHash(want.nodeName) : null;
  await fsp.mkdir(path.dirname(into), { recursive: true });
  const tmp = `${into}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  let size = 0;

  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        size += chunk.length;
        sha256.update(chunk);
        if (other) other.update(chunk);
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
    throw httpError(502, `the download of ${filename} did not complete: ${err.message}`);
  }

  const gotSha256 = sha256.digest('hex');
  if (want) {
    const got = want.name === 'sha256' ? gotSha256 : other.digest('hex');
    if (got !== want.hex) {
      await fsp.unlink(tmp).catch(() => {});
      log.error(`${filename} did not match the ${want.name} hash its index published, refusing it`);
      throw httpError(502, `${filename} did not match the ${want.name} hash the registry published, so it was not served`);
    }
  } else if (mirrorOptions.requiresHash(registry)) {
    await fsp.unlink(tmp).catch(() => {});
    log.error(`${filename} was listed with no hash, so there was nothing to check it against. refusing it`);
    throw httpError(502, `the ${registry.name} index publishes no hash for ${filename}, so it can not be checked and was not kept`);
  } else {
    log.warn(`${filename} was listed with no hash, so there was nothing to check it against`);
  }
  return { tmp, size, sha256: gotSha256 };
}

async function findEntry(project, filename) {
  const page = await getProject(project);
  const entry = page.doc.files.find((f) => f.filename === filename);
  if (!entry) throw httpError(404, `${filename} is not a file of ${project}`);
  return { entry, source: page.source };
}

async function registryNamed(name, fallback) {
  return (await upstreams.all('pypi')).find((u) => u.name === name) || fallback;
}

// a file or its PEP 658 .metadata. temporary = the caller deletes it after sending
async function getFile(project, filename, version, options = {}) {
  const stored = options.metadata ? `${filename}.metadata` : filename;
  if (await require('../../policy/private-names').isPrivate('pypi', project)) {
    const own = await cachedFile(project, stored, version);
    if (own && own.source === require('../shared/published').SOURCE) {
      pypiFiles.touchFile(project, stored).catch(() => {});
      return { file: own.file, sha256: own.sha256, size: own.size, cacheHit: true, temporary: false, artifactId: own.artifactId };
    }
    await refuseReserved(project);
  }
  const up = await upstreams.forPackage(project, 'pypi');
  const sources = await acceptableSources(up);

  const hit = await cachedFile(project, stored, version);
  if (hit && sources.includes(hit.source)) {
    pypiFiles.touchFile(project, stored).catch(() => {});
    return { file: hit.file, sha256: hit.sha256, size: hit.size, cacheHit: true, temporary: false, artifactId: hit.artifactId };
  }
  if (hit && !upstreamEnabled()) {
    throw httpError(503, `${stored} is cached from ${hit.source || 'an unknown registry'} but now comes from `
      + `${up ? up.name : 'nowhere'}, and the upstream registries are switched off, so it cannot be refetched`);
  }

  // scan before serve can only hold a file it kept, so it keeps them whatever the cache setting says
  const keep = db.settings.getBool('cache_tarballs')
    || (db.settings.getBool('malware_scanning') && db.settings.getBool('malware_scan_before_serve'));

  const fetchIt = async () => {
    if (keep) {
      const again = await cachedFile(project, stored, version);
      if (again && sources.includes(again.source)) {
        return { file: again.file, sha256: again.sha256, size: again.size, artifactId: again.artifactId, cacheHit: true, temporary: false };
      }
    }
    if (!upstreamEnabled()) throw httpError(503, `${require('../../policy/mode').offlineReason()} and ${stored} is not in the cache`);
    checkUsable(up, project);

    const { entry, source } = await findEntry(project, filename);
    let url = entry.url;
    let hashes = entry.hashes;
    if (options.metadata) {
      if (!entry.coreMetadata) throw httpError(404, `no metadata file is published for ${filename}`);
      url = `${entry.url}.metadata`;
      hashes = entry.coreMetadata === true ? {} : entry.coreMetadata;
    }

    const registry = await registryNamed(source, up);
    const final = filePath(project, stored);
    const got = await download(registry, url, stored, hashes, final);

    if (!keep) return { file: got.tmp, size: got.size, cacheHit: false, temporary: true };

    // blob store, with the old path hard linked to it for the previous release
    let kept;
    try {
      kept = await artifacts.keep({
        ecosystem: 'pypi',
        packageName: project,
        version: version || '',
        filename: stored,
        upstream: registry.name,
        legacyPath: final
      }, { tmp: got.tmp, sha256: got.sha256 });
    } finally {
      // only catches a failure on the way in
      await fsp.unlink(got.tmp).catch(() => {});
    }
    await pypiFiles.cacheFile({ project, version: version || '', filename: stored, path: final, size: kept.size, sha256: kept.sha256, source: registry.name });
    return { file: null, sha256: kept.sha256, size: kept.size, cacheHit: false, temporary: false, artifactId: kept.id };
  };

  // share a download only when kept, an unkept file gets deleted by whoever sent it first
  return keep ? coalesce(`file:${project}/${stored}`, fetchIt) : fetchIt();
}

async function purgeAll() {
  await fsp.rm(fileDir, { recursive: true, force: true });
  await fsp.mkdir(fileDir, { recursive: true });
  await pypiFiles.deleteAll();
  await pypiDocs.deleteAll();
}

module.exports = {
  init,
  indexBase,
  headersFor,
  jsonBase,
  getProject,
  getJson,
  getFile,
  dropFile,
  filePath,
  knownProjects,
  purgeAll,
  fileDir,
  openFile: (got) => artifacts.open(got)
};
