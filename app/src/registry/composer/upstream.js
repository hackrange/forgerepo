// Talking to a Composer repository like repo.packagist.org, and to wherever a package's archive actually lives.
// Author: Tim Rice
//
// the repository describes packages: a p2/<vendor>/<name>.json per package, every release in it. the code is somewhere
// else, most often a GitHub archive of the exact commit the release points at. this box fetches that archive itself,
// keeps and scans it, and the metadata it hands out points composer at the kept copy. the git fallback composer would
// use when a download fails (source) is taken out, so there is no way around the box
//
// Packagist minifies p2 files: each release only lists what changed from the one before it, "__unset" drops a key.
// they are expanded here and handed out whole

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
const composerName = require('../../ecosystems/composer/name');
const composerVersion = require('../../ecosystems/composer/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'composer';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (Composer)`;
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const MAX_VERSIONS = 5000;
const DEFAULT_METADATA = '/p2/%package%.json';
// a MEDIUMBLOB holds 16MB
const MAX_STORED = 15 * 1024 * 1024;

const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const base = (up) => String(up.url).replace(/\/+$/, '');
const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

function checkUsable(up, what) {
  if (!up) throw httpError(502, `no Composer repository is set up to serve ${what}. Add a Composer registry under Settings, Registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} repository, which serves ${what}, is switched off`);
}

async function getJson(up, url, what) {
  const res = await safefetch.request(url, { headers: headers(up, { accept: 'application/json' }), timeoutMs: 60000, maxBytes: MAX_JSON_BYTES });
  if (res.status === 404) throw httpError(404, `${what} is not on the ${up.name} repository`);
  if (!res.ok) throw httpError(502, `the ${up.name} repository said ${res.status} for ${what}`);
  try {
    return JSON.parse((await res.arrayBuffer()).toString('utf8'));
  } catch (err) {
    throw httpError(502, `the ${up.name} repository answered ${what} with something that is not json`);
  }
}

// where a repository keeps a package's metadata. Packagist and most others say so in packages.json
async function metadataUrl(up) {
  const held = await docs.get(ECO, `root:${up.name}`.slice(0, 214), 'root');
  if (held && upstreams.sameSource(held.source, up) && Date.now() - held.fetchedAt.getTime() < 24 * 3600 * 1000) return held.doc.template;
  let template = DEFAULT_METADATA;
  try {
    const root = await getJson(up, `${base(up)}/packages.json`, 'packages.json');
    if (root && typeof root['metadata-url'] === 'string') template = root['metadata-url'];
  } catch (err) {
    if (held) return held.doc.template;
    if (err.status !== 404) throw err;
  }
  // the template may be absolute, but only on the repository's own host. a repository does not get to send the box elsewhere
  const url = new URL(template, `${base(up)}/`);
  if (url.origin !== new URL(base(up)).origin || !url.pathname.includes('%package%')) template = DEFAULT_METADATA;
  else template = url.pathname;
  await docs.put(ECO, `root:${up.name}`.slice(0, 214), 'root', { template }, up.name);
  return template;
}

// Composer's MetadataMinifier::expand
function expand(list) {
  const out = [];
  let current = null;
  for (const entry of Array.isArray(list) ? list : []) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    if (!current) {
      current = { ...entry };
    } else {
      current = { ...current };
      for (const [k, v] of Object.entries(entry)) {
        if (v === '__unset') delete current[k];
        else current[k] = v;
      }
    }
    out.push(current);
  }
  return out;
}

// the releases in a stored list: expanded, and only the ones whose name is the package asked for. branches live in
// the ~dev file and are not taken
function releasesOf(held) {
  const all = held.minified ? expand(held.list) : (held.list || []).filter((e) => e && typeof e === 'object');
  return all.filter((e) => typeof e.version === 'string' && composerVersion.valid(e.version) && (!e.name || composerName.fold(e.name) === held.name))
    .slice(0, MAX_VERSIONS);
}

const asDoc = (held) => ({ name: held.name, versions: releasesOf(held) });

// a package's releases, from the cache while fresh. { doc: { name, versions: [release objects] }, cacheHit }. the list
// is kept minified the way the repository sent it, expanded it can be many times the size
async function metadata(name) {
  if (!composerName.valid(name)) throw httpError(400, 'that is not a package name like monolog/monolog');
  const folded = composerName.fold(name);
  const up = await upstreams.forPackage(folded, ECO);
  const held = await docs.get(ECO, folded, 'p2');
  const usable = held && up && upstreams.sameSource(held.source, up) ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { doc: asDoc(usable.doc), cacheHit: true };
  if (!upstreamEnabled()) {
    if (held) return { doc: asDoc(held.doc), cacheHit: true };
    throw httpError(503, `${mode.offlineReason()} and ${folded} is not in the cache`);
  }
  if (!held && mode.noNewNames()) throw mode.newName(folded);
  checkUsable(up, folded);
  try {
    const template = await metadataUrl(up);
    const body = await getJson(up, `${new URL(base(up)).origin}${template.replace('%package%', folded)}`, folded);
    const listed = body && body.packages && typeof body.packages === 'object' ? body.packages[folded] : null;
    if (!Array.isArray(listed)) throw httpError(404, `${folded} is not on the ${up.name} repository`);
    const stored = { name: folded, minified: !!body.minified, list: listed };
    if (JSON.stringify(stored).length < MAX_STORED) await docs.put(ECO, folded, 'p2', stored, up.name);
    else log.warn(`the metadata of ${folded} is too large to keep, it is fetched every time`);
    return { doc: asDoc(stored), cacheHit: false };
  } catch (err) {
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} repository failed for ${folded}, answering from the cache`, err.message);
      return { doc: asDoc(usable.doc), cacheHit: true };
    }
    throw err;
  }
}

function release(doc, v) {
  return doc.versions.find((e) => e.version === v) || null;
}

// the exact archive a release's dist names, or why it can not be mirrored. { url, reference, shasum, sameHost } or { refuse }
function distOf(up, rel) {
  const d = rel && rel.dist;
  if (!d || typeof d !== 'object' || typeof d.url !== 'string') return { refuse: 'it has no archive to download, only a git source' };
  if (d.type && d.type !== 'zip') return { refuse: `its archive is a ${String(d.type).slice(0, 20)}, and this box only mirrors zip archives` };
  const reference = typeof d.reference === 'string' ? d.reference : '';
  if (!/^[0-9a-f]{40}$/.test(reference)) return { refuse: 'its archive is not pinned to a commit, so there is no fixed release to fetch' };
  let url;
  try {
    url = new URL(d.url);
  } catch (err) {
    return { refuse: 'its archive address does not read' };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { refuse: `its archive is a ${url.protocol} address, which this box does not fetch` };
  // the GitHub API's zipball is rate limited without a token, the same bytes come from codeload without one
  const gh = /^\/repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/zipball\/([0-9a-f]{40})$/.exec(url.pathname);
  if (url.host === 'api.github.com' && gh) {
    if (gh[3] !== reference) return { refuse: 'its archive address and its commit do not agree' };
    return { url: `https://codeload.github.com/${gh[1]}/${gh[2]}/legacy.zip/${reference}`, reference, shasum: shasumOf(d), sameHost: false };
  }
  const sameHost = !!up && url.origin === new URL(base(up)).origin;
  return { url: url.href, reference, shasum: shasumOf(d), sameHost };
}

const shasumOf = (d) => (typeof d.shasum === 'string' && /^[0-9a-f]{40}$/i.test(d.shasum) ? d.shasum.toLowerCase() : null);

const archiveName = (name, v) => `${composerName.fold(name).replace('/', '-')}-${v}.zip`;

// the archive of a release, from the store or from where its dist says it is
async function getArchive(name, v) {
  const { doc } = await metadata(name);
  const rel = release(doc, v);
  if (!rel) throw httpError(404, `${doc.name} has no release ${v}`);
  const filename = archiveName(doc.name, v);
  const held = await artifacts.locate(ECO, doc.name, v, filename);
  // a copy from a registry this name is no longer routed to is not this name anymore
  const routed = held && (await upstreams.fromRoute(held.upstream, doc.name, ECO));
  if (held && !routed && !upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, doc.name, ECO));
  if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(doc.name, ECO);
  checkUsable(up, doc.name);
  const dist = distOf(up, rel);
  if (dist.refuse) throw httpError(403, `${doc.name} ${v} can not be mirrored here: ${dist.refuse}`);
  // Packagist gives no shasum for a GitHub archive, so with a hash required most of it is refused, and before downloading
  if (!dist.shasum && mirrorOptions.requiresHash(up)) {
    log.error(`${doc.name} ${v}: its metadata gives no shasum for the archive, so there would be nothing to check it against. refusing it`);
    throw httpError(502, `the ${up.name} repository publishes no hash for the archive of ${doc.name} ${v}, so it can not be checked and was not kept`);
  }
  // the repository's own token only goes to the repository's own host. anything else is somebody else's server
  let res;
  try {
    res = await safefetch.request(dist.url, dist.sameHost
      ? { headers: headers(up, { accept: 'application/zip, */*' }), timeoutMs: 600000, maxBytes: MAX_ARCHIVE_BYTES, stream: true }
      : { headers: { 'user-agent': USER_AGENT, accept: 'application/zip, */*' }, timeoutMs: 600000, maxBytes: MAX_ARCHIVE_BYTES, stream: true, publicOnly: true });
  } catch (err) {
    throw httpError(502, `the archive of ${doc.name} ${v} could not be fetched: ${err.message}`);
  }
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `${new URL(dist.url).host} said ${res.status} for the archive of ${doc.name} ${v}`);
  }
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `composer.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  const sha1 = crypto.createHash('sha1');
  let head = Buffer.alloc(0);
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        sha256.update(chunk);
        sha1.update(chunk);
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
    if (!head.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) throw httpError(502, `the archive of ${doc.name} ${v} is not a zip, so it was not kept`);
    const got1 = sha1.digest('hex');
    if (dist.shasum && dist.shasum !== got1) {
      log.error(`${doc.name} ${v}: the archive does not match the shasum its metadata gives, not keeping it`);
      throw httpError(502, `the archive of ${doc.name} ${v} does not match the shasum its metadata gives, so it was not kept`);
    }
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: doc.name, version: v, filename, upstream: up.name }, { tmp, sha256: sha256.digest('hex') });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } catch (err) {
    if (err.status) throw err;
    throw httpError(502, `the download of ${doc.name} ${v} did not complete: ${err.message}`);
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, expand, metadata, release, distOf, archiveName, getArchive, open };
