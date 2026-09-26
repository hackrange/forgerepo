// Talking to a CocoaPods CDN, and to wherever a pod's source code actually lives.
// Author: Tim Rice
//
// the CDN only describes pods: which versions exist (a shard file per md5 prefix) and a podspec per version. the code
// is somewhere else, most often a git tag on GitHub. this box fetches that code itself, as the tag's archive, keeps and
// scans it like any package, and the podspec it hands out points pod at the kept copy. a source it can not fetch as an
// exact, fixed archive (a branch, a commit, submodules, svn) is refused rather than let through unchecked

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
const podName = require('../../ecosystems/cocoapods/name');
const podVersion = require('../../ecosystems/cocoapods/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'cocoapods';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (CocoaPods)`;
const MAX_TEXT_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const MAX_VERSIONS = 5000;
// what an http source can be, and the name its archive goes out under here
const ARCHIVE_TYPES = { zip: 'zip', tgz: 'tar.gz', 'tar.gz': 'tar.gz', tbz: 'tar.bz2', 'tar.bz2': 'tar.bz2', txz: 'tar.xz', 'tar.xz': 'tar.xz', tar: 'tar' };
const MAGIC = {
  zip: Buffer.from([0x50, 0x4b]),
  'tar.gz': Buffer.from([0x1f, 0x8b]),
  'tar.bz2': Buffer.from([0x42, 0x5a, 0x68]),
  'tar.xz': Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a])
};

const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const base = (up) => String(up.url).replace(/\/+$/, '');
const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

function checkUsable(up, what) {
  if (!up) throw httpError(502, `no CocoaPods CDN is set up to serve ${what}. Add a CocoaPods registry under Settings, Registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} CDN, which serves ${what}, is switched off`);
}

// a text file of the CDN, kept as a document while it is fresh, the stale copy when the CDN is down
async function cdnText(up, rel, key) {
  const held = await docs.get(ECO, key, 'text');
  const usable = held && upstreams.sameSource(held.source, up) ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { text: usable.doc.text, cacheHit: true };
  if (!upstreamEnabled()) {
    if (held) return { text: held.doc.text, cacheHit: true };
    throw httpError(503, `${mode.offlineReason()} and ${rel} is not in the cache`);
  }
  checkUsable(up, rel);
  try {
    const res = await safefetch.request(`${base(up)}/${rel}`, { headers: headers(up, { accept: 'text/plain, application/json' }), timeoutMs: 30000, maxBytes: MAX_TEXT_BYTES });
    if (res.status === 404) throw httpError(404, `${rel} is not on the ${up.name} CDN`);
    if (!res.ok) throw httpError(502, `the ${up.name} CDN said ${res.status} for ${rel}`);
    const text = (await res.arrayBuffer()).toString('utf8');
    await docs.put(ECO, key, 'text', { text }, up.name);
    return { text, cacheHit: false };
  } catch (err) {
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} CDN failed for ${rel}, answering from the cache`, err.message);
      return { text: usable.doc.text, cacheHit: true };
    }
    throw err;
  }
}

const shardFile = (name) => `all_pods_versions_${podName.shard(name).join('_')}.txt`;

// a shard: every pod whose name hashes to it, with its versions. { pods: Map(name -> [versions]), cacheHit }. each
// CDN set up gives its shard, and a pod is only taken from the CDN its name is routed to, as for every other type
async function shard(file) {
  if (!/^all_pods_versions_[0-9a-f]_[0-9a-f]_[0-9a-f]\.txt$/.test(file)) throw httpError(404, 'there is no such shard');
  const pods = new Map();
  let cacheHit = true;
  let answered = 0;
  let last = null;
  for (const up of (await upstreams.all(ECO)).filter((u) => u.enabled)) {
    let got;
    try {
      got = await cdnText(up, file, `shard:${up.name}:${file}`.slice(0, 214));
    } catch (err) {
      // a shard one CDN does not have is simply empty there
      if (err.status !== 404) last = err;
      continue;
    }
    answered += 1;
    cacheHit = cacheHit && got.cacheHit;
    for (const line of got.text.split('\n')) {
      const parts = line.trim().split('/');
      if (parts.length < 2 || !podName.valid(parts[0]) || pods.has(parts[0])) continue;
      const routed = await upstreams.forPackage(parts[0], ECO);
      if (!routed || routed.name !== up.name) continue;
      pods.set(parts[0], parts.slice(1).filter((v) => podVersion.valid(v)).slice(0, MAX_VERSIONS));
    }
  }
  if (!answered && last) throw last;
  return { pods, cacheHit };
}

// the versions of one pod, from its shard
async function versions(name) {
  if (!podName.valid(name)) throw httpError(400, 'that is not a pod name');
  const up = await upstreams.forPackage(name, ECO);
  checkUsable(up, name);
  const got = await cdnText(up, shardFile(name), `shard:${up.name}:${shardFile(name)}`.slice(0, 214));
  for (const line of got.text.split('\n')) {
    const parts = line.trim().split('/');
    if (parts[0] === name) return parts.slice(1).filter((v) => podVersion.valid(v)).slice(0, MAX_VERSIONS);
  }
  throw httpError(404, `${name} is not on the ${up.name} CDN`);
}

const specPath = (name, v) => `Specs/${podName.shard(name).join('/')}/${name}/${v}/${name}.podspec.json`;

// one podspec as the CDN has it, parsed. it has to name the pod and version asked for
async function podspec(name, v) {
  if (!podName.valid(name) || !podVersion.valid(v)) throw httpError(400, 'that is not a pod and version');
  const up = await upstreams.forPackage(name, ECO);
  const got = await cdnText(up, specPath(name, v), `spec:${name}@${v}`.slice(0, 214));
  let spec;
  try {
    spec = JSON.parse(got.text);
  } catch (err) {
    throw httpError(502, `the ${up.name} CDN answered the podspec of ${name} ${v} with something that is not json`);
  }
  if (!spec || typeof spec !== 'object' || spec.name !== name || String(spec.version) !== v) {
    throw httpError(502, `the ${up.name} CDN answered ${name} ${v} with the podspec of something else`);
  }
  return spec;
}

// where the code of a version comes from, and the exact archive to fetch for it, or why it can not be mirrored.
// { url, ext } or { refuse }
function sourceOf(spec) {
  const s = spec && spec.source;
  if (!s || typeof s !== 'object') return { refuse: 'its podspec names no source' };
  if (typeof s.http === 'string') {
    let url;
    try {
      url = new URL(s.http);
    } catch (err) {
      return { refuse: 'its source address does not read' };
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return { refuse: `its source is a ${url.protocol} address, which this box does not fetch` };
    const named = typeof s.type === 'string' ? s.type.toLowerCase() : Object.keys(ARCHIVE_TYPES).find((k) => url.pathname.toLowerCase().endsWith(`.${k}`));
    const ext = ARCHIVE_TYPES[named];
    if (!ext) return { refuse: 'its source is a download this box can not tell the type of' };
    return { url: url.href, ext, sha256: typeof s.sha256 === 'string' ? s.sha256.toLowerCase() : null, sha1: typeof s.sha1 === 'string' ? s.sha1.toLowerCase() : null, flatten: s.flatten === true };
  }
  if (typeof s.git === 'string') {
    if (s.submodules) return { refuse: 'its source needs git submodules, which a tag archive does not carry' };
    if (typeof s.tag !== 'string' || !s.tag || s.commit || s.branch) return { refuse: 'its source is a git branch or commit, not a tag, so there is no fixed release to fetch' };
    const m = /^https:\/\/(github\.com|gitlab\.com)\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(s.git);
    if (!m) return { refuse: 'its source is a git repository this box can not fetch a tag archive from (only github.com and gitlab.com)' };
    const tag = encodeURIComponent(s.tag);
    const url = m[1] === 'github.com'
      ? `https://codeload.github.com/${m[2]}/${m[3]}/tar.gz/refs/tags/${tag}`
      : `https://gitlab.com/${m[2]}/${m[3]}/-/archive/${tag}/${m[3]}-${tag}.tar.gz`;
    return { url, ext: 'tar.gz', sha256: null, sha1: null, flatten: false };
  }
  return { refuse: `its source is ${Object.keys(s).filter((k) => ['svn', 'hg', 'bzr'].includes(k))[0] || 'of a kind'} this box does not fetch` };
}

const archiveName = (name, v, ext) => `${name}-${v}.${ext}`;

// the source archive of a version, from the store or from where the podspec says the code is
async function getArchive(name, v) {
  const spec = await podspec(name, v);
  const src = sourceOf(spec);
  if (src.refuse) throw httpError(403, `${name} ${v} can not be mirrored here: ${src.refuse}`);
  const filename = archiveName(name, v, src.ext);
  const held = await artifacts.locate(ECO, name, v, filename);
  // a copy from a registry this name is no longer routed to is not this name anymore
  const routed = held && (await upstreams.fromRoute(held.upstream, name, ECO));
  if (held && !routed && !upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, name, ECO));
  if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename, ext: src.ext };
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(name, ECO);
  checkUsable(up, name);
  // a git tag has no checksum in its podspec, only an http source can carry one. with a hash required, refused up front
  if (!src.sha256 && !src.sha1 && mirrorOptions.requiresHash(up)) {
    log.error(`${name} ${v}: its podspec gives no checksum for the source, so there would be nothing to check it against. refusing it`);
    throw httpError(502, `the ${up.name} podspec for ${name} ${v} publishes no hash for its source, so it can not be checked and was not kept`);
  }
  // the code host is somebody else's server, so nothing of the CDN's token goes to it
  let res;
  try {
    res = await safefetch.request(src.url, { headers: { 'user-agent': USER_AGENT, accept: '*/*' }, timeoutMs: 600000, maxBytes: MAX_ARCHIVE_BYTES, stream: true, publicOnly: true });
  } catch (err) {
    // an address on this network, a host that does not answer: either way there is no source to keep
    throw httpError(502, `the source of ${name} ${v} could not be fetched: ${err.message}`);
  }
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `${new URL(src.url).host} said ${res.status} for the source of ${name} ${v}`);
  }
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `pod.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  const sha1 = crypto.createHash('sha1');
  let head = Buffer.alloc(0);
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        sha256.update(chunk);
        sha1.update(chunk);
        if (head.length < 8) head = Buffer.concat([head, chunk.subarray(0, 8 - head.length)]);
      });
      res.stream.on('error', (err) => {
        out.destroy();
        reject(err);
      });
      out.on('error', reject);
      out.on('finish', resolve);
      res.stream.pipe(out);
    });
    const magic = MAGIC[src.ext];
    if (magic && !head.subarray(0, magic.length).equals(magic)) throw httpError(502, `the source of ${name} ${v} is not the ${src.ext} archive it should be, so it was not kept`);
    const got256 = sha256.digest('hex');
    const got1 = sha1.digest('hex');
    if ((src.sha256 && src.sha256 !== got256) || (src.sha1 && src.sha1 !== got1)) {
      log.error(`${name} ${v}: the source archive does not match the checksum its podspec gives, not keeping it`);
      throw httpError(502, `the source of ${name} ${v} does not match the checksum its podspec gives, so it was not kept`);
    }
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: name, version: v, filename, upstream: up.name }, { tmp, sha256: got256 });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename, ext: src.ext };
  } catch (err) {
    if (err.status) throw err;
    throw httpError(502, `the download of the source of ${name} ${v} did not complete: ${err.message}`);
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

// the CDN's own small files: CocoaPods-version.yml says how shards are named
async function versionFile() {
  const up = await upstreams.forPackage('', ECO);
  return (await cdnText(up, 'CocoaPods-version.yml', 'meta:version')).text;
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, ARCHIVE_TYPES, shardFile, shard, versions, specPath, podspec, sourceOf, archiveName, getArchive, versionFile, open };
