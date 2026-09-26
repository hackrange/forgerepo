// Swift packages live in git. This box reads a repository's tags from the git host and serves each semver tag as a
// registry release: the tag's source archive, fetched once, kept and scanned, and the Package.swift read out of it.
// Author: Tim Rice
//
// the registry is a git host like https://github.com. apple.swift-log is github.com/apple/swift-log. tags come from git's
// own ref listing (info/refs), not from the host's API, so there is no API rate limit to run into

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const db = require('../../db');
const config = require('../../config');
const safefetch = require('../../security/safefetch');
const upstreams = require('../shared/upstreams');
const artifacts = require('../../storage/artifacts');
const docs = require('../../db/repositories/package-documents');
const swiftName = require('../../ecosystems/swift/name');
const swiftVersion = require('../../ecosystems/swift/version');
const zip = require('../shared/zip');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'swift';
const USER_AGENT = `git/2.43 ForgeRepo/${require('../../../package.json').version}`;
const MAX_REFS_BYTES = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
// the manifest is read from the archive in memory, so an archive bigger than this has its manifest refused
const MAX_READ_BYTES = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_VERSIONS = 5000;

const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const base = (up) => String(up.url).replace(/\/+$/, '');
const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

function checkUsable(up, id) {
  if (!up) throw httpError(502, `no git host is set up to serve ${id}. Add a Swift registry under Settings, Registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} git host, which serves ${id}, is switched off`);
}

// git's pkt-line ref listing: "<4 hex length><sha> <ref>[\0capabilities]\n"
function parseRefs(buf) {
  const tags = new Map();
  let p = 0;
  while (p + 4 <= buf.length) {
    const len = parseInt(buf.toString('ascii', p, p + 4), 16);
    if (!Number.isFinite(len)) break;
    if (len === 0) {
      p += 4;
      continue;
    }
    const line = buf.toString('utf8', p + 4, p + len).replace(/\n$/, '').split('\0')[0];
    p += len;
    const m = /^([0-9a-f]{40}) refs\/tags\/(.+?)(\^\{\})?$/.exec(line);
    if (!m) continue;
    // an annotated tag shows twice, the peeled ^{} line is the commit. the tag name is what counts here
    if (!tags.has(m[2])) tags.set(m[2], m[1]);
  }
  return tags;
}

// the semver tags of a repository, as releases. v1.2.3 and 1.2.3 are both release 1.2.3, the plain one wins
function releasesFrom(tags) {
  const out = new Map();
  for (const tag of tags.keys()) {
    const v = tag.replace(/^v/, '');
    if (!swiftVersion.valid(v) || v.includes('+')) continue;
    if (!out.has(v) || !tag.startsWith('v')) out.set(v, tag);
  }
  return [...out.entries()].slice(0, MAX_VERSIONS).map(([version, tag]) => ({ version, tag }));
}

// a package's releases, from the cache while fresh. { doc: { id, scope, name, versions: [{ version, tag }] }, cacheHit }
async function summary(id) {
  const parts = swiftName.split(id);
  if (!parts) throw httpError(400, 'that is not a package identity like apple.swift-log');
  const folded = swiftName.fold(id);
  const up = await upstreams.forPackage(folded, ECO);
  const held = await docs.get(ECO, folded, 'summary');
  const usable = held && up && upstreams.sameSource(held.source, up) ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { doc: usable.doc, cacheHit: true };
  if (!upstreamEnabled()) {
    if (held) return { doc: held.doc, cacheHit: true };
    throw httpError(503, `${mode.offlineReason()} and ${folded} is not in the cache`);
  }
  if (!held && mode.noNewNames()) throw mode.newName(folded);
  checkUsable(up, folded);
  try {
    const url = `${base(up)}/${encodeURIComponent(parts.scope)}/${encodeURIComponent(parts.name)}.git/info/refs?service=git-upload-pack`;
    const res = await safefetch.request(url, { headers: headers(up), timeoutMs: 30000, maxBytes: MAX_REFS_BYTES });
    // a repository that does not exist asks for a login on GitHub, rather than saying 404
    if (res.status === 404 || res.status === 401) throw httpError(404, `${folded} is not a repository on the ${up.name} git host`);
    if (!res.ok) throw httpError(502, `the ${up.name} git host said ${res.status} for ${folded}`);
    const doc = { id: folded, scope: parts.scope.toLowerCase(), name: parts.name.toLowerCase(), versions: releasesFrom(parseRefs(await res.arrayBuffer())) };
    await docs.put(ECO, folded, 'summary', doc, up.name);
    return { doc, cacheHit: false };
  } catch (err) {
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} git host failed for ${folded}, answering from the cache`, err.message);
      return { doc: usable.doc, cacheHit: true };
    }
    throw err;
  }
}

const archiveName = (id, v) => `${swiftName.fold(id)}-${v}.zip`;

// an upstream saved with require a hash on before that was refused for Swift. there is no hash to require, so the
// archive is fetched as always; the warning says so once per upstream, so nobody takes the setting for a check
const hashWarned = new Set();
function warnHashIgnored(up) {
  if (!up || !up.options || up.options.requireHash !== true || hashWarned.has(up.name)) return;
  hashWarned.add(up.name);
  log.warn(`the ${up.name} upstream has require a hash turned on, but Swift packages carry no checksum, so it is ignored. turn it off to stop this warning`);
}

// the source archive of a release: the tag's zip from the git host, kept like any package
async function getArchive(id, v) {
  const { doc } = await summary(id);
  const rel = doc.versions.find((x) => x.version === v);
  if (!rel) throw httpError(404, `${doc.id} has no release ${v}`);
  const filename = archiveName(doc.id, v);
  const held = await artifacts.locate(ECO, doc.id, v, filename);
  // a copy from a registry this name is no longer routed to is not this name anymore
  const routed = held && (await upstreams.fromRoute(held.upstream, doc.id, ECO));
  if (held && !routed && !upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, doc.id, ECO));
  if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(doc.id, ECO);
  checkUsable(up, doc.id);
  warnHashIgnored(up);
  const url = `${base(up)}/${encodeURIComponent(doc.scope)}/${encodeURIComponent(doc.name)}/archive/refs/tags/${encodeURIComponent(rel.tag)}.zip`;
  const res = await safefetch.request(url, { headers: headers(up, { accept: 'application/zip' }), timeoutMs: 600000, maxBytes: MAX_ARCHIVE_BYTES, stream: true });
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} git host said ${res.status} for the archive of ${doc.id} ${v}`);
  }
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `swift.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  let head = Buffer.alloc(0);
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        sha256.update(chunk);
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
    if (!head.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) throw httpError(502, `the archive of ${doc.id} ${v} is not a zip, so it was not kept`);
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: doc.id, version: v, filename, upstream: up.name }, { tmp, sha256: sha256.digest('hex') });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } catch (err) {
    if (err.status) throw err;
    throw httpError(502, `the download of ${doc.id} ${v} did not complete: ${err.message}`);
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

// the manifests at the top of a kept archive: Package.swift, and Package@swift-5.9.swift and friends
async function manifests(got) {
  if (got.size > MAX_READ_BYTES) throw httpError(413, 'the archive is too large to read its manifest from');
  const buf = await artifacts.readAll(got);
  const out = {};
  try {
    const list = zip.entries(buf);
    const top = zip.topFolder(list);
    for (const e of list) {
      const rel = e.name.slice(top.length);
      const m = /^Package(?:@swift-(\d+(?:\.\d+){0,2}))?\.swift$/.exec(rel);
      if (!m || !e.name.startsWith(top)) continue;
      out[m[1] || ''] = zip.read(buf, e, MAX_MANIFEST_BYTES);
    }
  } catch (err) {
    // a damaged zip, or a manifest that inflates past the ceiling. the archive's fault, not the box's
    throw httpError(502, `the manifest could not be read from ${got.filename}: ${err.message}`);
  }
  if (!out['']) throw httpError(404, 'the archive has no Package.swift at its top');
  return out;
}

// the Package.swift of a release, from the archive this box keeps
async function manifestText(id, version) {
  const got = await getArchive(id, version);
  const all = await manifests(got);
  return all[''] ? all[''].toString('utf8') : null;
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, parseRefs, releasesFrom, summary, archiveName, getArchive, manifests, manifestText, open };
