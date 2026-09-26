// Talking to a gem source: a gem's compact index info file, its .gem files and gemspecs, and the license list.
// Author: Tim Rice
//
// the info file (/info/<gem>) lists every version with the sha256 of its .gem and when it was pushed. that is the
// summary everything here comes from, and a .gem has to hash to what it says or it is not kept. a gemspec is Marshal,
// which this box never reads: it is passed on as bytes, after the same checks as the gem it belongs to

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const db = require('../../db');
const config = require('../../config');
const safefetch = require('../../security/safefetch');
const upstreams = require('../shared/upstreams');
const mirrorOptions = require('../shared/mirror-options');
const published = require('../shared/published');
const artifacts = require('../../storage/artifacts');
const docs = require('../../db/repositories/package-documents');
const gemName = require('../../ecosystems/rubygems/name');
const gemVersion = require('../../ecosystems/rubygems/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'rubygems';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (RubyGems)`;
const MAX_INFO_BYTES = 16 * 1024 * 1024;
const MAX_GEM_BYTES = 1024 * 1024 * 1024;
const MAX_SPEC_BYTES = 4 * 1024 * 1024;
const MAX_INDEX_BYTES = 64 * 1024 * 1024;
const MAX_LINES = 20000;
const PLATFORM_RE = /^[A-Za-z0-9_.-]{1,64}$/;

const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const base = (up) => String(up.url).replace(/\/+$/, '');
const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

function checkUsable(up, name) {
  if (!up) throw httpError(502, `no gem source is set up to serve ${name}. Add a RubyGems registry under Settings, Registries`);
  if (!up.enabled) throw httpError(503, `the ${up.name} gem source, which serves ${name}, is switched off`);
}

// 1.16.0-x86_64-linux is version 1.16.0 for the platform x86_64-linux. a plain version is for every platform (ruby)
function splitVersion(token) {
  const i = token.indexOf('-');
  if (i === -1) return { version: token, platform: '' };
  const version = token.slice(0, i);
  const platform = token.slice(i + 1);
  // 2.0.0-rc1 has a dash too. a platform starts with a letter and names a system, a pre-release does not
  if (/^(x86|x64|arm|aarch|universal|java|jruby|mswin|mingw|darwin|linux|freebsd|openbsd|netbsd|solaris|cygwin|x64-mingw|ppc|s390|riscv|wasm)/i.test(platform)
    && PLATFORM_RE.test(platform)) {
    return { version, platform };
  }
  return { version: token, platform: '' };
}

// one line of an info file: "1.16.0-x86_64-linux racc:~> 1.4|checksum:abc...,ruby:>= 3.0,created_at:2024-01-01T00:00:00Z"
function parseLine(line) {
  const bar = line.indexOf('|');
  const head = bar === -1 ? line : line.slice(0, bar);
  const tail = bar === -1 ? '' : line.slice(bar + 1);
  const space = head.indexOf(' ');
  const token = space === -1 ? head : head.slice(0, space);
  const { version, platform } = splitVersion(token.trim());
  if (!gemVersion.valid(version)) return null;
  const meta = {};
  for (const part of tail.split(',')) {
    const c = part.indexOf(':');
    if (c > 0) meta[part.slice(0, c).trim()] = part.slice(c + 1).trim();
  }
  const sha256 = /^[0-9a-f]{64}$/.test(meta.checksum || '') ? meta.checksum : null;
  const at = Date.parse(meta.created_at || '');
  return { version, platform, sha256, published: Number.isFinite(at) ? new Date(at).toISOString() : null, line };
}

function parseInfo(text) {
  const out = [];
  const lines = String(text).split('\n');
  const start = lines.indexOf('---');
  for (const raw of lines.slice(start === -1 ? 0 : start + 1, (start === -1 ? 0 : start + 1) + MAX_LINES)) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) continue;
    const got = parseLine(line);
    if (got) out.push(got);
  }
  return out;
}

// a gem's summary from its info file, cached while fresh. { doc: { name, files: [...] }, cacheHit, stale }
// what was pushed here, and what the mirror says, as one index. a reserved name is only ever what was pushed
async function merged(name, doc) {
  const own = await docs.get(ECO, name, published.KIND).catch(() => null);
  const mine = own && own.doc && Array.isArray(own.doc.files) ? own.doc.files : [];
  if (await require('../../policy/private-names').isPrivate(ECO, name)) return { name, files: mine };
  if (!mine.length) return doc;
  const key = (f) => `${f.version}\u0000${f.platform || ''}`;
  const seen = new Set(mine.map(key));
  return { name, files: [...(doc.files || []).filter((f) => !seen.has(key(f))), ...mine] };
}

async function info(name) {
  if (!gemName.valid(name)) throw httpError(400, 'that is not a gem name');
  if (await require('../../policy/private-names').isPrivate(ECO, name)) {
    const own = await docs.get(ECO, name, published.KIND).catch(() => null);
    if (own && own.doc) return { doc: own.doc, cacheHit: true, stale: false };
    throw httpError(404, `${name} is a reserved gem name and nothing has been pushed to it yet. It is never fetched from an upstream`);
  }
  const up = await upstreams.forPackage(name, ECO);
  const held = await docs.get(ECO, name, 'summary');
  const usable = held && up && upstreams.sameSource(held.source, up) ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { doc: await merged(name, usable.doc), cacheHit: true, stale: false };
  if (!upstreamEnabled()) {
    if (held) return { doc: await merged(name, held.doc), cacheHit: true, stale: true };
    const own = await docs.get(ECO, name, published.KIND).catch(() => null);
    if (own && own.doc) return { doc: own.doc, cacheHit: true, stale: false };
    throw httpError(503, `${mode.offlineReason()} and ${name} is not in the cache`);
  }
  if (!held && mode.noNewNames()) throw mode.newName(name);
  checkUsable(up, name);
  try {
    const res = await safefetch.request(`${base(up)}/info/${encodeURIComponent(name)}`, { headers: headers(up, { accept: 'text/plain' }), timeoutMs: 30000, maxBytes: MAX_INFO_BYTES });
    if (res.status === 404) throw httpError(404, `${name} is not on the ${up.name} gem source`);
    if (!res.ok) throw httpError(502, `the ${up.name} gem source said ${res.status} for ${name}`);
    const files = parseInfo((await res.arrayBuffer()).toString('utf8'));
    const doc = { name, files: files.map(({ line, ...f }) => ({ ...f, line })) };
    await docs.put(ECO, name, 'summary', doc, up.name);
    return { doc: await merged(name, doc), cacheHit: false, stale: false };
  } catch (err) {
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} gem source failed for ${name}, answering from the cache`, err.message);
      return { doc: await merged(name, usable.doc), cacheHit: true, stale: true };
    }
    throw err;
  }
}

const fileName = (name, f) => `${name}-${f.version}${f.platform ? `-${f.platform}` : ''}.gem`;

// stream a download to a scratch file, hashing it on the way
async function download(up, url, maxBytes, what) {
  const res = await safefetch.request(url, { headers: headers(up, { accept: '*/*' }), timeoutMs: 600000, maxBytes, stream: true });
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} gem source said ${res.status} for ${what}`);
  }
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `gem.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const sha256 = crypto.createHash('sha256');
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => sha256.update(chunk));
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
    throw httpError(502, `the download of ${what} did not complete: ${err.message}`);
  }
  return { tmp, sha256: sha256.digest('hex') };
}

// one .gem, from the store or the source. it must hash to the checksum the info file gives for it
async function getGem(name, f) {
  const filename = fileName(name, f);
  const held = await artifacts.locate(ECO, name, f.version, filename);
  // a reserved name is only ever what was pushed here, never a copy fetched before it was reserved
  if (await require('../../policy/private-names').isPrivate(ECO, name)) {
    if (held && held.upstream === published.SOURCE) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
    throw httpError(404, `${filename} is reserved and was never pushed here. It is never fetched from an upstream`);
  }
  // a copy from a registry this name is no longer routed to is not this name anymore
  const routed = held && (await upstreams.fromRoute(held.upstream, name, ECO));
  if (held && !routed && !upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, name, ECO));
  if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(name, ECO);
  checkUsable(up, name);
  const got = await download(up, `${base(up)}/gems/${encodeURIComponent(filename)}`, MAX_GEM_BYTES, filename);
  try {
    if (!f.sha256 && mirrorOptions.requiresHash(up)) {
      throw httpError(502, `the ${up.name} gem source gives no checksum for ${filename}, so it can not be checked and was not kept`);
    }
    // with none listed there is nothing to compare against, so only compare when there is
    if (f.sha256 && got.sha256 !== f.sha256) {
      log.error(`${filename} came back as sha256 ${got.sha256}, the info file says ${f.sha256}. not keeping it`);
      throw httpError(502, `${filename} does not match the checksum the ${up.name} gem source lists for it, so it was not kept`);
    }
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: name, version: f.version, filename, upstream: up.name }, { tmp: got.tmp, sha256: got.sha256 });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } finally {
    await fsp.unlink(got.tmp).catch(() => {});
  }
}

// the gemspec gem install asks for, as bytes. kept like any file, so a kill or a hold reaches it too
async function getSpec(name, f) {
  // a reserved name is only ever what was pushed here
  if (await require('../../policy/private-names').isPrivate(ECO, name)) {
    const own = `${fileName(name, f).slice(0, -4)}.gemspec.rz`;
    const mine = await artifacts.locate(ECO, name, f.version, own).catch(() => null);
    if (mine && mine.upstream === published.SOURCE) return { artifactId: mine.id, sha256: mine.sha256, size: mine.size, cacheHit: true, filename: own };
    throw httpError(404, `${name} ${f.version} is reserved and its gemspec was not pushed here`);
  }
  const filename = `${fileName(name, f).slice(0, -4)}.gemspec.rz`;
  const held = await artifacts.locate(ECO, name, f.version, filename);
  // a copy from a registry this name is no longer routed to is not this name anymore
  const routed = held && (await upstreams.fromRoute(held.upstream, name, ECO));
  if (held && !routed && !upstreamEnabled()) throw httpError(503, upstreams.movedReason(filename, held.upstream, name, ECO));
  if (routed) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  const up = await upstreams.forPackage(name, ECO);
  checkUsable(up, name);
  const got = await download(up, `${base(up)}/quick/Marshal.4.8/${encodeURIComponent(filename)}`, MAX_SPEC_BYTES, filename);
  try {
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: name, version: f.version, filename, upstream: up.name }, { tmp: got.tmp, sha256: got.sha256 });
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } finally {
    await fsp.unlink(got.tmp).catch(() => {});
  }
}

// the full index files (specs.4.8.gz and friends) gem sources --add checks for. a list of names and versions, passed on
// from the default source as it is. nothing in it is installed from, the gem files are what get checked
async function indexFile(file) {
  if (!upstreamEnabled()) throw httpError(503, mode.offlineReason());
  const up = await upstreams.forPackage('', ECO);
  checkUsable(up, file);
  const res = await safefetch.request(`${base(up)}/${file}`, { headers: headers(up), timeoutMs: 120000, maxBytes: MAX_INDEX_BYTES });
  if (!res.ok) throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} gem source said ${res.status} for ${file}`);
  return res.arrayBuffer();
}

// the license names rubygems.org lists per version, or null when the source has no such API
async function licenses(name, version) {
  const up = await upstreams.forPackage(name, ECO);
  checkUsable(up, name);
  const res = await safefetch.request(`${base(up)}/api/v1/versions/${encodeURIComponent(name)}.json`, { headers: headers(up, { accept: 'application/json' }), timeoutMs: 30000, maxBytes: MAX_INFO_BYTES });
  if (!res.ok) return null;
  const list = await res.json().catch(() => null);
  const hit = Array.isArray(list) ? list.find((x) => x && x.number === version && (!x.platform || x.platform === 'ruby')) || list.find((x) => x && x.number === version) : null;
  return hit && Array.isArray(hit.licenses) ? hit.licenses.filter((l) => typeof l === 'string').slice(0, 10) : null;
}

// every gem name the default source has (its /names list, about 200 thousand), plus the names this box has already
// summed up (a source with no /names, or one set up for a pattern). bundler only asks /info about names it finds in
// /versions, so this is how a gem nobody approved yet still reaches the rules and opens a request
const NAMES_TTL_MS = 60 * 60 * 1000;
let named = null;
// a push adds a name, and the list is kept for an hour, so it is thrown away when one arrives
function invalidateNames() {
  named = null;
}

async function names() {
  if (named && named.until > Date.now()) return named.list;
  const out = new Set(await docs.names(ECO));
  const up = await upstreams.forPackage('', ECO).catch(() => null);
  if (up && up.enabled && upstreamEnabled()) {
    try {
      const res = await safefetch.request(`${base(up)}/names`, { headers: headers(up, { accept: 'text/plain' }), timeoutMs: 60000, maxBytes: 32 * 1024 * 1024 });
      if (res.ok) {
        const text = (await res.arrayBuffer()).toString('utf8');
        for (const n of text.split('\n')) if (gemName.valid(n.trim())) out.add(n.trim());
      }
    } catch (err) {
      log.warn(`the ${up.name} gem source did not give its name list`, err.message);
    }
  }
  const list = [...out].sort();
  named = { list, until: Date.now() + (list.length ? NAMES_TTL_MS : 60000) };
  return list;
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, splitVersion, parseLine, parseInfo, info, fileName, getGem, getSpec, indexFile, licenses, names, invalidateNames, open };
