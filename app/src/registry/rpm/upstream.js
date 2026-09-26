// Talking to an RPM repository: its index (repodata/repomd.xml and the files it lists) and its packages.
// Author: Tim Rice
//
// repomd.xml names every metadata file with its checksum, and the files are named after that checksum, so a copy is
// checked on the way in and never changes. primary.xml lists every package with its version, where it is and its
// checksum; it is read once per revision into an index kept in memory, streamed, since it runs to hundreds of MB.
// packages are checked against the checksum primary.xml gives before they are kept

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const { StringDecoder } = require('string_decoder');
const db = require('../../db');
const config = require('../../config');
const safefetch = require('../../security/safefetch');
const upstreams = require('../shared/upstreams');
const mirrorOptions = require('../shared/mirror-options');
const artifacts = require('../../storage/artifacts');
const refused = require('../shared/refused');
const docs = require('../../db/repositories/package-documents');
const rpmName = require('../../ecosystems/rpm/name');
const rpmVersion = require('../../ecosystems/rpm/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'rpm';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (RPM mirror)`;
const MAX_REPOMD_BYTES = 4 * 1024 * 1024;
const MAX_META_BYTES = 1024 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_PACKAGES = 500000;
const ALGOS = { sha: 'sha1', sha1: 'sha1', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512' };
const RPM_MAGIC = Buffer.from([0xed, 0xab, 0xee, 0xdb]);

const dir = () => path.join(config.cacheDir, 'rpm');
const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

// the mirror an address names, by its name's slug. null when there is none
async function mirror(s) {
  return (await upstreams.all(ECO)).find((u) => mirrorOptions.slug(u.name) === s) || null;
}

function checkUsable(up) {
  if (!up.enabled) throw httpError(503, `the ${up.name} mirror is switched off`);
}

const unxml = (s) => String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const attr = (tag, name) => {
  const m = new RegExp(`\\s${name}="([^"]*)"`).exec(tag);
  return m ? unxml(m[1]) : null;
};

// the metadata files repomd.xml lists: [{ type, href, algo, checksum, size, block }]
// the <data> blocks and their <location> are found with indexOf and anchored regexes, not a lazy [\s\S]*? or a
// [^>]* tried from every opening, since those go quadratic on a file stuffed with openings that never close
function parseRepomd(xml) {
  const out = [];
  const open = /<data\s+type="([A-Za-z0-9_-]{1,40})"\s*>/y;
  const location = (body) => {
    const re = /<location\s[^>]*href="([^"]+)"/y;
    for (let at = body.indexOf('<location'); at >= 0; ) {
      if (!/\s/.test(body[at + 9] || '')) {
        at = body.indexOf('<location', at + 1);
        continue;
      }
      re.lastIndex = at;
      const loc = re.exec(body);
      if (loc) return loc;
      // an opening between this one and its > only sees a part of the same attributes, so it cannot match either
      const gt = body.indexOf('>', at);
      if (gt < 0) return null;
      at = body.indexOf('<location', gt);
    }
    return null;
  };
  for (let at = xml.indexOf('<data'); at >= 0; ) {
    open.lastIndex = at;
    const m = open.exec(xml);
    if (!m) {
      at = xml.indexOf('<data', at + 1);
      continue;
    }
    const close = xml.indexOf('</data>', open.lastIndex);
    if (close < 0) break;
    const end = close + '</data>'.length;
    at = xml.indexOf('<data', end);
    const body = xml.slice(open.lastIndex, close);
    const ck = /<checksum\s+type="([a-z0-9]+)"\s*>([0-9a-f]{40,128})<\/checksum>/.exec(body);
    const loc = location(body);
    if (!ck || !loc || !ALGOS[ck[1]]) continue;
    const href = unxml(loc[1]);
    // only files of the repository's own repodata folder
    if (!/^repodata\/[A-Za-z0-9._-]+$/.test(href)) continue;
    const size = /<size>(\d+)<\/size>/.exec(body);
    out.push({ type: m[1], href, algo: ALGOS[ck[1]], checksum: ck[2], size: size ? Number(size[1]) : null, block: xml.slice(m.index, end) });
  }
  return out;
}

// repomd.xml of a mirror, fresh or from the cache. { xml, entries, cacheHit }
async function repomd(up) {
  const key = `repomd:${mirrorOptions.slug(up.name)}`;
  const held = await docs.get(ECO, key, 'repomd');
  const usable = held && upstreams.sameSource(held.source, up) && held.doc.url === up.url ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return { xml: usable.doc.xml, entries: parseRepomd(usable.doc.xml), cacheHit: true };
  if (!upstreamEnabled()) {
    if (usable) return { xml: usable.doc.xml, entries: parseRepomd(usable.doc.xml), cacheHit: true };
    throw httpError(503, `${mode.offlineReason()} and the index of ${up.name} is not in the cache`);
  }
  checkUsable(up);
  try {
    const res = await safefetch.request(`${up.url}/repodata/repomd.xml`, { headers: headers(up), timeoutMs: 30000, maxBytes: MAX_REPOMD_BYTES });
    if (!res.ok) throw httpError(502, `the ${up.name} mirror said ${res.status} for repodata/repomd.xml`);
    const xml = (await res.arrayBuffer()).toString('utf8');
    if (!/<repomd[\s>]/.test(xml) || !parseRepomd(xml).some((e) => e.type === 'primary')) throw httpError(502, `the ${up.name} mirror's repomd.xml does not list a primary index`);
    // the signature goes with it, if the repository has one. it is only ever handed out next to this exact file
    let asc = null;
    const sig = await safefetch.request(`${up.url}/repodata/repomd.xml.asc`, { headers: headers(up), timeoutMs: 30000, maxBytes: 64 * 1024 }).catch(() => null);
    if (sig && sig.ok) asc = (await sig.arrayBuffer()).toString('utf8');
    await docs.put(ECO, key, 'repomd', { xml, asc, url: up.url }, up.name);
    return { xml, entries: parseRepomd(xml), cacheHit: false };
  } catch (err) {
    if (usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} mirror failed for repomd.xml, answering from the cache`, err.message);
      return { xml: usable.doc.xml, entries: parseRepomd(usable.doc.xml), cacheHit: true };
    }
    throw err;
  }
}

// the signature that goes with the repomd.xml last fetched, or null
async function repomdSignature(up) {
  const held = await docs.get(ECO, `repomd:${mirrorOptions.slug(up.name)}`, 'repomd');
  return held && held.doc.url === up.url ? held.doc.asc || null : null;
}

// stream a url into a file, checking it against the checksum it is known by. the file path, or it throws
async function fetchChecked(up, rel, algo, checksum, maxBytes, magic) {
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `rpm.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let res;
  try {
    res = await safefetch.request(`${up.url}/${rel}`, { headers: headers(up), timeoutMs: 1800000, maxBytes, stream: true });
  } catch (err) {
    throw httpError(502, `${rel} could not be fetched from the ${up.name} mirror: ${err.message}`);
  }
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} mirror said ${res.status} for ${rel}`);
  }
  const hash = crypto.createHash(algo);
  const sha256 = crypto.createHash('sha256');
  let head = Buffer.alloc(0);
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        hash.update(chunk);
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
    if (magic && !head.equals(magic)) throw httpError(502, `${rel} from the ${up.name} mirror is not an RPM, so it was not kept`);
    if (hash.digest('hex') !== checksum) {
      log.error(`${up.name}: ${rel} does not match the checksum the repository lists, not keeping it`);
      throw httpError(502, `${rel} from the ${up.name} mirror does not match the checksum its repository lists, so it was not kept`);
    }
    return { tmp, sha256: sha256.digest('hex') };
  } catch (err) {
    await fsp.unlink(tmp).catch(() => {});
    if (err.status) throw err;
    throw httpError(502, `the download of ${rel} from the ${up.name} mirror did not complete: ${err.message}`);
  }
}

// a metadata file, kept on disk under its own checksum. the path to read it from
const inflight = new Map();
async function metaFile(up, entry) {
  await fsp.mkdir(dir(), { recursive: true });
  const file = path.join(dir(), `${entry.checksum}.meta`);
  if (await fsp.stat(file).then(() => true, () => false)) return file;
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${entry.href} is not in the cache`);
  if (!inflight.has(file)) {
    inflight.set(file, (async () => {
      const got = await fetchChecked(up, entry.href, entry.algo, entry.checksum, MAX_META_BYTES, null);
      await fsp.rename(got.tmp, file);
      return file;
    })().finally(() => inflight.delete(file)));
  }
  return inflight.get(file);
}

// the text of a metadata file, however it is packed. .xz and .bz2 are not read here
function textStream(file, href) {
  const raw = fs.createReadStream(file);
  if (href.endsWith('.gz')) return raw.pipe(zlib.createGunzip());
  if (href.endsWith('.zst')) return raw.pipe(zlib.createZstdDecompress());
  if (href.endsWith('.xml')) return raw;
  throw httpError(502, `${href} is packed in a way this box does not read (only gzip and zstd)`);
}

// every <package> block of primary.xml, and the text before the first one (the header), in order
async function eachPackage(file, href, onHeader, onBlock) {
  const decoder = new StringDecoder('utf8');
  let buf = '';
  let headerDone = false;
  for await (const chunk of textStream(file, href)) {
    buf += decoder.write(chunk);
    if (!headerDone) {
      const first = buf.indexOf('<package');
      if (first < 0) {
        if (buf.length > 1024 * 1024) throw httpError(502, `${href} does not look like a primary index`);
        continue;
      }
      await onHeader(buf.slice(0, first));
      buf = buf.slice(first);
      headerDone = true;
    }
    let end;
    while ((end = buf.indexOf('</package>')) >= 0) {
      await onBlock(buf.slice(0, end + 10));
      buf = buf.slice(end + 10).replace(/^\s+/, '');
    }
    if (buf.length > 64 * 1024 * 1024) throw httpError(502, `${href} has a package entry larger than 64MB, which is not a primary index`);
  }
}

// what one <package> block says. null when it is not a usable rpm entry
function readBlock(block) {
  if (!/^<package\s[^>]*type="rpm"/.test(block)) return null;
  const tag = (t) => {
    const m = new RegExp(`<${t}>([^<]*)</${t}>`).exec(block);
    return m ? unxml(m[1]) : null;
  };
  const name = tag('name');
  const arch = tag('arch');
  const vtag = /<version\s[^>]*\/?>/.exec(block);
  const ck = /<checksum\s+type="([a-z0-9]+)"[^>]*>([0-9a-f]{40,128})<\/checksum>/.exec(block);
  const loc = /<location\s[^>]*\/?>/.exec(block);
  if (!name || !arch || !vtag || !ck || !loc || !rpmName.valid(name) || !ALGOS[ck[1]]) return null;
  const href = attr(loc[0], 'href');
  // a package somewhere else than this repository (xml:base) is not mirrored
  if (!href || attr(loc[0], 'xml:base') || href.startsWith('/') || href.split('/').includes('..') || !/\.rpm$/.test(href) || href.length > 400) return null;
  const epoch = Number(attr(vtag[0], 'epoch') || 0);
  const ver = attr(vtag[0], 'ver');
  const rel = attr(vtag[0], 'rel');
  const version = `${epoch ? `${epoch}:` : ''}${ver}-${rel}`;
  if (!rpmVersion.valid(version)) return null;
  const size = /<size\s[^>]*package="(\d+)"/.exec(block);
  const time = /<time\s[^>]*build="(\d+)"/.exec(block);
  const license = /<rpm:license>([^<]*)<\/rpm:license>/.exec(block);
  return {
    name, arch, version, href, algo: ALGOS[ck[1]], checksum: ck[2],
    size: size ? Number(size[1]) : null,
    published: time ? new Date(Number(time[1]) * 1000).toISOString() : null,
    license: license ? unxml(license[1]).slice(0, 200) : ''
  };
}

// the package index of a mirror at its current revision: { primary, packages, byHref, byName }
const indexes = new Map();
async function index(up) {
  const { entries } = await repomd(up);
  const primary = entries.find((e) => e.type === 'primary');
  const key = `${up.name}\u0000${primary.checksum}`;
  const held = indexes.get(up.name);
  if (held && held.key === key) return held.promise;
  const promise = (async () => {
    const file = await metaFile(up, primary);
    const packages = [];
    await eachPackage(file, primary.href, () => {}, (block) => {
      const p = readBlock(block);
      if (p && packages.length < MAX_PACKAGES) packages.push(p);
    });
    const byHref = new Map(packages.map((p) => [p.href, p]));
    const byName = new Map();
    for (const p of packages) {
      if (!byName.has(p.name)) byName.set(p.name, []);
      byName.get(p.name).push(p);
    }
    log.info(`${up.name}: ${packages.length} packages in its index`);
    return { primary, packages, byHref, byName };
  })();
  indexes.set(up.name, { key, promise });
  promise.catch(() => {
    if (indexes.get(up.name) && indexes.get(up.name).promise === promise) indexes.delete(up.name);
  });
  return promise;
}

const filenameOf = (p) => p.href.split('/').pop();

// what a held copy hashes to under the algorithm an index uses. its sha256 is on record; anything else (older repos
// list sha1, some sha512) means reading the copy once. the answer is remembered, the bytes behind a sha256 never change
const heldDigests = new Map();
async function heldDigest(held, algo) {
  if (algo === 'sha256') return held.sha256;
  const key = `${held.sha256}\u0000${algo}`;
  if (heldDigests.has(key)) return heldDigests.get(key);
  const hash = crypto.createHash(algo);
  for await (const chunk of artifacts.open(held)) hash.update(chunk);
  const hex = hash.digest('hex');
  if (heldDigests.size >= 10000) heldDigests.delete(heldDigests.keys().next().value);
  heldDigests.set(key, hex);
  return hex;
}

// a package, from the store or from the mirror, checked against its index entry
async function getPackage(up, p) {
  const filename = filenameOf(p);
  const held = await artifacts.locate(ECO, p.name, p.version, filename);
  // the name is all the lookup goes by, so a held copy only counts when it is the file this index lists. another
  // mirror's build under the same name, or one the mirror has since replaced, is fetched again
  if (held && (await heldDigest(held, p.algo).catch(() => null)) === p.checksum) {
    return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  }
  if (held) log.warn(`${up.name}: the held copy of ${filename} is not the one its index lists now, fetching it again`);
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  checkUsable(up);
  const before = refused.recall(up.name, filename, p.checksum);
  if (before) throw before;
  const got = await fetchChecked(up, p.href, p.algo, p.checksum, MAX_PACKAGE_BYTES, RPM_MAGIC);
  try {
    const kept = await artifacts.keep({ ecosystem: ECO, packageName: p.name, version: p.version, filename, upstream: up.name }, got);
    // the same mirror handing out other bytes under a name it already served keeps the first copy and raises an
    // integrity alert. that first copy is not what the index lists, so it is not served either
    if (kept.sha256 !== got.sha256) {
      const err = httpError(502, `${filename} from the ${up.name} mirror is not the copy first seen under that name, so it was not served. An admin can review it under Integrity alerts`);
      refused.remember(up.name, filename, p.checksum, err);
      throw err;
    }
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } finally {
    await fsp.unlink(got.tmp).catch(() => {});
  }
}

// every enabled mirror's entries for a package name: [{ up, p }]
async function everywhere(name) {
  const out = [];
  for (const up of (await upstreams.all(ECO)).filter((u) => u.enabled)) {
    try {
      const idx = await index(up);
      for (const p of idx.byName.get(name) || []) out.push({ up, p });
    } catch (err) {
      log.warn(`${up.name}: its index could not be read`, err.message);
    }
  }
  return out;
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, mirror, parseRepomd, repomd, repomdSignature, metaFile, textStream, eachPackage, readBlock, index, filenameOf, getPackage, everywhere, open };
