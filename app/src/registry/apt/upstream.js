// Talking to an APT repository (a Debian or Ubuntu archive): each suite's Release, the index files it lists, packages.
// Author: Tim Rice
//
// dists/<suite>/InRelease lists every index file of the suite with its SHA256 and size, so a copy is checked on the way
// in and kept under that checksum. binary-<arch>/Packages lists every package with its SHA256; it is read when a
// package of it is first asked for, into an index kept in memory, and every .deb is checked against it before it is kept.
// the signature on InRelease is the client's to check (see signing.js for the filtered index, which the box checks)

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
const debName = require('../../ecosystems/apt/name');
const debVersion = require('../../ecosystems/apt/version');
const mode = require('../../policy/mode');
const log = require('../../logger');
const { httpError } = require('../../lib/errors');

const ECO = 'apt';
const USER_AGENT = `ForgeRepo/${require('../../../package.json').version} (APT mirror)`;
const MAX_RELEASE_BYTES = 8 * 1024 * 1024;
const MAX_META_BYTES = 1024 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_PACKAGES = 500000;
const DEB_MAGIC = Buffer.from('!<arch>\n');
const SUITE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

const dir = () => path.join(config.cacheDir, 'apt');
const workDir = path.join(config.cacheDir, 'tmp');

function upstreamEnabled() {
  return db.settings.getBool('upstream_enabled') && !mode.lockdown();
}

const headers = (up, extra) => upstreams.headersFor(up, { 'user-agent': USER_AGENT, ...(extra || {}) });

async function mirror(s) {
  return (await upstreams.all(ECO)).find((u) => mirrorOptions.slug(u.name) === s) || null;
}

function checkUsable(up) {
  if (!up.enabled) throw httpError(503, `the ${up.name} mirror is switched off`);
}

// the text inside a clearsigned message, dash escapes undone. only for reading hashes, the client checks the signature
function unsigned(text) {
  const t = String(text);
  if (!t.startsWith('-----BEGIN PGP SIGNED MESSAGE-----')) return t;
  const start = t.indexOf('\n\n');
  const end = t.indexOf('\n-----BEGIN PGP SIGNATURE-----');
  if (start < 0 || end < start) return '';
  return t.slice(start + 2, end).split('\n').map((l) => (l.startsWith('- ') ? l.slice(2) : l)).join('\n');
}

// a Release file: its fields, and the SHA256 list [{ sha256, size, path }]
function parseRelease(text) {
  const fields = {};
  const files = [];
  let section = null;
  for (const line of String(text).split('\n')) {
    if (/^\s/.test(line)) {
      if (section === 'SHA256') {
        const m = /^\s+([0-9a-f]{64})\s+(\d+)\s+(\S+)$/.exec(line);
        // only paths inside the suite, nothing that climbs out of it
        if (m && !m[3].split('/').includes('..') && !m[3].startsWith('/')) files.push({ sha256: m[1], size: Number(m[2]), path: m[3] });
      }
      continue;
    }
    const kv = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
    if (!kv) continue;
    section = kv[1];
    if (!['MD5Sum', 'SHA1', 'SHA256', 'SHA512'].includes(kv[1])) fields[kv[1]] = kv[2];
  }
  return { fields, files };
}

// a suite's InRelease (or Release and Release.gpg), fresh or from the cache
async function release(up, suite) {
  if (!SUITE_RE.test(suite)) throw httpError(404, 'that is not a suite name');
  const key = `release:${mirrorOptions.slug(up.name)}:${suite}`;
  const held = await docs.get(ECO, key, 'release');
  const usable = held && upstreams.sameSource(held.source, up) && held.doc.url === up.url ? held : null;
  const ttl = db.settings.getInt('packument_ttl', 300) * 1000;
  const staleOk = db.settings.getInt('stale_ok_seconds', 604800) * 1000;
  const shaped = (doc, cacheHit) => ({ ...doc, parsed: parseRelease(unsigned(doc.inrelease || doc.release)), cacheHit });
  if (usable && Date.now() - usable.fetchedAt.getTime() < ttl) return shaped(usable.doc, true);
  if (!upstreamEnabled()) {
    if (usable) return shaped(usable.doc, true);
    throw httpError(503, `${mode.offlineReason()} and the ${suite} index of ${up.name} is not in the cache`);
  }
  checkUsable(up);
  const get = async (name) => {
    const res = await safefetch.request(`${up.url}/dists/${suite}/${name}`, { headers: headers(up), timeoutMs: 30000, maxBytes: MAX_RELEASE_BYTES });
    if (res.status === 404) return null;
    if (!res.ok) throw httpError(502, `the ${up.name} mirror said ${res.status} for dists/${suite}/${name}`);
    return (await res.arrayBuffer()).toString('utf8');
  };
  try {
    const inrelease = await get('InRelease');
    const plain = inrelease ? null : await get('Release');
    if (!inrelease && !plain) throw httpError(404, `${suite} is not a suite of the ${up.name} mirror`);
    const releaseGpg = plain ? await get('Release.gpg') : null;
    const doc = { inrelease, release: plain, releaseGpg, url: up.url };
    if (!parseRelease(unsigned(inrelease || plain)).files.length) throw httpError(502, `the ${suite} Release of ${up.name} lists no files`);
    await docs.put(ECO, key, 'release', doc, up.name);
    return shaped(doc, false);
  } catch (err) {
    if (err.status !== 404 && usable && Date.now() - usable.fetchedAt.getTime() < staleOk) {
      log.warn(`the ${up.name} mirror failed for the ${suite} Release, answering from the cache`, err.message);
      return shaped(usable.doc, true);
    }
    throw err;
  }
}

// the suites of a mirror that anybody asked for so far
async function knownSuites(up) {
  const prefix = `release:${mirrorOptions.slug(up.name)}:`;
  const rows = await db.query("SELECT name FROM package_documents WHERE ecosystem = 'apt' AND kind = 'release' AND name LIKE ? LIMIT 200", [`${prefix}%`]);
  return rows.map((r) => r.name.slice(prefix.length)).filter((s) => SUITE_RE.test(s));
}

// stream a url into a file, checking it against its sha256 and size. the temp file, or it throws
async function fetchChecked(up, url, rel, sha256, size, maxBytes, magic) {
  await fsp.mkdir(workDir, { recursive: true });
  const tmp = path.join(workDir, `apt.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let res;
  try {
    res = await safefetch.request(url, { headers: headers(up), timeoutMs: 1800000, maxBytes: Math.min(maxBytes, size ? size + 1 : maxBytes), stream: true });
  } catch (err) {
    throw httpError(502, `${rel} could not be fetched from the ${up.name} mirror: ${err.message}`);
  }
  if (!res.ok) {
    if (res.stream) res.stream.resume();
    throw httpError(res.status === 404 ? 404 : 502, `the ${up.name} mirror said ${res.status} for ${rel}`);
  }
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  let head = Buffer.alloc(0);
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp, { mode: 0o640 });
      res.stream.on('data', (chunk) => {
        hash.update(chunk);
        bytes += chunk.length;
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
    if (magic && !head.equals(magic)) throw httpError(502, `${rel} from the ${up.name} mirror is not a Debian package, so it was not kept`);
    const got = hash.digest('hex');
    if (got !== sha256 || (size && bytes !== size)) {
      log.error(`${up.name}: ${rel} does not match the SHA256 its index lists, not keeping it`);
      throw httpError(502, `${rel} from the ${up.name} mirror does not match the SHA256 its index lists, so it was not kept`);
    }
    return { tmp, sha256: got };
  } catch (err) {
    await fsp.unlink(tmp).catch(() => {});
    if (err.status) throw err;
    throw httpError(502, `the download of ${rel} from the ${up.name} mirror did not complete: ${err.message}`);
  }
}

// an index file of a suite, kept on disk under its SHA256. entry is one line of the Release SHA256 list
const inflight = new Map();
async function metaFile(up, suite, entry, byHash) {
  await fsp.mkdir(dir(), { recursive: true });
  const file = path.join(dir(), `${entry.sha256}.meta`);
  if (await fsp.stat(file).then(() => true, () => false)) return file;
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${entry.path} is not in the cache`);
  if (!inflight.has(file)) {
    // by hash where the suite offers it, so a file that changed upstream in between is never mistaken for this one
    const rel = byHash ? `${path.posix.dirname(entry.path)}/by-hash/SHA256/${entry.sha256}` : entry.path;
    inflight.set(file, (async () => {
      const got = await fetchChecked(up, `${up.url}/dists/${suite}/${rel}`, `dists/${suite}/${rel}`, entry.sha256, entry.size, MAX_META_BYTES, null);
      await fsp.rename(got.tmp, file);
      return file;
    })().finally(() => inflight.delete(file)));
  }
  return inflight.get(file);
}

// every stanza of a Packages file, as a { Field: value } object, in order
async function eachStanza(file, name, onStanza) {
  let input = fs.createReadStream(file);
  if (name.endsWith('.gz')) input = input.pipe(zlib.createGunzip());
  else if (name.endsWith('.xz') || name.endsWith('.bz2') || name.endsWith('.lzma')) throw httpError(502, `${name} is packed in a way this box does not read`);
  const decoder = new StringDecoder('utf8');
  let buf = '';
  const take = async (text) => {
    const st = {};
    let last = null;
    for (const line of text.split('\n')) {
      if (/^\s/.test(line)) {
        if (last) st[last] += `\n${line}`;
        continue;
      }
      const m = /^([A-Za-z0-9-]+):\s?(.*)$/.exec(line);
      if (m) {
        last = m[1];
        st[last] = m[2];
      }
    }
    if (Object.keys(st).length) await onStanza(st, text);
  };
  for await (const chunk of input) {
    buf += decoder.write(chunk);
    let end;
    while ((end = buf.indexOf('\n\n')) >= 0) {
      await take(buf.slice(0, end));
      buf = buf.slice(end + 2);
    }
    if (buf.length > 16 * 1024 * 1024) throw httpError(502, `${name} has a stanza larger than 16MB`);
  }
  if (buf.trim()) await take(buf.replace(/\n+$/, ''));
}

// what one Packages stanza says. null when it is not a usable package entry
function readStanza(st) {
  const name = st.Package;
  const version = st.Version;
  const filename = st.Filename;
  if (!name || !version || !filename || !st.SHA256 || !debName.valid(name) || !debVersion.valid(version)) return null;
  if (!/^pool\/[A-Za-z0-9._+~/-]+\.u?deb$/.test(filename) || filename.split('/').includes('..') || filename.length > 400) return null;
  if (!/^[0-9a-f]{64}$/.test(st.SHA256)) return null;
  // Source: openssl, or Source: openssl (3.0.11-1~deb12u2) when the binary's version differs
  const src = /^([a-z0-9][a-z0-9+.-]+)(?:\s+\(([^)]+)\))?$/.exec(String(st.Source || '').trim());
  return {
    name, version, arch: st.Architecture || '', filename, sha256: st.SHA256, size: Number(st.Size) || null,
    source: src ? src[1] : name, sourceVersion: src && src[2] ? src[2] : version,
    depends: [st['Pre-Depends'], st.Depends].filter(Boolean).join(', ').slice(0, 4000)
  };
}

// the index of one Packages file: { entries, byFilename, byName }
//
// verified is the { fields, files } of an InRelease whose signature the caller
// already checked. Anything this box signs has to take its hashes from there:
// reading release() again could pick up a refetched, unchecked copy.
const indexes = new Map();
async function packagesIndex(up, suite, comp, arch, verified) {
  const rel = verified ? { parsed: verified } : await release(up, suite);
  const want = [`${comp}/binary-${arch}/Packages.gz`, `${comp}/binary-${arch}/Packages`];
  const entry = want.map((p) => rel.parsed.files.find((f) => f.path === p)).find(Boolean);
  if (!entry) return null;
  const key = `${up.name}\u0000${suite}\u0000${entry.sha256}`;
  const held = indexes.get(`${up.name}\u0000${suite}\u0000${comp}\u0000${arch}`);
  if (held && held.key === key) return held.promise;
  const promise = (async () => {
    const file = await metaFile(up, suite, entry, /yes/i.test(rel.parsed.fields['Acquire-By-Hash'] || ''));
    const entries = [];
    await eachStanza(file, entry.path, (st) => {
      const p = readStanza(st);
      if (p && entries.length < MAX_PACKAGES) entries.push(p);
    });
    const byFilename = new Map(entries.map((p) => [p.filename, p]));
    const byName = new Map();
    for (const p of entries) {
      if (!byName.has(p.name)) byName.set(p.name, []);
      byName.get(p.name).push(p);
    }
    log.info(`${up.name}: ${entries.length} packages in ${suite} ${comp} ${arch}`);
    return { entry, entries, byFilename, byName };
  })();
  indexes.set(`${up.name}\u0000${suite}\u0000${comp}\u0000${arch}`, { key, promise });
  promise.catch(() => indexes.delete(`${up.name}\u0000${suite}\u0000${comp}\u0000${arch}`));
  return promise;
}

// which index entry a pool path is, looking through the suites clients use. { suite, p } or null
async function findPool(up, filename) {
  const parts = filename.split('/');
  const comp = parts[1];
  const arch = (/_([a-z0-9-]+)\.u?deb$/.exec(filename) || [])[1];
  if (!comp || !arch) return null;
  for (const suite of await knownSuites(up)) {
    let rel;
    try {
      rel = await release(up, suite);
    } catch (err) {
      continue;
    }
    const archs = arch === 'all' ? String(rel.parsed.fields.Architectures || '').split(/\s+/).filter((a) => a && a !== 'all') : [arch];
    // a component path can be nested (updates/main), the pool path only names the top
    const comps = String(rel.parsed.fields.Components || '').split(/\s+/).filter((c) => c === comp || c.endsWith(`/${comp}`));
    for (const c of comps) {
      for (const a of archs) {
        const idx = await packagesIndex(up, suite, c, a).catch(() => null);
        const p = idx && idx.byFilename.get(filename);
        if (p) return { suite, p };
      }
    }
  }
  return null;
}

const baseName = (p) => p.filename.split('/').pop();

async function getPackage(up, p) {
  const filename = baseName(p);
  const held = await artifacts.locate(ECO, p.name, p.version, filename);
  // the name is all the lookup goes by, so a held copy only counts when it is the file this index lists. another
  // mirror's build under the same name, or one the mirror has since replaced, is fetched again
  if (held && held.sha256 === p.sha256) return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true, filename };
  if (held) log.warn(`${up.name}: the held copy of ${filename} is not the one its index lists now, fetching it again`);
  if (!upstreamEnabled()) throw httpError(503, `${mode.offlineReason()} and ${filename} is not in the cache`);
  checkUsable(up);
  const before = refused.recall(up.name, filename, p.sha256);
  if (before) throw before;
  const got = await fetchChecked(up, `${up.url}/${p.filename}`, p.filename, p.sha256, p.size, MAX_PACKAGE_BYTES, DEB_MAGIC);
  try {
    const kept = await artifacts.keep({
      ecosystem: ECO, packageName: p.name, version: p.version, filename, upstream: up.name,
      // advisory feeds file Debian packages under their source package
      metadata: { source: p.source, sourceVersion: p.sourceVersion }
    }, got);
    // the same mirror handing out other bytes under a name it already served keeps the first copy and raises an
    // integrity alert. that first copy is not what the index lists, so it is not served either
    if (kept.sha256 !== got.sha256) {
      const err = httpError(502, `${filename} from the ${up.name} mirror is not the copy first seen under that name, so it was not served. An admin can review it under Integrity alerts`);
      refused.remember(up.name, filename, p.sha256, err);
      throw err;
    }
    return { artifactId: kept.id, sha256: kept.sha256, size: kept.size, cacheHit: false, filename };
  } finally {
    await fsp.unlink(got.tmp).catch(() => {});
  }
}

// every enabled mirror's entries for a package, in the suites and architectures clients used: [{ up, p }]
async function everywhere(name) {
  const out = [];
  for (const up of (await upstreams.all(ECO)).filter((u) => u.enabled)) {
    for (const suite of await knownSuites(up)) {
      let rel;
      try {
        rel = await release(up, suite);
      } catch (err) {
        continue;
      }
      for (const f of rel.parsed.files) {
        const m = /^(.+)\/binary-([a-z0-9-]+)\/Packages\.gz$/.exec(f.path);
        if (!m || !indexes.has(`${up.name}\u0000${suite}\u0000${m[1]}\u0000${m[2]}`)) continue;
        const idx = await packagesIndex(up, suite, m[1], m[2]).catch(() => null);
        for (const p of (idx && idx.byName.get(name)) || []) out.push({ up, p });
      }
    }
  }
  return out;
}

const open = (got) => artifacts.open(got);

module.exports = { ECO, SUITE_RE, mirror, unsigned, parseRelease, release, knownSuites, metaFile, eachStanza, readStanza, packagesIndex, findPool, baseName, getPackage, everywhere, open };
