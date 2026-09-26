// The filtered index of an APT mirror: each suite's Packages files with only what the rules and the kill switch let
// through, and a Release listing them, signed by this box. only for mirrors set to filter, see mirror-options.js
// Author: Tim Rice
//
// the distro's own InRelease is checked first (signing.verified), so nothing the distro did not sign is ever vouched
// for. filtered Packages are made for amd64 and arm64; other architectures are left out of the filtered Release. every
// other file of the suite (translations, contents) keeps the distro's hash. files are named after their own SHA256
// and made once, so a change of rules gives new files. what a hold, an advisory or cooling off would refuse is still
// refused on download

const crypto = require('crypto');
const fsp = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const config = require('../../config');
const policy = require('../../policy');
const killswitch = require('../../policy/killswitch');
const ecosystems = require('../../ecosystems');
const upstream = require('./upstream');
const signing = require('./signing');

const ARCHES = ['amd64', 'arm64'];
const dir = () => path.join(config.cacheDir, 'apt', 'filtered');
const adapter = () => ecosystems.adapter('apt');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

async function keepBytes(buf) {
  await fsp.mkdir(dir(), { recursive: true });
  const h = sha(buf);
  const file = path.join(dir(), h);
  if (!(await fsp.stat(file).then(() => true, () => false))) {
    const tmp = `${file}.${process.pid}.tmp`;
    await fsp.writeFile(tmp, buf, { mode: 0o640 });
    await fsp.rename(tmp, file);
  }
  return { sha256: h, size: buf.length };
}

// which package versions of an index this caller may see
async function allowedOf(idx, scope) {
  const ok = new Set();
  for (const [name, list] of idx.byName) {
    if (!(await policy.checkPackage(name, adapter(), scope)).allowed) continue;
    const killed = await killswitch.killedVersions('apt', name, list.map((p) => p.version));
    for (const p of list) {
      if (!killed.has(p.version) && (await policy.checkVersion(name, p.version, adapter(), scope)).allowed) ok.add(p.filename);
    }
  }
  return ok;
}

// one filtered Packages file, plain and gzipped: [{ path, sha256, size }]. made again only when the index or what is
// allowed out of it changed
const made = new Map();
async function filteredPackages(up, suite, comp, arch, scope, verified) {
  const idx = await upstream.packagesIndex(up, suite, comp, arch, verified);
  if (!idx) return [];
  const ok = await allowedOf(idx, scope);
  const key = `${idx.entry.sha256}\u0000${sha([...ok].sort().join('\n'))}`;
  if (made.has(key)) return made.get(key);
  const file = await upstream.metaFile(up, suite, idx.entry, false);
  const parts = [];
  await upstream.eachStanza(file, idx.entry.path, (st, text) => {
    const p = upstream.readStanza(st);
    if (p && ok.has(p.filename)) parts.push(`${text}\n\n`);
  });
  const plain = Buffer.from(parts.join(''), 'utf8');
  const gz = zlib.gzipSync(plain, { level: 6 });
  const a = await keepBytes(plain);
  const b = await keepBytes(gz);
  const base = `${comp}/binary-${arch}/Packages`;
  const out = [{ path: base, ...a }, { path: `${base}.gz`, ...b }];
  if (made.size > 500) made.clear();
  made.set(key, out);
  return out;
}

// the signed InRelease, Release and Release.gpg of a suite as this caller sees it. reuseMs: an answer made that
// recently for the same caller will do (the files a Release lists, asked for right after it)
const built = new Map();
const recent = new Map();
async function suite(up, name, scope, reuseMs = 0) {
  const who = `${up.name}\u0000${name}\u0000${scope.app}\u0000${scope.env}`;
  const last = recent.get(who);
  if (reuseMs && last && Date.now() - last.at < reuseMs) return last.out;
  const out = await build(up, name, scope);
  if (recent.size > 500) recent.clear();
  recent.set(who, { at: Date.now(), out });
  return out;
}

async function build(up, name, scope) {
  const rel = await upstream.release(up, name);
  if (!rel.inrelease) throw Object.assign(new Error(`${name} of ${up.name} has no InRelease, so no filtered index can be made from it`), { status: 502 });
  const body = await signing.verified(rel.inrelease);
  const { fields, files } = upstream.parseRelease(body);
  const comps = String(fields.Components || '').split(/\s+/).filter(Boolean);
  const arches = ARCHES.filter((a) => String(fields.Architectures || '').split(/\s+/).includes(a));
  const ours = [];
  // the signature-checked file list, never a second read of the Release
  const verified = { fields, files };
  for (const c of comps) for (const a of arches) ours.push(...await filteredPackages(up, name, c, a, scope, verified));
  const stamp = sha(`${rel.inrelease}\n${ours.map((m) => m.sha256).join('\n')}`);
  const key = `${up.name}\u0000${name}\u0000${stamp}`;
  if (built.has(key)) return built.get(key);
  // every file of the distro's, except the architecture indexes, which are this box's own now
  const kept = files.filter((f) => !/(^|\/)binary-[a-z0-9-]+\//.test(f.path));
  const listed = [...kept, ...ours].sort((x, y) => x.path.localeCompare(y.path));
  const width = String(Math.max(...listed.map((f) => f.size))).length;
  // Signed-By names the distro's keys, and apt would hold the box's signature against it
  const rest = { ...fields };
  delete rest['Signed-By'];
  const head = Object.entries({ ...rest, Architectures: [...arches, ...(/\ball\b/.test(fields.Architectures || '') ? ['all'] : [])].join(' ') })
    .map(([k, v]) => `${k}: ${v}`).join('\n');
  const text = `${head}\nSHA256:\n${listed.map((f) => ` ${f.sha256} ${String(f.size).padStart(width)} ${f.path}`).join('\n')}\n`;
  const out = { release: text, inrelease: await signing.clearsign(text), releaseGpg: await signing.detachSign(text), files: listed };
  if (built.size > 200) built.clear();
  built.set(key, out);
  return out;
}

// a file this box made, by its SHA256, or null
async function fileFor(h) {
  if (!/^[0-9a-f]{64}$/.test(h)) return null;
  const file = path.join(dir(), h);
  return (await fsp.stat(file).then(() => true, () => false)) ? file : null;
}

module.exports = { ARCHES, suite, fileFor };
