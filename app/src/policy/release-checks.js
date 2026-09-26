// What a new release says about itself, against what it really is and what came before it.
// Author: Tim Rice
//
// install-time code: a version that starts running code when it is installed, when the version before it did not.
// npm: preinstall, install or postinstall in the package.json inside the tarball (npm runs those, whatever the registry
// listing says), or a binding.gyp. PyPI: a release that ships only an sdist when the one before it had wheels, so
// installing it runs setup.py.
// manifest confusion (npm): the registry's listing of a version and the package.json in its tarball disagree. npm
// installs from the tarball, so a listing can hide install scripts or dependencies from anyone who only reads it.

const zlib = require('zlib');
const semver = require('semver');
const db = require('../db');
const log = require('../logger');
const artifacts = require('../storage/artifacts');

const HOOKS = ['preinstall', 'install', 'postinstall'];
const MAX_TGZ = 256 * 1024 * 1024;

function installMode() {
  const m = String(db.settings.get('install_script_check') || 'warn');
  return ['warn', 'hold', 'off'].includes(m) ? m : 'warn';
}

function confusionMode() {
  const m = String(db.settings.get('manifest_confusion') || 'hold');
  return ['hold', 'warn', 'off'].includes(m) ? m : 'hold';
}

function takeoverMode() {
  const m = String(db.settings.get('takeover_signals') || 'warn');
  return ['warn', 'hold', 'off'].includes(m) ? m : 'warn';
}

// a package nobody has touched for this long, then a release, is worth a look
const DORMANT_DAYS = 365;
const WHO = (v) => String(((v || {})._npmUser || {}).name || '').toLowerCase();
const NAMES = (v) => (Array.isArray((v || {}).maintainers) ? v.maintainers : []).map((m) => String((m && m.name) || '').toLowerCase()).filter(Boolean);

// what changed around this release, compared with the ones before it. npm keeps who published each version and when
function takeoverNpm(doc, version, prev) {
  if (!prev) return [];
  const listed = doc.versions || {};
  const mine = listed[version] || {};
  const before = Object.keys(listed).filter((v) => v !== version && semver.valid(v) && semver.lt(v, version)).sort(semver.rcompare).slice(0, 10);
  const signals = [];
  const who = WHO(mine);
  const knew = new Set(before.map((v) => WHO(listed[v])).filter(Boolean));
  if (who && knew.size && !knew.has(who)) signals.push(`published by ${who}, who had not published this package before (${[...knew].slice(0, 3).join(', ')} did)`);
  const now = new Set(NAMES(mine));
  const then = new Set(NAMES(listed[prev]));
  if (now.size && then.size) {
    const added = [...now].filter((n) => !then.has(n));
    const gone = [...then].filter((n) => !now.has(n));
    if (gone.length && !added.length && now.size < then.size) signals.push(`${gone.slice(0, 3).join(', ')} is no longer a maintainer`);
    else if (added.length) signals.push(`${added.slice(0, 3).join(', ')} joined the maintainers with this release`);
  }
  const times = doc.time || {};
  const at = Date.parse(times[version] || '');
  const was = Date.parse(times[prev] || '');
  if (Number.isFinite(at) && Number.isFinite(was)) {
    const days = Math.round((at - was) / 86400000);
    if (days >= DORMANT_DAYS) signals.push(`nothing was published for ${days} days before it`);
  }
  return signals;
}

// PyPI says when each release went up, which is enough for the quiet years part
function takeoverPypi(json, version) {
  const releases = json && json.releases && typeof json.releases === 'object' ? json.releases : null;
  if (!releases) return [];
  const pv = require('../ecosystems/pypi/version');
  const when = (v) => (Array.isArray(releases[v]) ? releases[v] : []).map((f) => Date.parse(f && f.upload_time_iso_8601 ? f.upload_time_iso_8601 : (f || {}).upload_time)).filter(Number.isFinite).sort()[0];
  const at = when(version);
  if (!Number.isFinite(at)) return [];
  const before = Object.keys(releases).filter((v) => v !== version && pv.valid(v) && pv.compare(v, version) < 0).sort(pv.rcompare)[0];
  const was = before ? when(before) : null;
  if (!Number.isFinite(was)) return [];
  const days = Math.round((at - was) / 86400000);
  return days >= DORMANT_DAYS ? [`nothing was published for ${days} days before it`] : [];
}

// ---------------------------------------------------------------- npm

// the package.json at the top of an npm tarball, and whether there is a binding.gyp next to it
function readTarball(buf) {
  const tar = zlib.gunzipSync(buf, { maxOutputLength: MAX_TGZ });
  let manifest = null;
  let gyp = false;
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    if (h.every((b) => b === 0)) break;
    const size = parseInt(h.toString('utf8', 124, 136).replace(/\0.*$/s, '').trim() || '0', 8);
    if (!Number.isFinite(size) || size < 0) break;
    const prefix = h.toString('utf8', 345, 500).replace(/\0.*$/s, '');
    const name = (prefix ? `${prefix}/` : '') + h.toString('utf8', 0, 100).replace(/\0.*$/s, '');
    const parts = name.replace(/^\.\//, '').split('/');
    // one folder deep, whatever the folder is called (package/ usually)
    if (parts.length === 2 && parts[1] === 'package.json' && !manifest) {
      try {
        manifest = JSON.parse(tar.toString('utf8', offset + 512, offset + 512 + size));
      } catch (err) {
        manifest = { unreadable: true };
      }
    }
    if (parts.length === 2 && parts[1] === 'binding.gyp') gyp = true;
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return { manifest, gyp };
}

function hooksOf(m, gyp) {
  const s = m && m.scripts && typeof m.scripts === 'object' ? m.scripts : {};
  const found = HOOKS.filter((k) => typeof s[k] === 'string' && s[k].trim());
  // npm runs node-gyp rebuild for a binding.gyp when there is no install script
  if (gyp && !found.includes('install')) found.push('install (node-gyp)');
  return found;
}

// the version this one follows: the newest listed version below it
function previousOf(doc, version) {
  if (!semver.valid(version)) return null;
  const below = Object.keys((doc && doc.versions) || {}).filter((v) => semver.valid(v) && semver.lt(v, version));
  return below.sort(semver.rcompare)[0] || null;
}

function installCodeNpm(listed, prevListed, own, gyp, version, prev) {
  if (!prev) return null;
  const now = hooksOf(own, gyp);
  if (!now.length) return null;
  const before = hooksOf(prevListed, prevListed && prevListed.gypfile);
  if (before.length || (prevListed && prevListed.hasInstallScript)) return null;
  const cmd = now.map((k) => {
    const c = own.scripts && own.scripts[k];
    return c ? `${k}: ${String(c).slice(0, 80)}` : k;
  });
  return `${version} runs code when it is installed (${cmd.join('; ')}), ${prev} did not`;
}

const sortedJson = (o) => JSON.stringify(o && typeof o === 'object' ? Object.keys(o).sort().reduce((m, k) => ({ ...m, [k]: o[k] }), {}) : {});

// { severe: [...], mild: [...] } differences between the listing and the tarball
function confusionNpm(listed, own) {
  const severe = [];
  const mild = [];
  if (!own || own.unreadable) return { severe: ['the tarball has no readable package.json'], mild };
  if (listed.name !== own.name) severe.push(`the name is ${JSON.stringify(own.name)} in the tarball, ${JSON.stringify(listed.name)} in the listing`);
  if (listed.version !== own.version) severe.push(`the version is ${JSON.stringify(own.version)} in the tarball, ${JSON.stringify(listed.version)} in the listing`);
  for (const k of HOOKS) {
    const a = (listed.scripts || {})[k];
    const b = (own.scripts || {})[k];
    // the registry writes node-gyp rebuild into the listing itself when there is a binding.gyp
    if (k === 'install' && !b && a === 'node-gyp rebuild' && listed.gypfile) continue;
    if ((a || '') !== (b || '')) severe.push(`the ${k} script is ${b ? JSON.stringify(String(b).slice(0, 80)) : 'missing'} in the tarball, ${a ? JSON.stringify(String(a).slice(0, 80)) : 'missing'} in the listing`);
  }
  for (const k of ['dependencies', 'optionalDependencies']) {
    if (sortedJson(listed[k]) !== sortedJson(own[k])) severe.push(`${k} differ between the tarball and the listing`);
  }
  for (const k of ['peerDependencies', 'bin']) {
    const a = typeof listed[k] === 'string' ? { [listed.name]: listed[k] } : listed[k];
    const b = typeof own[k] === 'string' ? { [own.name]: own[k] } : own[k];
    if (sortedJson(a) !== sortedJson(b)) mild.push(`${k} differ between the tarball and the listing`);
  }
  if (listed.license && own.license && JSON.stringify(listed.license) !== JSON.stringify(own.license)) mild.push('the license differs between the tarball and the listing');
  return { severe, mild };
}

async function checkNpm(a) {
  const found = await artifacts.locate('npm', a.package_name, a.version, a.filename).catch(() => null);
  if (!found || found.upstream === require('../registry/shared/published').SOURCE) return [];
  const { doc } = await require('../registry/npm/upstream').getPackument(a.package_name, 'full');
  const listed = doc && doc.versions && doc.versions[a.version];
  if (!listed) return [];
  const { manifest, gyp } = readTarball(await artifacts.readAll(found));
  const out = [];
  const prev = previousOf(doc, a.version);
  const code = installCodeNpm(listed, prev && doc.versions[prev], manifest || {}, gyp, a.version, prev);
  if (code) out.push({ kind: 'install-code', reason: code, severe: false });
  const signals = takeoverMode() === 'off' ? [] : takeoverNpm(doc, a.version, prev);
  if (signals.length) out.push({ kind: 'takeover', reason: `signs of a takeover: ${signals.join('; ')}`, severe: false });
  const c = confusionNpm(listed, manifest);
  if (c.severe.length) out.push({ kind: 'manifest', reason: `manifest confusion: ${c.severe.concat(c.mild).slice(0, 5).join('; ')}`, severe: true });
  else if (c.mild.length) out.push({ kind: 'manifest', reason: `manifest confusion: ${c.mild.slice(0, 5).join('; ')}`, severe: false });
  return out;
}

// ---------------------------------------------------------------- PyPI

async function checkPypi(a) {
  if (/\.whl$/i.test(a.filename)) return [];
  const simple = require('../ecosystems/pypi/simple');
  const pv = require('../ecosystems/pypi/version');
  const page = await require('../registry/pypi/upstream').getProject(a.package_name);
  const files = (page && page.doc && page.doc.files) || [];
  const byRelease = new Map();
  for (const f of files) {
    const r = simple.releaseOf(f.filename, a.package_name);
    if (!r || !pv.valid(r)) continue;
    const key = pv.normalize(r);
    if (!byRelease.has(key)) byRelease.set(key, []);
    byRelease.get(key).push(f.filename);
  }
  const mine = byRelease.get(pv.normalize(a.version)) || [];
  if (mine.some((f) => /\.whl$/i.test(f))) return [];
  const prev = [...byRelease.keys()].filter((r) => pv.compare(r, a.version) < 0).sort(pv.rcompare)[0];
  if (!prev || !byRelease.get(prev).some((f) => /\.whl$/i.test(f))) return [];
  return [{ kind: 'install-code', reason: `${a.version} ships no wheel, so installing it runs its setup.py; ${prev} had wheels`, severe: false }];
}

// the quiet years signal, from the dates PyPI's json api gives
async function takeoverPypiFor(a) {
  if (takeoverMode() === 'off') return [];
  const got = await require('../registry/pypi/upstream').getJson(a.package_name).catch(() => null);
  const signals = takeoverPypi(got && got.doc, a.version);
  return signals.length ? [{ kind: 'takeover', reason: `signs of a takeover: ${signals.join('; ')}`, severe: false }] : [];
}

// ---------------------------------------------------------------- acting on it

async function act(a, f) {
  const how = f.kind === 'manifest' ? (f.severe ? confusionMode() : (confusionMode() === 'off' ? 'off' : 'warn'))
    : f.kind === 'takeover' ? takeoverMode() : installMode();
  if (how === 'off') return;
  const file = { ecosystem: a.ecosystem, packageName: a.package_name, version: a.version, filename: a.filename };
  log.warn(`${f.kind}: ${a.ecosystem} ${a.package_name} ${a.filename}: ${f.reason}`);
  require('../integrations/events').emit('policy.violation', {
    ecosystem: a.ecosystem, package: a.package_name, version: a.version, filename: a.filename, artifactHash: a.sha256,
    policy: f.kind === 'manifest' ? 'manifest confusion' : f.kind === 'takeover' ? 'takeover signals' : 'install-time code', reason: f.reason,
    action: how === 'hold' ? 'held in quarantine' : 'recorded', severity: f.severe ? 'HIGH' : 'MEDIUM'
  });
  if (how === 'hold') await require('./quarantine').hold(file, { source: f.kind, reason: f.reason, sha256: a.sha256 });
}

// every check for one newly cached file. never throws, a failure here is logged and the file is looked at again
// only when its bytes change
async function run(a) {
  try {
    const found = a.ecosystem === 'npm' ? await checkNpm(a)
      : a.ecosystem === 'pypi' ? [...await checkPypi(a), ...await takeoverPypiFor(a)] : [];
    for (const f of found) await act(a, f);
    return found;
  } catch (err) {
    log.warn(`release checks on ${a.ecosystem} ${a.package_name} ${a.filename} did not finish`, err.message);
    return [];
  }
}

module.exports = {
  run, installMode, confusionMode, takeoverMode,
  _internal: { readTarball, hooksOf, previousOf, installCodeNpm, confusionNpm, checkPypi, takeoverNpm, takeoverPypi, DORMANT_DAYS }
};
