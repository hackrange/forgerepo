// SBOMs for what is in the cache: one cached file with what it depends on, or everything an application downloaded.
// Author: Tim Rice
// read only. dependencies come from metadata already cached, nothing is fetched to write one

const zlib = require('node:zlib');
const { promisify } = require('node:util');
const semver = require('semver');
const config = require('../config');
const generate = require('../sbom/generate');
const repo = require('../db/repositories/sbom');
const artifacts = require('../db/repositories/artifacts');
const packuments = require('../db/repositories/packuments');
const pypiDocs = require('../db/repositories/pypi-documents');
const labels = require('../db/repositories/labels');
const pypiVersion = require('../ecosystems/pypi/version');
const spdx = require('../policy/licenses/spdx');
const { parseRequirement, onlyForExtra } = require('../registry/pypi/tree');
const { fail } = require('../lib/errors');

const gunzip = promisify(zlib.gunzip);
const VERSION = require('../../package.json').version;
const MAX_DEPS = 500;
const MAX_ROWS = 20000;

function checkFormat(value) {
  const format = String(value || 'cyclonedx').toLowerCase();
  if (!generate.FORMATS.includes(format)) fail(400, 'the format is cyclonedx or spdx');
  return format;
}

// a real SPDX expression goes in as one, anything else only as the name it was published under
function licenseOf(expression) {
  if (!expression) return {};
  const text = String(expression);
  const parsed = spdx.parse(text);
  return parsed && parsed.tree ? { license: text } : { licenseName: text.slice(0, 255) };
}

const fileSafe = (s) => String(s).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 120) || 'sbom';
const own = (obj, k) => !!obj && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, k);

async function readDoc(row) {
  if (!row || !row.body) return null;
  try {
    return JSON.parse((await gunzip(row.body)).toString('utf8'));
  } catch (err) {
    return null;
  }
}

function samePypiVersion(a, b) {
  if (String(a) === String(b)) return true;
  return pypiVersion.valid(a) && pypiVersion.valid(b) && pypiVersion.eq(a, b);
}

// what this exact version says it needs. null when none of its metadata is cached
async function declared(row) {
  const out = [];
  const seen = new Set();
  const add = (name, range, scope) => {
    if (typeof name !== 'string' || !name || seen.has(name)) return;
    seen.add(name);
    out.push({ name, range: typeof range === 'string' ? range : '', scope });
  };
  if (row.ecosystem === 'pypi') {
    let doc = await readDoc(await pypiDocs.get(row.package_name, 'json', row.version));
    if (!doc) {
      doc = await readDoc(await pypiDocs.get(row.package_name, 'json', ''));
      if (!doc || !doc.info || !samePypiVersion(doc.info.version, row.version)) return null;
    }
    const info = doc.info;
    if (!info) return null;
    for (const line of Array.isArray(info.requires_dist) ? info.requires_dist : []) {
      const req = parseRequirement(line);
      if (!req || req.url || onlyForExtra(req.marker)) continue;
      add(req.name, req.specifier, req.marker ? 'optional' : 'required');
    }
    return out;
  }
  // NuGet keeps each version's dependency groups in its own summary, every framework's together here
  if (row.ecosystem === 'nuget') {
    const held = await require('../db/repositories/package-documents').get('nuget', require('../ecosystems/nuget/name').fold(row.package_name), 'summary').catch(() => null);
    const v = held && held.doc && Array.isArray(held.doc.versions) ? held.doc.versions.find((x) => String(x.version).toLowerCase() === String(row.version).toLowerCase()) : null;
    if (!v) return null;
    for (const g of Array.isArray(v.deps) ? v.deps : []) {
      for (const d of Array.isArray(g.dependencies) ? g.dependencies : []) add(d.id, d.range || '', 'required');
    }
    return out;
  }
  // every other type that can say what it needs, read from its own metadata. never npm's list for the same name
  if (row.ecosystem !== 'npm') {
    const kind = require('../registry/kinds').get(row.ecosystem);
    if (!kind || !kind.dependencies) return null;
    const got = await kind.dependencies(row.package_name, row.version).catch(() => null);
    if (!got) return null;
    for (const d of got.slice(0, MAX_DEPS)) add(d.name, d.range, d.scope);
    return out;
  }
  const doc = (await readDoc(await packuments.get(row.package_name, 'full'))) ||
    (await readDoc(await packuments.get(row.package_name, 'abbreviated')));
  if (!doc || !own(doc.versions, row.version)) return null;
  const meta = doc.versions[row.version] || {};
  // npm repeats optional ones under dependencies, so they go first to keep their scope
  for (const [section, scope] of [['optionalDependencies', 'optional'], ['dependencies', 'required'], ['peerDependencies', 'optional']]) {
    const map = meta[section];
    if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
    for (const name of Object.keys(map)) add(name, map[name], scope);
  }
  return out;
}

// the newest cached version the range allows, with every file of it. otherwise listed by its range
function pin(ecosystem, dep, files) {
  const mine = files.filter((f) => f.package_name === dep.name);
  const versions = [...new Set(mine.map((f) => f.version))];
  let best = null;
  if (ecosystem === 'pypi') {
    const ok = versions.filter((v) => pypiVersion.valid(v));
    if (!dep.range) best = ok.length ? pypiVersion.rcompare && ok.slice().sort(pypiVersion.rcompare)[0] : null;
    else if (pypiVersion.validSpecifierSet(dep.range)) best = pypiVersion.maxSatisfying(ok, dep.range);
  } else if (semver.validRange(dep.range || '*')) {
    best = semver.maxSatisfying(versions.filter((v) => semver.valid(v)), dep.range || '*');
  }
  // nothing but npm and PyPI ranges are worked out here. an exact version that is cached is still pinned, so a Maven
  // or Debian dependency on one version comes out with its file hashes
  if (ecosystem !== 'npm' && ecosystem !== 'pypi') best = versions.includes(String(dep.range || '').trim()) ? String(dep.range).trim() : null;
  if (!best) return { ecosystem, name: dep.name, range: dep.range || '*', scope: dep.scope };
  const chosen = mine.filter((f) => f.version === best);
  const licensed = chosen.find((f) => f.license_expression);
  return {
    ecosystem,
    name: dep.name,
    version: best,
    scope: dep.scope,
    sha256s: [...new Set(chosen.map((f) => f.sha256))],
    files: chosen.length > 1 ? chosen.map((f) => ({ filename: f.filename, sha256: f.sha256 })) : [],
    ...licenseOf(licensed && licensed.license_expression)
  };
}

// ---------------------------------------------------------------- images

const MAX_IMAGE_PACKAGES = 20000;
const MAX_IMAGES_IN_APP = 200;

// the packages inside one image, or each platform image of a list, from the scans this box has done.
// { components, notes, platforms, scanned }. an unscanned image is said to be so, never listed as empty
async function imageContents(repository, digest) {
  const upstream = require('../registry/oci/upstream');
  const scans = require('../db/repositories/image-scans');
  const { _internal: tree } = require('./image-tree');
  // only what this box holds. an SBOM never makes it fetch an image, allowed or not
  const held = async (ref) => ((await require('../policy/private-names').isPrivate('oci', repository).catch(() => false))
    ? upstream.getManifest(repository, ref).catch(() => null)
    : upstream.keptFor(repository, ref, { anyAge: true }));
  const top = await held(digest);
  if (!top) fail(404, `${repository} ${digest} is not held here. Pull it through this registry first`);
  const doc = top.doc || {};
  const entries = Array.isArray(doc.manifests)
    ? doc.manifests.filter((e) => e && /^sha256:[0-9a-f]{64}$/.test(String(e.digest)) && !tree.isAttestation(e)).slice(0, 32).map((e) => ({ digest: e.digest, platform: tree.platformOf(e) }))
    : [{ digest: top.digest, platform: '' }];
  const byPurl = new Map();
  const notes = [];
  let scanned = 0;
  for (const e of entries) {
    const row = await scans.byKey(repository, e.digest);
    if (!row || row.status !== 'done') {
      notes.push(`${e.platform || 'The image'} ${e.digest} has not been scanned${row ? ` (${row.status})` : ''}, so its packages are not listed. Scan it from its dependency tree.`);
      continue;
    }
    scanned += 1;
    for (const c of await scans.components(row.id, { limit: MAX_IMAGE_PACKAGES })) {
      const isOs = ['deb', 'apk', 'rpm'].includes(c.type);
      const eco = c.type === 'pypi' ? 'pypi' : c.type === 'npm' ? 'npm' : null;
      if (!isOs && !eco) continue;
      const p = isOs ? generate.osPurl(c.type, c.name, c.version, c.ecosystem || row.feed) : generate.purl(eco, c.name, c.version);
      if (!byPurl.has(p)) {
        byPurl.set(p, { purl: p, ecosystem: eco || c.type, name: c.name, version: c.version, properties: {}, platforms: new Set() });
        if (c.binaries && c.binaries.length && isOs) byPurl.get(p).properties.binaries = c.binaries.join(' ');
        if (c.advisories) byPurl.get(p).properties.advisories = String(c.advisories).slice(0, 500);
      }
      if (e.platform) byPurl.get(p).platforms.add(e.platform);
    }
  }
  const components = [...byPurl.values()].map((c) => {
    const { platforms, ...rest } = c;
    if (platforms.size && entries.length > 1) rest.properties.platforms = [...platforms].join(' ');
    return rest;
  });
  return { digest: top.digest, components, notes, platforms: entries.length, scanned };
}

async function forImage(repository, reference, rawFormat) {
  const format = checkFormat(rawFormat);
  let got;
  try {
    got = await imageContents(repository, reference);
  } catch (err) {
    fail(err.status === 404 ? 404 : err.status || 502, err.message);
  }
  const notes = [`Every package found inside ${repository}@${got.digest}${got.platforms > 1 ? `, across ${got.platforms} platform images` : ''}, from the image scan. OS packages are listed by their source package.`].concat(got.notes);
  const subject = { kind: 'image', ecosystem: 'oci', name: repository, version: got.digest };
  return {
    format,
    filename: `${fileSafe(repository)}-${got.digest.slice(7, 19)}.${format === 'spdx' ? 'spdx' : 'cdx'}.json`,
    components: got.components.length,
    doc: write(format, { subject, components: got.components, notes })
  };
}

function write(format, input) {
  return generate.build(format, { ...input, toolVersion: VERSION, now: new Date().toISOString(), namespace: config.publicUrl });
}

async function forArtifact(id, rawFormat) {
  const format = checkFormat(rawFormat);
  const row = await artifacts.rowById(id);
  if (!row) fail(404, 'there is no such artifact');
  const notes = [];
  let deps = row.version ? await declared(row) : null;
  if (!deps) {
    notes.push('Dependencies unknown: the metadata for this version is not in the cache.');
    deps = [];
  }
  if (deps.length > MAX_DEPS) {
    notes.push(`Only the first ${MAX_DEPS} dependencies are listed.`);
    deps = deps.slice(0, MAX_DEPS);
  }
  const files = await repo.cachedFiles(row.ecosystem, [...new Set(deps.map((d) => d.name))]);
  const components = deps.map((d) => pin(row.ecosystem, d, files));
  if (components.length) notes.push('Direct dependencies only. Each is pinned to the newest cached version its range allows; one with nothing cached is listed by its range.');
  const subject = {
    kind: 'artifact',
    ecosystem: row.ecosystem,
    name: row.package_name,
    version: row.version,
    sha256s: [row.sha256],
    files: [{ filename: row.filename, sha256: row.sha256 }],
    ...licenseOf(row.license_expression)
  };
  return {
    format,
    filename: `${fileSafe(row.filename)}.${format === 'spdx' ? 'spdx' : 'cdx'}.json`,
    components: components.length,
    doc: write(format, { subject, components, notes })
  };
}

// application and environment by name, as the consumption record keeps them
async function forApplication({ application, environment }, rawFormat) {
  const format = checkFormat(rawFormat);
  const app = await labels.byName('applications', application);
  if (!app) fail(404, 'there is no application by that name');
  const env = environment ? await labels.byName('environments', environment) : null;
  if (environment && !env) fail(404, 'there is no environment by that name');
  const rows = await repo.consumed(app.name, env ? env.name : null, MAX_ROWS + 1);
  const notes = [`Everything ${app.name}${env ? ` in ${env.name}` : ''} downloaded through this registry, from its consumption record.`];
  if (rows.length > MAX_ROWS) {
    rows.length = MAX_ROWS;
    notes.push(`Cut short at ${MAX_ROWS} files.`);
  }
  const groups = new Map();
  for (const r of rows) {
    const key = `${r.ecosystem}\n${r.package_name}\n${r.version}`;
    if (!groups.has(key)) groups.set(key, { ecosystem: r.ecosystem, name: r.package_name, version: r.version, files: [], license: null });
    const g = groups.get(key);
    if (r.sha256) g.files.push({ filename: r.filename, sha256: r.sha256 });
    if (!g.license && r.license_expression) g.license = r.license_expression;
  }
  let gone = 0;
  const components = [...groups.values()].map((g) => {
    if (!g.files.length) gone += 1;
    return {
      ecosystem: g.ecosystem,
      name: g.name,
      version: g.version,
      sha256s: [...new Set(g.files.map((f) => f.sha256))],
      files: g.files.length > 1 ? g.files : [],
      ...licenseOf(g.license)
    };
  });
  if (gone) notes.push(`${gone} version(s) are no longer in the cache and are listed without hashes.`);
  // each image carries what is inside it
  let images = 0;
  let unscanned = 0;
  for (const c of components.filter((x) => x.ecosystem === 'oci' && /^sha256:[0-9a-f]{64}$/.test(String(x.version))).slice(0, MAX_IMAGES_IN_APP)) {
    const inside = await imageContents(c.name, c.version).catch(() => null);
    if (!inside || !inside.scanned) {
      unscanned += 1;
      continue;
    }
    c.contains = inside.components;
    images += 1;
  }
  if (images) notes.push(`${images} image(s) list the packages found inside them.`);
  if (unscanned) notes.push(`${unscanned} image(s) have not been scanned, so their contents are not listed.`);
  const subject = { kind: 'application', name: app.name, version: '', scope: env ? env.name : '' };
  return {
    format,
    filename: `${fileSafe(app.name)}${env ? `-${fileSafe(env.name)}` : ''}.${format === 'spdx' ? 'spdx' : 'cdx'}.json`,
    components: components.length,
    doc: write(format, { subject, components, notes })
  };
}

module.exports = { MAX_DEPS, MAX_ROWS, checkFormat, licenseOf, declared, pin, forArtifact, forApplication, forImage, imageContents };
