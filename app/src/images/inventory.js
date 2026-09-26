// What is installed in an image: the OS packages and the npm and Python ones, read from the files package managers keep.
// Author: Tim Rice
//
// layers stack. a later layer replaces a file, deletes it with a .wh. marker, or empties a folder with .wh..wh..opq,
// so what counts is the filesystem the container would actually see, not every file any layer ever had.
// every parser here takes hostile text and returns plain data or nothing, never throws past its caller

const semver = require('semver');
const pypiName = require('../ecosystems/pypi/name');
const pypiVersion = require('../ecosystems/pypi/version');
const tar = require('./tar');

const KB = 1024;
const MB = 1024 * KB;

const OS_RELEASE = ['etc/os-release', 'usr/lib/os-release'];
const DPKG_STATUS = 'var/lib/dpkg/status';
const DPKG_STATUS_D = /^var\/lib\/dpkg\/status\.d\/[^/]+$/;
// merged /usr images (Wolfi, apk 3) keep it under usr/lib, with lib a link to it
const APK_INSTALLED = ['lib/apk/db/installed', 'usr/lib/apk/db/installed'];
const RPM_SQLITE = ['var/lib/rpm/rpmdb.sqlite', 'usr/lib/sysimage/rpm/rpmdb.sqlite'];
const RPM_BDB = ['var/lib/rpm/Packages', 'usr/lib/sysimage/rpm/Packages'];
// SUSE's own format, not read
const RPM_NDB = ['var/lib/rpm/Packages.db', 'usr/lib/sysimage/rpm/Packages.db'];
const NPM_PACKAGE = /(^|\/)node_modules\/(@[^/]+\/)?[^/@.][^/]*\/package\.json$/;
const PY_METADATA = /(^|\/)(site|dist)-packages\/[^/]+\.(dist-info\/METADATA|egg-info\/PKG-INFO|egg-info)$/;
const MAX_COMPONENTS = 50000;

// how much of each file is worth keeping. 0 = not interesting
function want(path) {
  if (OS_RELEASE.includes(path)) return 64 * KB;
  if (path === DPKG_STATUS || APK_INSTALLED.includes(path)) return 64 * MB;
  if (DPKG_STATUS_D.test(path)) return 1 * MB;
  if (RPM_SQLITE.includes(path) || RPM_BDB.includes(path)) return 256 * MB;
  if (RPM_NDB.includes(path)) return 1;
  if (NPM_PACKAGE.test(path) || PY_METADATA.test(path)) return 1 * MB;
  return 0;
}

// ---------------------------------------------------------------- the filesystem the layers add up to

function removeUnder(files, path) {
  files.delete(path);
  const prefix = `${path}/`;
  for (const key of [...files.keys()]) if (key.startsWith(prefix)) files.delete(key);
}

function removeBelow(files, dir) {
  const prefix = dir ? `${dir}/` : '';
  for (const key of [...files.keys()]) if (key.startsWith(prefix)) files.delete(key);
}

/**
 * one layer at a time, oldest first. a layer's own deletions only apply to what was under it,
 * so they are gathered first and its files added after
 */
function stacker() {
  const files = new Map();
  const notes = [];
  return {
    files,
    notes,
    async layer(open) {
      const added = new Map();
      const whiteouts = [];
      const opaque = [];
      await open({
        want,
        onFile: (path, data, info) => {
          if (!data) {
            if (!RPM_NDB.includes(path)) notes.push(`${path} is ${info.size} bytes, more than is read`);
            added.set(path, { tooBig: true });
          } else {
            added.set(path, { data });
          }
        },
        // wanted files, and the short folder links merged /usr images have (lib -> usr/lib)
        onLink: (path, target, kind) => {
          if (want(path) || path.split('/').length <= 3) added.set(path, { link: target, kind });
        },
        onWhiteout: (path) => whiteouts.push(path),
        onOpaque: (dir) => opaque.push(dir)
      });
      for (const dir of opaque) removeBelow(files, dir);
      for (const path of whiteouts) removeUnder(files, path);
      for (const [path, value] of added) files.set(path, value);
    }
  };
}

function linkTarget(path, entry) {
  if (entry.kind === 'symbolic' && !entry.link.startsWith('/')) {
    const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
    return tar.clean(`${dir}/${entry.link}`);
  }
  return tar.clean(entry.link);
}

// a symlink or hard link, the file's own or a folder's on the way to it, followed a few hops inside the image and never outside it
function read(files, path, hops = 0) {
  if (hops > 8) return null;
  const entry = files.get(path);
  if (entry && entry.data) return entry.data;
  if (entry && entry.link) return read(files, linkTarget(path, entry), hops + 1);
  const parts = path.split('/');
  for (let i = parts.length - 1; i > 0; i -= 1) {
    const dir = parts.slice(0, i).join('/');
    const link = files.get(dir);
    if (link && link.link) return read(files, tar.clean(`${linkTarget(dir, link)}/${parts.slice(i).join('/')}`), hops + 1);
  }
  return null;
}

// ---------------------------------------------------------------- parsers

function unquote(v) {
  const s = String(v).trim();
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]) return s.slice(1, -1).replace(/\\(.)/g, '$1');
  return s;
}

function osRelease(textIn) {
  const out = {};
  for (const line of String(textIn || '').split('\n').slice(0, 200)) {
    const m = /^([A-Z0-9_]{1,64})=(.*)$/.exec(line.trim());
    if (m) out[m[1]] = unquote(m[2]).slice(0, 256);
  }
  if (!out.ID) return null;
  return {
    id: out.ID.toLowerCase(),
    versionId: out.VERSION_ID || '',
    version: out.VERSION || '',
    idLike: (out.ID_LIKE || '').toLowerCase(),
    name: out.PRETTY_NAME || out.NAME || out.ID
  };
}

// debian control files: paragraphs split by blank lines, continuation lines start with a space
function paragraphs(textIn, maxRecords = MAX_COMPONENTS) {
  const out = [];
  let current = {};
  let last = null;
  const push = () => {
    if (Object.keys(current).length) out.push(current);
    current = {};
    last = null;
  };
  for (const line of String(textIn || '').split('\n')) {
    if (out.length >= maxRecords) break;
    if (!line.trim()) {
      push();
      continue;
    }
    if ((line[0] === ' ' || line[0] === '\t') && last) {
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    last = line.slice(0, colon).trim().toLowerCase();
    current[last] = line.slice(colon + 1).trim();
  }
  push();
  return out;
}

const DEB_NAME = /^[a-z0-9][a-z0-9+.-]{0,200}$/;
const DEB_VERSION = /^[A-Za-z0-9.+~:-]{1,128}$/;

function dpkgStatus(textIn) {
  const out = [];
  for (const p of paragraphs(textIn)) {
    // status.d files from distroless images carry no Status line, and everything in them is installed
    if (p.status !== undefined && !/\binstalled$/.test(p.status)) continue;
    if (!DEB_NAME.test(p.package || '') || !DEB_VERSION.test(p.version || '')) continue;
    let source = p.package;
    let sourceVersion = p.version;
    const m = /^([a-z0-9][a-z0-9+.-]*)(?:\s+\(([^)]+)\))?$/.exec(p.source || '');
    if (m) {
      source = m[1];
      if (m[2] && DEB_VERSION.test(m[2])) sourceVersion = m[2];
    }
    out.push({ type: 'deb', name: source, version: sourceVersion, binary: p.package, binaryVersion: p.version });
  }
  return out;
}

const APK_NAME = /^[A-Za-z0-9][A-Za-z0-9+._-]{0,200}$/;
const APK_VERSION = /^[A-Za-z0-9._+~-]{1,128}$/;

// the apk database: one letter, a colon, the value. o: is the origin, the source package advisories name
function apkInstalled(textIn) {
  const out = [];
  let rec = {};
  const push = () => {
    if (APK_NAME.test(rec.P || '') && APK_VERSION.test(rec.V || '')) {
      const origin = APK_NAME.test(rec.o || '') ? rec.o : rec.P;
      out.push({ type: 'apk', name: origin, version: rec.V, binary: rec.P, binaryVersion: rec.V });
    }
    rec = {};
  };
  for (const line of String(textIn || '').split('\n')) {
    if (out.length >= MAX_COMPONENTS) break;
    if (!line.trim()) {
      push();
      continue;
    }
    if (line[1] === ':' && !(line[0] in rec)) rec[line[0]] = line.slice(2).trim();
  }
  push();
  return out;
}

const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

function npmPackage(buf, path) {
  let doc;
  try {
    doc = JSON.parse(buf.toString('utf8'));
  } catch (err) {
    return null;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const { name, version } = doc;
  if (typeof name !== 'string' || name.length > 214 || !NPM_NAME.test(name)) return null;
  if (typeof version !== 'string' || version.length > 64 || !semver.valid(version)) return null;
  // the folder has to be the package it says it is, a fixture or a template inside a package is not installed
  if (!path.endsWith(`node_modules/${name}/package.json`)) return null;
  return { type: 'npm', name, version };
}

function pythonMetadata(buf) {
  const head = buf.toString('utf8', 0, Math.min(buf.length, 64 * KB)).split(/\r?\n\r?\n/)[0];
  const fields = {};
  for (const line of head.split(/\r?\n/)) {
    const m = /^(Name|Version):\s*(.+)$/i.exec(line);
    if (m && !fields[m[1].toLowerCase()]) fields[m[1].toLowerCase()] = m[2].trim();
  }
  if (!fields.name || !pypiName.valid(fields.name) || !fields.version || !pypiVersion.valid(fields.version)) return null;
  return { type: 'pypi', name: pypiName.normalize(fields.name), version: fields.version };
}

// ---------------------------------------------------------------- which advisory feed covers it

const RPM_FAMILIES = { rocky: 'Rocky Linux', almalinux: 'AlmaLinux' };

/** @returns {{ ecosystem: string|null, also?: string[], why: string|null }} */
function osFeed(os) {
  if (!os) return { ecosystem: null, why: 'the image has no os-release file, so its OS packages cannot be matched to a distribution' };
  const major = (os.versionId.match(/^\d+/) || [''])[0];
  switch (os.id) {
    case 'debian':
      return major ? { ecosystem: `Debian:${major}`, why: null } : { ecosystem: null, why: `${os.name} has no release number (testing or unstable), there is no advisory feed for it` };
    case 'ubuntu': {
      if (!/^\d+\.\d+$/.test(os.versionId)) return { ecosystem: null, why: `${os.name} has no release number` };
      return { ecosystem: `Ubuntu:${os.versionId}${/LTS/.test(os.version) ? ':LTS' : ''}`, why: null };
    }
    case 'alpine': {
      const m = /^(\d+\.\d+)/.exec(os.versionId);
      return m ? { ecosystem: `Alpine:v${m[1]}`, why: null } : { ecosystem: null, why: `${os.name} is not a numbered release (edge), there is no advisory feed for it` };
    }
    case 'wolfi':
      return { ecosystem: 'Wolfi', why: null };
    case 'chainguard':
      return { ecosystem: 'Chainguard', why: null };
    // UBI and RHEL. which repository a package came from is not in the rpm database, so both are asked
    case 'rhel':
      return major
        ? { ecosystem: `Red Hat:enterprise_linux:${major}::baseos`, also: [`Red Hat:enterprise_linux:${major}::appstream`], why: null }
        : { ecosystem: null, why: `${os.name} has no release number` };
    case 'rocky':
    case 'almalinux':
      return major ? { ecosystem: `${RPM_FAMILIES[os.id]}:${major}`, why: null } : { ecosystem: null, why: `${os.name} has no release number` };
    default:
      return { ecosystem: null, why: `there is no built in advisory feed for ${os.name}, its OS packages are listed but not checked` };
  }
}

// every feed a component is asked about. a UBI package could be in either Red Hat repository
function feedsFor(ecosystem) {
  const m = /^(Red Hat:enterprise_linux:\d+)::baseos$/.exec(String(ecosystem || ''));
  return m ? [ecosystem, `${m[1]}::appstream`] : ecosystem ? [ecosystem] : [];
}

function dedupe(list) {
  const seen = new Map();
  for (const c of list) {
    const key = `${c.type}\n${c.name}\n${c.version}`;
    const had = seen.get(key);
    if (!had) seen.set(key, { ...c, binaries: c.binary ? [c.binary] : [], binary: undefined, binaryVersion: undefined });
    else if (c.binary && !had.binaries.includes(c.binary)) had.binaries.push(c.binary);
  }
  return [...seen.values()].map(({ binary, binaryVersion, ...rest }) => rest);
}

/**
 * what the stacked filesystem says is installed.
 * rpmReader(buffer) is handed an rpm sqlite database and resolves to packages; left out, rpm images are only noticed
 */
async function inventory(files, notes, rpmReader) {
  const out = { os: null, feed: null, feeds: [], components: [], notes: [...notes] };
  let osText = null;
  for (const p of OS_RELEASE) {
    osText = read(files, p);
    if (osText) break;
  }
  out.os = osRelease(osText ? osText.toString('utf8') : '');
  const feed = osFeed(out.os);
  out.feed = feed.ecosystem;
  out.feeds = feed.ecosystem ? [feed.ecosystem, ...(feed.also || [])] : [];
  if (feed.why) out.notes.push(feed.why);

  const found = [];
  const status = read(files, DPKG_STATUS);
  if (status) found.push(...dpkgStatus(status.toString('utf8')));
  for (const [path] of files) {
    if (DPKG_STATUS_D.test(path)) {
      const data = read(files, path);
      if (data) found.push(...dpkgStatus(data.toString('utf8')));
    }
  }
  const apk = APK_INSTALLED.map((p) => read(files, p)).find(Boolean);
  if (apk) found.push(...apkInstalled(apk.toString('utf8')));

  const sqlite = RPM_SQLITE.map((p) => read(files, p)).find(Boolean);
  const bdb = sqlite ? null : RPM_BDB.map((p) => read(files, p)).find(Boolean);
  if ((sqlite || bdb) && rpmReader) {
    try {
      found.push(...(await rpmReader(sqlite || bdb, sqlite ? 'sqlite' : 'bdb')));
    } catch (err) {
      out.notes.push(`the rpm database could not be read: ${err.message}`);
    }
  } else if (!sqlite && !bdb && RPM_NDB.some((p) => files.has(p))) {
    out.notes.push('the rpm database is in the ndb format SUSE uses, which is not read here. an external scanner can check it');
  }

  for (const [path, entry] of files) {
    if (!entry.data) continue;
    if (NPM_PACKAGE.test(path)) {
      const c = npmPackage(entry.data, path);
      if (c) found.push({ ...c, path: path.slice(0, -'/package.json'.length) });
    } else if (PY_METADATA.test(path)) {
      const c = pythonMetadata(entry.data);
      if (c) found.push(c);
    }
    if (found.length > MAX_COMPONENTS) {
      out.notes.push(`more than ${MAX_COMPONENTS} components, the rest are not listed`);
      break;
    }
  }

  // npm keeps the path, the same version can sit in many folders
  const npmPaths = new Map();
  for (const c of found) {
    if (c.type !== 'npm') continue;
    const key = `${c.name}@${c.version}`;
    if (!npmPaths.has(key)) npmPaths.set(key, []);
    if (npmPaths.get(key).length < 20) npmPaths.get(key).push(c.path);
  }
  out.components = dedupe(found.map(({ path, ...c }) => c)).map((c) => {
    const ecosystem = c.type === 'npm' ? 'npm' : c.type === 'pypi' ? 'PyPI' : feed.ecosystem;
    const paths = c.type === 'npm' ? npmPaths.get(`${c.name}@${c.version}`) : undefined;
    return { ...c, ecosystem: ecosystem || null, ...(paths ? { paths } : {}) };
  });
  const osPackages = out.components.filter((c) => c.type !== 'npm' && c.type !== 'pypi').length;
  if (out.os && !osPackages && !sqlite && !bdb && !RPM_NDB.some((p) => files.has(p))) out.notes.push('no OS package database was found in the image');
  return out;
}

module.exports = {
  want, stacker, read, inventory, osFeed, feedsFor,
  parsers: { osRelease, dpkgStatus, apkInstalled, npmPackage, pythonMetadata, paragraphs }
};
