// Lockfiles and SBOMs that are not npm's own JSON: yarn.lock, pnpm-lock.yaml, CycloneDX XML, requirements files,
// poetry.lock, uv.lock, pylock.toml and Pipfile.lock. and package urls, for every type the box has rules for.
// Author: Tim Rice
// every parser here walks lines or tags once and expands nothing. an XML file with a DOCTYPE is refused outright

const semver = require('semver');
const ecosystems = require('../ecosystems');
const pypiName = require('../ecosystems/pypi/name');
const pypiVersion = require('../ecosystems/pypi/version');
const { parseRequirement } = require('../registry/pypi/tree');

// CycloneDX types that are context, not dependencies
const NOT_A_DEPENDENCY = new Set([
  'application', 'container', 'operating-system', 'device', 'device-driver',
  'firmware', 'file', 'platform', 'machine-learning-model', 'data'
]);

const LOCAL_SPEC = /^(workspace:|link:|portal:|file:|patch:|exec:|git\+|git:|github:|https?:)/i;

const base = (path) => String(path || '').split('/').pop().toLowerCase();

// how each purl type this box has rules for spells a name, from the purl's namespace and name. null is junk
const PURL_TYPES = {
  npm: (ns, n) => ({ ecosystem: 'npm', name: ns ? `${ns}/${n}` : n }),
  pypi: (ns, n) => (ns ? null : { ecosystem: 'pypi', name: pypiName.normalize(n) }),
  nuget: (ns, n) => (ns ? null : { ecosystem: 'nuget', name: n }),
  maven: (ns, n) => (ns && !ns.includes('/') ? { ecosystem: 'maven', name: `${ns}:${n}` } : null),
  gem: (ns, n) => (ns ? null : { ecosystem: 'rubygems', name: n }),
  cocoapods: (ns, n) => (ns ? null : { ecosystem: 'cocoapods', name: n }),
  composer: (ns, n) => (ns && !ns.includes('/') ? { ecosystem: 'composer', name: `${ns}/${n}`.toLowerCase() } : null),
  // pkg:rpm/almalinux/openssl@1:3.0.7-24.el9, the namespace is the distro
  rpm: (ns, n) => (!ns.includes('/') ? { ecosystem: 'rpm', name: n } : null),
  // pkg:deb/debian/libssl3@3.0.11-1~deb12u2, the namespace is the distro
  deb: (ns, n) => (!ns.includes('/') ? { ecosystem: 'apt', name: n } : null),
  // pkg:swift/github.com/apple/swift-log is the package apple.swift-log
  swift: (ns, n) => {
    const owner = String(ns || '').split('/').filter(Boolean);
    // pkg:swift/acme/tools, as this box writes a registry package, is acme.tools
    return owner.length >= 1 ? { ecosystem: 'swift', name: `${owner[owner.length - 1]}.${n}` } : null;
  }
};

// pkg:npm/%40scope/name@1.0.0, pkg:nuget/Newtonsoft.Json@13.0.3, pkg:maven/org.x/y@1 and friends, or the type of a
// purl this box has no rules for ({ other, type })
function fromPurl(text) {
  const purl = String(text || '');
  if (!purl.startsWith('pkg:')) return null;
  const body = purl.slice(4).split(/[?#]/)[0].replace(/^\/+/, '');
  const slash = body.indexOf('/');
  if (slash < 1) return { other: true, type: '' };
  const type = body.slice(0, slash).toLowerCase();
  const rest = body.slice(slash + 1);
  const cut = rest.lastIndexOf('@');
  let full;
  let version = '';
  try {
    full = decodeURIComponent(cut > 0 ? rest.slice(0, cut) : rest);
    version = cut > 0 ? decodeURIComponent(rest.slice(cut + 1)) : '';
  } catch (err) {
    return null;
  }
  const spell = Object.prototype.hasOwnProperty.call(PURL_TYPES, type) ? PURL_TYPES[type] : null;
  // a type the box knows but has switched out of the build is still another ecosystem here
  if (!spell || !ecosystems.get({ gem: 'rubygems', deb: 'apt' }[type] || type)) return { other: true, type: type.slice(0, 40) };
  const at = full.lastIndexOf('/');
  const got = type === 'npm' ? { ecosystem: 'npm', name: full } : spell(at > 0 ? full.slice(0, at) : '', at > 0 ? full.slice(at + 1) : full);
  if (!got || !got.name) return null;
  return { ...got, version };
}

// "lodash@^4.17.0" -> lodash, "@babel/core@npm:^7" -> @babel/core, and the range after it
function splitSpec(text) {
  const s = String(text).trim().replace(/^"|"$/g, '');
  const cut = s.lastIndexOf('@');
  if (cut <= 0) return null;
  return { name: s.slice(0, cut), range: s.slice(cut + 1).replace(/^npm:/, '') };
}

// ---------------------------------------------------------------- yarn.lock, classic and berry

function yarnLock(text) {
  const entries = [];
  const seen = new Set();
  let local = 0;
  let names = null;
  for (const line of text.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      names = line.replace(/:\s*$/, '').split(/,\s*/).map(splitSpec).filter(Boolean);
      if (names.length && names.every((n) => LOCAL_SPEC.test(n.range))) {
        local += 1;
        names = null;
      }
      continue;
    }
    const m = /^\s{2}version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (!m || !names || !names.length) continue;
    const key = `${names[0].name}@${m[1]}`;
    if (!seen.has(key) && semver.valid(m[1])) {
      seen.add(key);
      entries.push({ ecosystem: 'npm', name: names[0].name, spec: m[1], section: 'yarn.lock' });
    }
    names = null;
  }
  return { kind: 'yarn-lockfile', entries, notes: local ? [`${local} workspace, file, git or patched package(s) come from outside a registry and were left out`] : [] };
}

// ---------------------------------------------------------------- pnpm-lock.yaml, v5 to v9

function pnpmKey(raw) {
  let key = raw.trim().replace(/:$/, '').replace(/^['"]|['"]$/g, '').replace(/^\//, '');
  const paren = key.indexOf('(');
  if (paren > 0) key = key.slice(0, paren);
  let name;
  let version;
  // v5 wrote /name/1.0.0 and /@scope/name/1.0.0_peer@1, and that peer @ is not the version's
  const v5 = /^((?:@[^/@]+\/)?[^/@]+)\/(\d[^_/]*)(?:_.*)?$/.exec(key);
  if (v5) {
    name = v5[1];
    version = v5[2];
  } else {
    const at = key.lastIndexOf('@');
    if (at <= 0) return null;
    name = key.slice(0, at);
    version = key.slice(at + 1);
  }
  return semver.valid(version) ? { name, version } : null;
}

function pnpmLock(text) {
  const entries = [];
  const seen = new Set();
  let inPackages = false;
  let skipped = 0;
  for (const line of text.split('\n')) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    if (!/^\s/.test(line)) {
      inPackages = /^packages:\s*$/.test(line);
      continue;
    }
    if (!inPackages || !/^ {2}\S.*:\s*$/.test(line)) continue;
    const got = pnpmKey(line);
    if (!got) {
      skipped += 1;
      continue;
    }
    const key = `${got.name}@${got.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({ ecosystem: 'npm', name: got.name, spec: got.version, section: 'pnpm-lock.yaml' });
  }
  return { kind: 'pnpm-lockfile', entries, notes: skipped ? [`${skipped} pnpm entr(ies) are not a registry version and were left out`] : [] };
}

// ---------------------------------------------------------------- CycloneDX XML

const XML_TEXT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
function xmlText(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos);/gi, (all, code) => {
    if (code[0] !== '#') return XML_TEXT[code.toLowerCase()];
    const n = code[1].toLowerCase() === 'x' ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
    return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
  }).trim();
}

function cyclonedxXml(text) {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    return { kind: 'cyclonedx-xml', entries: [], error: 'the XML declares a DOCTYPE or entities, which a CycloneDX file never needs, so it was not read' };
  }
  const body = text.replace(/<!--[\s\S]*?-->/g, '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (all, inner) => inner.replace(/</g, '&lt;'));
  const entries = [];
  const stack = [];
  const open = [];
  let otherEcosystems = 0;
  const otherTypes = new Set();
  let notPackages = 0;
  const tag = /<(\/?)([A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)([^>]*?)(\/?)>/g;
  let m;
  while ((m = tag.exec(body))) {
    const closing = m[1] === '/';
    const name = m[3];
    const selfClosing = m[5] === '/';
    if (!closing) {
      if (name === 'component') {
        const type = /\btype\s*=\s*["']([^"']*)["']/.exec(m[4]);
        const ref = /\bbom-ref\s*=\s*["']([^"']*)["']/.exec(m[4]);
        open.push({ type: type ? type[1].toLowerCase() : '', ref: ref ? xmlText(ref[1]) : '', fields: {}, inMetadata: stack.includes('metadata') });
      } else if (['name', 'version', 'purl', 'group'].includes(name) && stack[stack.length - 1] === 'component' && open.length && !selfClosing) {
        const end = body.indexOf('<', tag.lastIndex);
        const current = open[open.length - 1];
        if (end > 0 && current.fields[name] === undefined) current.fields[name] = xmlText(body.slice(tag.lastIndex, end));
      }
      if (!selfClosing) stack.push(name);
      else if (name === 'component') open.pop();
      continue;
    }
    // close whatever was open down to this name, a sloppy file doesn't derail the rest
    const at = stack.lastIndexOf(name);
    if (at >= 0) stack.length = at;
    if (name !== 'component' || !open.length) continue;
    const c = open.pop();
    if (c.inMetadata) continue;
    // some tools leave purl out and put the package url in bom-ref instead
    const p = fromPurl(c.fields.purl || (c.ref.startsWith('pkg:') ? c.ref : ''));
    if (p && p.other) {
      otherEcosystems += 1;
      if (p.type) otherTypes.add(p.type);
    } else if (p) {
      const version = c.fields.version || p.version;
      if (p.name && version) entries.push({ ecosystem: p.ecosystem, name: p.name, spec: version, section: 'sbom:component' });
    } else if (NOT_A_DEPENDENCY.has(c.type)) {
      notPackages += 1;
    } else if (c.fields.name && c.fields.version) {
      entries.push({ ecosystem: 'npm', name: c.fields.group ? `${c.fields.group}/${c.fields.name}` : c.fields.name, spec: c.fields.version, section: 'sbom:component' });
    }
  }
  return { kind: 'cyclonedx-xml-sbom', entries, otherEcosystems, otherTypes: [...otherTypes], notPackages, notes: [] };
}

// ---------------------------------------------------------------- requirements files

const OPERATOR = /(===|==|~=|!=|<=|>=|<|>)/;

function requirements(text) {
  const entries = [];
  const notes = [];
  let includes = 0;
  let editable = 0;
  let fromUrl = 0;
  let unparsed = 0;
  const joined = text.replace(/\\\r?\n/g, ' ');
  for (const raw of joined.split('\n')) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('-')) {
      if (/^(-r|-c|--requirement|--constraint)\b/.test(line)) includes += 1;
      else if (/^(-e|--editable)\b/.test(line)) editable += 1;
      continue;
    }
    // --hash and friends ride on the same line
    const req = parseRequirement(line.replace(/\s--\S+.*$/, ''));
    if (!req) {
      unparsed += 1;
      continue;
    }
    if (req.url) {
      fromUrl += 1;
      continue;
    }
    // shown the way the file spells it, the review folds it again for matching
    const typed = /^[A-Za-z0-9][A-Za-z0-9._-]*/.exec(line);
    const name = typed && pypiName.normalize(typed[0]) === req.name ? typed[0] : req.name;
    entries.push({ ecosystem: 'pypi', name, spec: req.specifier || '', section: 'requirements' });
  }
  if (includes) notes.push(`${includes} line(s) pull in another requirements file, which was not followed; review that file too`);
  if (editable) notes.push(`${editable} editable install(s) are local code rather than a package and were left out`);
  if (fromUrl) notes.push(`${fromUrl} requirement(s) come straight from a url rather than an index and were left out`);
  if (unparsed) notes.push(`${unparsed} line(s) were not a requirement and were left out`);
  return { kind: 'python-requirements', entries, notes, unparsed };
}

// a .txt that is not named like one only counts when every line is a requirement with an operator
function looksLikeRequirements(text) {
  let hits = 0;
  for (const raw of text.replace(/\\\r?\n/g, ' ').split('\n')) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line || line.startsWith('-')) continue;
    if (/[\t,;]/.test(line.split(';')[0]) || !OPERATOR.test(line) || !parseRequirement(line.replace(/\s--\S+.*$/, ''))) return false;
    hits += 1;
  }
  return hits > 0;
}

// ---------------------------------------------------------------- poetry.lock, uv.lock, pylock.toml

function tomlLock(text, path) {
  const entries = [];
  let local = 0;
  let current = null;
  let sub = null;
  const flush = () => {
    if (current && current.name && current.version) {
      if (current.local) local += 1;
      else entries.push({ ecosystem: 'pypi', name: pypiName.normalize(current.name), spec: current.version, section: base(path) || 'toml lockfile' });
    }
    current = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (/^\[\[\s*packages?\s*\]\]\s*(#.*)?$/.test(line)) {
      flush();
      current = {};
      sub = null;
      continue;
    }
    if (line.startsWith('[')) {
      // poetry keeps where a package came from in [package.source]
      sub = current && /^\[\s*packages?\.source\s*\]/.test(line) ? 'source' : 'other';
      continue;
    }
    if (!current) continue;
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const [, key, value] = kv;
    if (sub === 'source') {
      if (key === 'type' && /"(git|directory|file|url)"/.test(value)) current.local = true;
      continue;
    }
    if (sub) continue;
    const str = /^"((?:[^"\\]|\\.)*)"/.exec(value);
    if ((key === 'name' || key === 'version') && str) current[key] = str[1];
    // uv: source = { editable = "." }, pylock: directory = { path = "." } and vcs = { ... }
    if (key === 'source' && /\b(editable|virtual|directory|path|git|url)\s*=/.test(value)) current.local = true;
    if (['directory', 'vcs', 'archive'].includes(key)) current.local = true;
  }
  flush();
  return { kind: 'python-lockfile', entries, notes: local ? [`${local} package(s) come from a local path, git or a url and were left out`] : [] };
}

// ---------------------------------------------------------------- composer.lock and composer.json (JSON)

// the platform (php, ext-json, lib-icu) is not a package anybody downloads
const composerPlatform = (name) => !String(name).includes('/');

// every locked package with its exact version. branches (dev-main) are not releases and are counted out
function composerLock(doc) {
  const entries = [];
  let branches = 0;
  for (const section of ['packages', 'packages-dev']) {
    for (const p of Array.isArray(doc[section]) ? doc[section] : []) {
      if (!p || typeof p !== 'object' || typeof p.name !== 'string' || typeof p.version !== 'string' || composerPlatform(p.name)) continue;
      if (/^dev-|-dev$/.test(p.version)) {
        branches += 1;
        continue;
      }
      entries.push({ ecosystem: 'composer', name: p.name.toLowerCase(), spec: p.version, section: `composer.lock:${section}` });
    }
  }
  return { kind: 'composer-lock', entries, notes: branches ? [`${branches} package(s) are locked to a branch rather than a release and were left out`] : [] };
}

// what composer.json asks for, as constraints
function composerJson(doc) {
  const entries = [];
  for (const section of ['require', 'require-dev']) {
    const map = doc[section];
    if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
    for (const [name, spec] of Object.entries(map)) {
      if (typeof spec !== 'string' || composerPlatform(name)) continue;
      entries.push({ ecosystem: 'composer', name: name.toLowerCase(), spec, section: `composer.json:${section}` });
    }
  }
  return { kind: 'composer-json', entries, notes: [] };
}

// ---------------------------------------------------------------- Pipfile.lock (JSON)

function pipfileLock(doc) {
  const entries = [];
  let local = 0;
  for (const section of ['default', 'develop']) {
    const map = doc[section];
    if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
    for (const [name, info] of Object.entries(map)) {
      if (!info || typeof info !== 'object') continue;
      if (info.git || info.path || info.file || info.editable) {
        local += 1;
        continue;
      }
      if (!pypiName.valid(name)) continue;
      entries.push({ ecosystem: 'pypi', name: pypiName.normalize(name), spec: typeof info.version === 'string' ? info.version : '', section: `Pipfile.lock:${section}` });
    }
  }
  return { kind: 'pipfile-lock', entries, notes: local ? [`${local} package(s) come from git, a path or a file and were left out`] : [] };
}

// ---------------------------------------------------------------- picking one

// an xml file that is a CycloneDX bom: maybe a declaration, maybe comments, then <bom or <!DOCTYPE.
// same as /^\s*(<\?xml[^>]*>\s*)?(<!--[\s\S]*?-->\s*)*<(bom|!DOCTYPE)[\s>]/i, which backtracked through a file of
// comments with nothing after them for as long as the file was long
function looksLikeBomXml(text) {
  const src = String(text);
  const skipSpace = (i) => { while (i < src.length && /\s/.test(src[i])) i += 1; return i; };
  const bomAt = (i) => /^<(bom|!DOCTYPE)[\s>]/i.test(src.slice(i, i + 10));
  let i = skipSpace(0);
  // the regex this replaces ignored case, <?XML included
  if (src.slice(i, i + 5).toLowerCase() === '<?xml') {
    const end = src.indexOf('>', i + 5);
    if (end < 0) return false;
    i = skipSpace(end + 1);
  }
  if (bomAt(i)) return true;
  if (!src.startsWith('<!--', i)) return false;
  // that regex let a comment end at ANY later -->, not only the first, so the bom may start after any of them.
  // looser than xml, but it decided which files get read as a bom and this keeps it deciding the same
  for (let e = src.indexOf('-->', i + 4); e >= 0; e = src.indexOf('-->', e + 1)) {
    if (bomAt(skipSpace(e + 3))) return true;
  }
  return false;
}

// a text file this module reads, or null to leave it to the name and version table reader
function detectText(path, text) {
  const name = base(path);
  if (looksLikeBomXml(text)) return cyclonedxXml(text);
  if (name === 'yarn.lock' || /^# yarn lockfile v1/m.test(text) || (/^__metadata:\s*$/m.test(text) && /@npm:/.test(text))) return yarnLock(text);
  if (/^pnpm-lock\.ya?ml$/.test(name) || (/^lockfileVersion:\s*['"]?\d/m.test(text) && /^packages:\s*$/m.test(text))) return pnpmLock(text);
  if (['poetry.lock', 'uv.lock', 'pylock.toml'].includes(name) || /^pylock\.[^/]+\.toml$/.test(name) || /^\[\[\s*packages?\s*\]\]\s*$/m.test(text)) {
    return tomlLock(text, path);
  }
  if (/^(requirements|constraints)[^/]*\.(txt|in)$/.test(name) || (name.endsWith('.txt') && looksLikeRequirements(text))) return requirements(text);
  return null;
}

// a parsed JSON document this module reads, or null
function detectJson(path, doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  if (doc._meta && typeof doc._meta === 'object' && (doc.default || doc.develop)) return pipfileLock(doc);
  if (typeof doc['content-hash'] === 'string' && Array.isArray(doc.packages)) return composerLock(doc);
  // package.json says dependencies, composer.json says require, with vendor/name keys
  const req = doc.require && typeof doc.require === 'object' && !Array.isArray(doc.require) ? Object.keys(doc.require) : [];
  if (!doc.dependencies && !doc.devDependencies && req.some((k) => k.includes('/'))) return composerJson(doc);
  return null;
}

// the file names worth pulling out of a zip
function wantedName(path) {
  const name = base(path);
  return name === 'yarn.lock' || /^pnpm-lock\.ya?ml$/.test(name) || ['poetry.lock', 'uv.lock', 'pylock.toml', 'pipfile.lock', 'composer.lock'].includes(name) ||
    /^pylock\.[^/]+\.toml$/.test(name) || /^(requirements|constraints)[^/]*\.in$/.test(name) || name.endsWith('.xml') || name.endsWith('.cdx');
}

function exactPypi(spec) {
  const s = String(spec || '').trim();
  const m = /^===?\s*([^\s,;]+)$/.exec(s);
  const v = m ? m[1] : s;
  return v && !OPERATOR.test(v) && pypiVersion.valid(v) ? v : null;
}

module.exports = {
  NOT_A_DEPENDENCY, fromPurl, detectText, detectJson, wantedName, exactPypi, looksLikeBomXml,
  yarnLock, pnpmLock, cyclonedxXml, requirements, tomlLock, pipfileLock, composerLock, composerJson
};
