// Options of a mirror registry (RPM now, APT next): a distro repository is one address, not a set of names.
// Author: Tim Rice
//
// a mirror is reached at /<type>/<its name>/, so every one stands alone: no pattern, no default. two options:
// filtered, the index handed out lists only what the rules allow (the client can not check the repository's signature
// then, since the index is no longer the one the distro signed), and advisories, the OSV feed its packages are in

// a file its registry publishes no hash for can not be checked against anything. npm, PyPI and rubygems publish one
// for every file, so those refuse it; the rest often have nothing to offer (a NuGet feed with no catalog, a podspec
// that points at a git tag, a Maven file with no .sha1, a Packagist archive with no shasum), so they keep letting it
// through until somebody says otherwise. Either way an upstream can be told the opposite.
const HASH_EXPECTED = ['npm', 'pypi', 'rubygems'];

// Swift has no hash anywhere in the protocol: a release is a git tag's archive and nothing more. requiring one can not
// be honored, so it is refused when saved. a record that already has it set (from before this was checked) still loads
// and works as before, the flag just does nothing, and the Swift side logs a warning about it
const HASH_IMPOSSIBLE = ['swift'];

// whether this upstream's files have to come with a published hash
function requiresHash(up) {
  if (HASH_IMPOSSIBLE.includes(up && up.ecosystem)) return false;
  if (up && up.options && typeof up.options.requireHash === 'boolean') return up.options.requireHash;
  return HASH_EXPECTED.includes(up && up.ecosystem);
}

// the feeds OSV has for each mirror type, the way OSV spells them
const FEEDS = {
  rpm: ['AlmaLinux:8', 'AlmaLinux:9', 'AlmaLinux:10', 'Rocky Linux:8', 'Rocky Linux:9', 'Rocky Linux:10', 'Red Hat'],
  apt: ['Debian:11', 'Debian:12', 'Debian:13', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04:LTS', 'Ubuntu:24.04:LTS', 'Ubuntu:26.04:LTS']
};

const isMirror = (ecosystem) => Object.prototype.hasOwnProperty.call(FEEDS, ecosystem);

// the name as it appears in the address: AlmaLinux 9 BaseOS -> almalinux-9-baseos
const slug = (name) => String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);

// whatever is stored, as { filtered, advisories }. a damaged value reads as the defaults
function parse(raw) {
  let o = {};
  try {
    o = raw ? JSON.parse(String(raw)) : {};
  } catch (err) {
    o = {};
  }
  const out = { filtered: o && o.filtered === true, advisories: o && typeof o.advisories === 'string' ? o.advisories : '' };
  // only set when somebody chose, so the kind's own answer stands when nobody has
  if (o && typeof o.requireHash === 'boolean') out.requireHash = o.requireHash;
  return out;
}

// what a caller sent, checked, as the text to store. unknown keys are dropped, an unknown feed is refused
function check(ecosystem, body, fail) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const yes = (v) => v === true || v === 'true' || v === 1 || v === '1';
  const out = {};
  if (isMirror(ecosystem)) {
    const advisories = b.advisories === undefined || b.advisories === null ? '' : String(b.advisories);
    if (advisories && !FEEDS[ecosystem].includes(advisories)) fail(400, `advisories come from one of: ${FEEDS[ecosystem].join(', ')}`);
    out.filtered = yes(b.filtered);
    out.advisories = advisories;
  }
  // left out entirely when nobody chose, so the kind's own answer keeps applying
  if (b.requireHash !== undefined && b.requireHash !== null && b.requireHash !== '') {
    out.requireHash = yes(b.requireHash);
    if (out.requireHash && HASH_IMPOSSIBLE.includes(ecosystem)) {
      fail(400, 'Swift packages carry no checksum, so require a hash can not be turned on for a Swift upstream');
    }
  }
  return JSON.stringify(out);
}

module.exports = { FEEDS, HASH_EXPECTED, HASH_IMPOSSIBLE, isMirror, requiresHash, slug, parse, check };
