// Swift package versions are semantic versions (the registry protocol asks for exactly that). Rule ranges read the npm
// way, which is how most people write semver ranges: 1.3.0, ^1.3.0, ~1.3, >=1.3 <2, with || between alternatives
// Author: Tim Rice

const semver = require('semver');

const MAX = 128;
const valid = (v) => String(v || '').length <= MAX && !!semver.valid(String(v || '').trim(), { loose: false });
const compare = (a, b) => (valid(a) && valid(b) ? semver.compare(a, b) : !valid(a) && !valid(b) ? 0 : !valid(a) ? -1 : 1);
const isPrerelease = (v) => valid(v) && semver.prerelease(v) !== null;

function validRange(range) {
  const r = String(range || '').trim();
  if (r.length > MAX) return false;
  if (!r) return true;
  return r.split('||').every((part) => part.trim() && semver.validRange(part.trim()) !== null);
}

// prereleases: true lets any pre-release in (a deny rule), 'auto' (the default) only when the range names one
function satisfies(version, range, options = {}) {
  if (!valid(version)) return false;
  const r = String(range || '').trim();
  const pre = options.prereleases === undefined ? 'auto' : options.prereleases;
  if (!r) return pre === true || !isPrerelease(version);
  try {
    return semver.satisfies(version, r, { includePrerelease: pre === true });
  } catch (err) {
    return false;
  }
}

function maxSatisfying(versions, range) {
  const ok = versions.filter((v) => valid(v) && satisfies(v, range, { prereleases: false }));
  return ok.length ? ok.sort((a, b) => compare(b, a))[0] : null;
}

module.exports = { MAX, valid, compare, isPrerelease, validRange, satisfies, maxSatisfying };
