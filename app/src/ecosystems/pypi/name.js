// PEP 503 package names, i.e. how Python compares names.
// Author: Tim Rice
//
// Opposite of npm. Flask, flask and FLASK are one project, zope.interface and zope_interface too:
// separator runs fold to one dash, then lowercase. a rule that didn't fold could be
// strolled around by typing the name differently.
// So allow and deny both match folded here. do NOT share a helper with npm's.

// can't start or end on a separator
const NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

// npm's 214 ceiling. only here so nothing absurd gets truncated into a different name
const MAX_LENGTH = 214;

function valid(name) {
  if (typeof name !== 'string') return false;
  if (!name.length || name.length > MAX_LENGTH) return false;
  return NAME_RE.test(name);
}

// canonical spelling, everything stored/compared/logged goes through here
function normalize(name) {
  return String(name === null || name === undefined ? '' : name)
    .replace(/[-_.]+/g, '-')
    .toLowerCase();
}

//two spellings, one project?
function same(a, b) {
  return normalize(a) === normalize(b);
}

// rules and requests both call this, so they can't normalize differently
function forMatching(name) {
  return normalize(name);
}

module.exports = { valid, normalize, same, forMatching, MAX_LENGTH, NAME_RE };
