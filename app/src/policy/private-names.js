// Is this name ours? A reserved name is only ever served from what was published here, never asked of an upstream,
// so nobody can register the same name publicly and have it installed instead (dependency confusion).
// Author: Tim Rice
// patterns: an exact name, an npm scope as @acme/*, an image namespace as acme/*, or a prefix ending in *. nothing else,
// so a pattern is never a regex

const repo = require('../db/repositories/private-names');
const pypiName = require('../ecosystems/pypi/name');
const ociName = require('../ecosystems/oci/name');

const CACHE_MS = 5000;
const ECOSYSTEMS = ['npm', 'pypi', 'oci', 'nuget', 'rubygems', 'maven'];
// com.acme:widgets, com.acme:* or com.acme.*: a coordinate, or a prefix ending in *
const MAVEN_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]*(\*|:(\*|[A-Za-z0-9_][A-Za-z0-9_.-]*\*?))?$/;
// a gem name, or a prefix ending in *: letters, digits, dashes, underscores and dots
const GEM_PATTERN = /^[a-z0-9][a-z0-9_.-]*\*?$/;

let cache = null;
let cachedAt = 0;

function invalidate() {
  cache = null;
}

// how a name is compared: npm names are lower case already, PyPI folds - _ . and case together, an image drops stray slashes
function fold(ecosystem, name) {
  const text = String(name || '').trim();
  if (ecosystem === 'oci') return ociName.fold(text);
  return ecosystem === 'pypi' ? pypiName.normalize(text) : text.toLowerCase();
}

const NPM_PATTERN = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/(?:\*|[a-z0-9~-][a-z0-9._~-]*\*?)|[a-z0-9~-][a-z0-9._~-]*\*?)$/;
const PYPI_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:-?\*)?$|^[a-z0-9]\*$/;
// NuGet ids ignore case: Acme.Logging, or a prefix like Acme.*
const NUGET_PATTERN = /^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_.-])?\*?$/;

// the folded pattern, or null when it is not one this accepts
function checkPattern(ecosystem, raw) {
  if (!ECOSYSTEMS.includes(ecosystem)) return null;
  const text = String(raw || '').trim();
  if (!text || text.length > 214 || text === '*') return null;
  if (ecosystem === 'pypi') {
    const star = text.endsWith('*');
    const body = star ? text.slice(0, -1) : text;
    if (!body) return null;
    const folded = pypiName.normalize(body.replace(/[-_.]+$/, '')) + (star && /[-_.]$/.test(body) ? '-*' : (star ? '*' : ''));
    return PYPI_PATTERN.test(folded) ? folded : null;
  }
  if (ecosystem === 'oci') {
    const folded = ociName.fold(text);
    const star = folded.endsWith('*');
    // acme/api, acme/* or acme-*: what is left once the star and the separator before it go must be a real name
    const body = star ? folded.slice(0, -1).replace(/[-._/]+$/, '') : folded;
    if (!body || !ociName.valid(body) || (star ? folded.slice(0, -1) : folded).includes('*')) return null;
    return folded;
  }
  const lower = text.toLowerCase();
  if (ecosystem === 'rubygems') return GEM_PATTERN.test(lower) ? lower : null;
  // a Maven coordinate keeps its case: a repository path is case sensitive
  if (ecosystem === 'maven') return MAVEN_PATTERN.test(text) ? text : null;
  if (ecosystem === 'nuget') return NUGET_PATTERN.test(lower) && !/\.\.|--|__/.test(lower) ? lower : null;
  return NPM_PATTERN.test(lower) ? lower : null;
}

function matches(pattern, name) {
  return pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern;
}

async function loaded() {
  if (cache && Date.now() - cachedAt < CACHE_MS) return cache;
  const rows = await repo.all();
  cache = new Map(ECOSYSTEMS.map((eco) => [eco, rows.filter((r) => r.ecosystem === eco)]));
  cachedAt = Date.now();
  return cache;
}

// the reserved entry that covers this name, or null
async function reservedBy(ecosystem, name) {
  if (!ECOSYSTEMS.includes(ecosystem) || !name) return null;
  const folded = fold(ecosystem, name);
  const rows = (await loaded()).get(ecosystem) || [];
  return rows.find((r) => matches(r.pattern, folded)) || null;
}

async function isPrivate(ecosystem, name) {
  return !!(await reservedBy(ecosystem, name));
}

// is anything reserved for this ecosystem at all
async function anyFor(ecosystem) {
  return ((await loaded()).get(ecosystem) || []).length > 0;
}

module.exports = { ECOSYSTEMS, fold, checkPattern, matches, reservedBy, isPrivate, anyFor, invalidate };
