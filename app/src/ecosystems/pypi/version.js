// PEP 440 versions, aka how Python numbers its releases.
// Author: Tim Rice
//
// Not semver, no matter how hard you squint. 1.0 == 1.0.0, 1.0rc1 < 1.0 < 1.0.post1,
// 2!1.0 beats every 1.x, and +local only breaks ties.
// a wrong comparison doesn't throw, it just quietly serves a blocked release. so no shortcuts

// alternation order is load bearing: alpha before a, preview before pre, post before r
const VERSION_RE = new RegExp(
  '^\\s*v?' +
    '(?:(\\d+)!)?' +                                                // 1  epoch
    '(\\d+(?:\\.\\d+)*)' +                                          // 2  release segments
    '(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\\d+)?)?' +   // 3  pre label, 4 pre number
    '(?:-(\\d+)|[-_.]?(post|rev|r)[-_.]?(\\d+)?)?' +                // 5  old style -N post, 6 post label, 7 post number
    '(?:[-_.]?(dev)[-_.]?(\\d+)?)?' +                               //8  dev, 9 dev number
    '(?:\\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?' +                      // 10 local, the bit after +
    '\\s*$',
  'i'
);

// every pre label spelling PEP 440 accepts -> normalized form
const PRE_LABELS = {
  alpha: 'a', a: 'a',
  beta: 'b', b: 'b',
  c: 'rc', pre: 'rc', preview: 'rc', rc: 'rc'
};

//null, not a throw. unparseable versions on an index are a normal Tuesday
function parse(input) {
  if (input && typeof input === 'object' && input.pep440) return input;

  const raw = String(input === null || input === undefined ? '' : input);
  const m = VERSION_RE.exec(raw);
  if (!m) return null;

  const epoch = m[1] ? parseInt(m[1], 10) : 0;
  const release = m[2].split('.').map((n) => parseInt(n, 10));

  // label with no number = zero, so 1.0a and 1.0a0 are the same release
  const pre = m[3] ? [PRE_LABELS[m[3].toLowerCase()], m[4] ? parseInt(m[4], 10) : 0] : null;

  // 1.0-1 is the old spelling of 1.0.post1, lands in the same field
  let post = null;
  if (m[5] !== undefined) post = parseInt(m[5], 10);
  else if (m[6]) post = m[7] ? parseInt(m[7], 10) : 0;

  const dev = m[8] ? (m[9] ? parseInt(m[9], 10) : 0) : null;

  // numeric local bits compare as numbers, the rest as text
  const local = m[10]
    ? m[10].toLowerCase().split(/[-_.]/).map((s) => (/^\d+$/.test(s) ? parseInt(s, 10) : s))
    : null;

  const v = { pep440: true, epoch, release, pre, post, dev, local, raw: raw.trim() };
  v.normalized = format(v);
  return v;
}

function valid(input) {
  return parse(input) !== null;
}

// canonical spelling, so one release can't become two db rows
function format(v) {
  let s = '';
  if (v.epoch) s += `${v.epoch}!`;
  s += v.release.join('.');
  if (v.pre) s += `${v.pre[0]}${v.pre[1]}`;
  if (v.post !== null) s += `.post${v.post}`;
  if (v.dev !== null) s += `.dev${v.dev}`;
  if (v.local) s += `+${v.local.join('.')}`;
  return s;
}

function normalize(input) {
  const v = parse(input);
  return v ? v.normalized : null;
}

// 1.0 == 1.0.0, so chop trailing zeros. keep one segment though or 0 vanishes
function withoutTrailingZeros(release) {
  const out = release.slice();
  while (out.length > 1 && out[out.length - 1] === 0) out.pop();
  return out;
}

function compareRelease(a, b) {
  const x = withoutTrailingZeros(a);
  const y = withoutTrailingZeros(b);
  const len = Math.max(x.length, y.length);
  for (let i = 0; i < len; i += 1) {
    const p = i < x.length ? x[i] : 0;
    const q = i < y.length ? y[i] : 0;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

// keys are a sentinel (+/-Infinity), number, string or tuple. sentinels win or lose outright
function compareKey(x, y) {
  const xs = Array.isArray(x);
  const ys = Array.isArray(y);

  if (!xs && !ys) {
    if (typeof x === 'number' && typeof y === 'number') return x < y ? -1 : x > y ? 1 : 0;
    const a = String(x);
    const b = String(y);
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (!xs) return x === -Infinity ? -1 : 1;
  if (!ys) return y === -Infinity ? 1 : -1;

  const len = Math.max(x.length, y.length);
  for (let i = 0; i < len; i += 1) {
    // shorter tuple sorts first, same as python does it
    const r = compareKey(i < x.length ? x[i] : -Infinity, i < y.length ? y[i] : -Infinity);
    if (r) return r;
  }
  return 0;
}

// a bare dev release goes before every pre-release of it (1.0.dev1 < 1.0a1)
function preKey(v) {
  if (v.pre === null && v.post === null && v.dev !== null) return -Infinity;
  if (v.pre === null) return Infinity;
  return v.pre;
}

// no post marker sorts first. 1.0 before 1.0.post1
function postKey(v) {
  return v.post === null ? -Infinity : v.post;
}

// No dev marker sorts LAST, so 1.0.post1.dev2 comes before 1.0.post1.
function devKey(v) {
  return v.dev === null ? Infinity : v.dev;
}

// No local sorts first. inside local, numbers outrank words, hence the -Infinity
function localKey(v) {
  if (v.local === null) return -Infinity;
  return v.local.map((s) => (typeof s === 'number' ? [s, ''] : [-Infinity, s]));
}

function compare(a, b) {
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) throw new TypeError(`cannot compare ${JSON.stringify(a)} with ${JSON.stringify(b)}`);

  if (x.epoch !== y.epoch) return x.epoch < y.epoch ? -1 : 1;

  const release = compareRelease(x.release, y.release);
  if (release) return release;

  let r = compareKey(preKey(x), preKey(y));
  if (r) return r;
  r = compareKey(postKey(x), postKey(y));
  if (r) return r;
  r = compareKey(devKey(x), devKey(y));
  if (r) return r;
  return compareKey(localKey(x), localKey(y));
}

function rcompare(a, b) {
  return compare(b, a);
}

function eq(a, b) { return compare(a, b) === 0; }
function gt(a, b) { return compare(a, b) > 0; }
function lt(a, b) { return compare(a, b) < 0; }

// pre or dev marker. a post release is NOT a pre-release, and < and > care
function isPrerelease(input) {
  const v = parse(input);
  return !!v && (v.pre !== null || v.dev !== null);
}

function isPostrelease(input) {
  const v = parse(input);
  return !!v && v.post !== null;
}

function sameBase(a, b) {
  return a.epoch === b.epoch && compareRelease(a.release, b.release) === 0;
}

function withoutLocal(v) {
  return v.local === null ? v : { ...v, local: null };
}

// longer ops first, or === reads as == plus "=1.0". runs on a trimmed part, a lazy .+? before \s*$ crawls on long spaces
const CLAUSE_RE = /^(===|==|!=|~=|<=|>=|<|>)\s*(.+)$/;

// pip's comma form, e.g. ">=1.4,<2,!=1.7.1". empty or * matches everything.
// No operator means ==. pip would reject that, but SBOM imports drop bare versions in the
// range column, and reading them any other way = a whitelist rule nobody can install
function parseSpecifierSet(text) {
  const raw = String(text === null || text === undefined ? '' : text).trim();
  if (!raw || raw === '*') return [];

  const clauses = [];
  for (const part of raw.split(',')) {
    if (!part.trim()) continue;
    const m = CLAUSE_RE.exec(part.trim());
    if (!m) {
      // bare version (maybe .*) or garbage
      const only = part.trim();
      const wild = only.endsWith('.*');
      const asVersion = parse(wild ? only.slice(0, -2) : only);
      if (!asVersion) return null;
      clauses.push({ op: '==', value: only, bare: only, wildcard: wild, version: asVersion });
      continue;
    }

    const op = m[1];
    const value = m[2];
    const wildcard = value.endsWith('.*');
    const bare = wildcard ? value.slice(0, -2) : value;

    // === is a plain text compare, the only op that doesn't need a real version
    const version = op === '===' ? null : parse(bare);
    if (op !== '===' && !version) return null;
    if (wildcard && op !== '==' && op !== '!=') return null;

    clauses.push({ op, value, bare, wildcard, version });
  }
  return clauses;
}

function validSpecifierSet(text) {
  return parseSpecifierSet(text) !== null;
}

// ==1.1.* covers 1.1, 1.1.3 and 1.1rc1. Not 1.2, nice try.
function matchesPrefix(v, spec) {
  if (v.epoch !== spec.epoch) return false;
  for (let i = 0; i < spec.release.length; i += 1) {
    const got = i < v.release.length ? v.release[i] : 0;
    if (got !== spec.release[i]) return false;
  }
  return true;
}

function matchesEqual(v, clause) {
  if (clause.wildcard) return matchesPrefix(v, clause.version);
  // no local on the spec? ignore the version's. ==1.0 is happy with 1.0+ubuntu.1
  const left = clause.version.local === null ? withoutLocal(v) : v;
  return compare(left, clause.version) === 0;
}

function matchesClause(v, clause) {
  const spec = clause.version;

  switch (clause.op) {
    case '===':
      return v.raw === clause.value.trim() || v.normalized === clause.value.trim();

    case '==':
      return matchesEqual(v, clause);

    case '!=':
      return !matchesEqual(v, clause);

    // <= and >= ignore the local segment, so 1.0+ubuntu.1 satisfies >=1.0
    case '<=':
      return compare(withoutLocal(v), spec) <= 0;

    case '>=':
      return compare(withoutLocal(v), spec) >= 0;

    case '<':
      if (compare(v, spec) >= 0) return false;
      // to a human 2.0rc1 is part of 2.0, so <2.0 skips it unless the bound is a pre itself
      if (!isPrerelease(spec) && isPrerelease(v) && sameBase(v, spec)) return false;
      return true;

    case '>':
      if (compare(v, spec) <= 0) return false;
      // mirror image. >1.0 skips 1.0.post1 and 1.0+local
      if (!isPostrelease(spec) && isPostrelease(v) && sameBase(v, spec)) return false;
      if (v.local !== null && sameBase(v, spec)) return false;
      return true;

    // ~=1.4.5 is >=1.4.5,==1.4.*. needs 2+ segments to fence anything in
    case '~=': {
      if (spec.release.length < 2) return false;
      if (compare(withoutLocal(v), spec) < 0) return false;
      return matchesPrefix(v, { epoch: spec.epoch, release: spec.release.slice(0, -1) });
    }

    default:
      return false;
  }
}

// prereleases is three-way on purpose, same as pip:
//   true   every pre-release counts (default, matches npm's includePrerelease)
//   false  never, whatever the range says
//   'auto' pip's default, only if the range names one. resolver behavior, not policy
function satisfies(version, specifierSet, options) {
  const mode = options && options.prereleases !== undefined ? options.prereleases : true;
  const v = parse(version);
  if (!v) return false;

  const clauses = parseSpecifierSet(specifierSet);
  if (clauses === null) return false;

  if (mode !== true && isPrerelease(v)) {
    if (mode !== 'auto') return false;
    if (!namesAPrerelease(clauses)) return false;
  }

  return clauses.every((c) => matchesClause(v, c));
}

// Only inclusive ops invite pre-releases in under 'auto'. <1.0rc1 names where it
// stops, not something it lets in. easy to miss
const INCLUSIVE_OPS = new Set(['==', '>=', '<=', '~=', '===']);

function namesAPrerelease(clauses) {
  return clauses.some((c) => {
    if (!INCLUSIVE_OPS.has(c.op)) return false;
    // === has no parsed version stored
    const spec = c.version || parse(c.bare);
    return !!spec && (spec.pre !== null || spec.dev !== null);
  });
}

// newest version in the set, or null
function maxSatisfying(versions, specifierSet, options) {
  let best = null;
  for (const raw of versions || []) {
    if (!satisfies(raw, specifierSet, options)) continue;
    if (best === null || compare(raw, best) > 0) best = raw;
  }
  return best;
}

//newest first, like every listing on this box. unparseable junk gets dropped
function sort(versions) {
  return (versions || []).filter(valid).sort(rcompare);
}

module.exports = {
  parse,
  valid,
  normalize,
  format,
  compare,
  rcompare,
  sort,
  eq,
  gt,
  lt,
  isPrerelease,
  isPostrelease,
  satisfies,
  maxSatisfying,
  parseSpecifierSet,
  validSpecifierSet
};
