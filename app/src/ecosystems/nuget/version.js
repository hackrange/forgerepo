// NuGet versions and ranges, the way NuGet.Versioning reads them.
// Author: Tim Rice
//
// 1.2, 1.2.3 and 1.2.3.4, a pre-release label after a dash, build metadata after a plus that never counts. versions are
// compared on their numbers, a pre-release sorts before its release. a rule range takes NuGet's own brackets
// ([1.0,2.0), (,3.0]), floating stars (13.*), comparators (>=13.0 <14) and || between alternatives. a bare version in a
// rule is that exact version, the same as for npm and PyPI (NuGet itself would read it as "this or newer")

const MAX = 128;
const VERSION_RE = /^v?(\d{1,9})\.(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

function parse(text) {
  const s = String(text || '').trim();
  if (!s || s.length > MAX) return null;
  const m = VERSION_RE.exec(s);
  if (!m) return null;
  return {
    parts: [Number(m[1]), Number(m[2]), Number(m[3] || 0), Number(m[4] || 0)],
    release: m[5] ? m[5].split('.') : []
  };
}

const valid = (text) => !!parse(text);

// the spelling nuget.org uses in addresses: three numbers, a fourth only when it is not zero, no metadata, lower case
function normalize(text) {
  const v = parse(text);
  if (!v) return null;
  const nums = v.parts[3] ? v.parts : v.parts.slice(0, 3);
  return `${nums.join('.')}${v.release.length ? `-${v.release.join('.')}` : ''}`.toLowerCase();
}

const isPrerelease = (text) => {
  const v = parse(text);
  return !!v && v.release.length > 0;
};

function compareLabel(a, b) {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) return Math.sign(Number(a) - Number(b));
  if (an) return -1;
  if (bn) return 1;
  const al = a.toLowerCase();
  const bl = b.toLowerCase();
  return al < bl ? -1 : al > bl ? 1 : 0;
}

// -1, 0 or 1. not a version sorts first, so a list of rubbish still sorts
function compare(x, y) {
  const a = typeof x === 'string' ? parse(x) : x;
  const b = typeof y === 'string' ? parse(y) : y;
  if (!a || !b) return !a && !b ? 0 : !a ? -1 : 1;
  for (let i = 0; i < 4; i += 1) if (a.parts[i] !== b.parts[i]) return Math.sign(a.parts[i] - b.parts[i]);
  if (!a.release.length || !b.release.length) return a.release.length === b.release.length ? 0 : a.release.length ? -1 : 1;
  for (let i = 0; i < Math.max(a.release.length, b.release.length); i += 1) {
    if (i >= a.release.length) return -1;
    if (i >= b.release.length) return 1;
    const c = compareLabel(a.release[i], b.release[i]);
    if (c) return c;
  }
  return 0;
}

const eq = (a, b) => compare(a, b) === 0 && valid(a) && valid(b);

// one alternative of a range, as a test on a parsed version. null when it is not a range this reads
function side(text) {
  const t = String(text).trim();
  if (!t || t === '*') return () => true;
  // [1.0,2.0) and friends. [1.0] is exactly 1.0
  const br = /^([[(])\s*([^,\])]*?)\s*(?:,\s*([^\])]*?)\s*)?([\])])$/.exec(t);
  if (br) {
    const [, open, lo, hi, close] = br;
    if (hi === undefined) {
      if (open !== '[' || close !== ']' || !valid(lo)) return null;
      return (v) => compare(v, parse(lo)) === 0;
    }
    if ((lo && !valid(lo)) || (hi && !valid(hi)) || (!lo && !hi)) return null;
    const low = lo ? parse(lo) : null;
    const high = hi ? parse(hi) : null;
    return (v) => (!low || (open === '[' ? compare(v, low) >= 0 : compare(v, low) > 0))
      && (!high || (close === ']' ? compare(v, high) <= 0 : compare(v, high) < 0));
  }
  // 13.* or 13.0.*: the same numbers in front, any release
  const star = /^(\d{1,9}(?:\.\d{1,9}){0,2})\.\*$/.exec(t);
  if (star) {
    const lead = star[1].split('.').map(Number);
    return (v) => lead.every((n, i) => v.parts[i] === n) && !v.release.length;
  }
  // comparators, all of them must hold: >=13.0 <14
  const tests = [];
  for (const word of t.split(/\s+/)) {
    const m = /^(>=|<=|>|<|=)?(.+)$/.exec(word);
    // <14 is <14.0, a comparator reads like people write it
    const text = m && /^\d+$/.test(m[2]) ? `${m[2]}.0` : m && m[2];
    if (!m || !valid(text)) return null;
    const bound = parse(text);
    const op = m[1] || '=';
    tests.push((v) => {
      const c = compare(v, bound);
      return op === '>=' ? c >= 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '<' ? c < 0 : c === 0;
    });
  }
  return (v) => tests.every((f) => f(v));
}

function validRange(range) {
  const r = String(range || '').trim();
  if (r.length > MAX) return false;
  if (!r) return true;
  const alts = r.split('||').map((x) => x.trim());
  return alts.every((a) => a && side(a));
}

// does this version fall in the range? prereleases: true lets any pre-release in (a deny rule), 'auto' (the default)
// only when the range itself names one, false never
function satisfies(version, range, options = {}) {
  const v = parse(version);
  if (!v) return false;
  const r = String(range || '').trim();
  const pre = options.prereleases === undefined ? 'auto' : options.prereleases;
  if (v.release.length && pre !== true && !(pre === 'auto' && /\d-/.test(r))) return false;
  if (!r) return true;
  const alts = r.split('||').map((x) => x.trim()).filter(Boolean);
  return alts.some((a) => {
    const f = side(a);
    return !!f && f(v);
  });
}

// the newest of a list a range allows, stable first, or null
function maxSatisfying(versions, range) {
  const ok = versions.filter((v) => valid(v) && satisfies(v, range, { prereleases: false }));
  return ok.length ? ok.sort((a, b) => compare(b, a))[0] : null;
}

module.exports = { MAX, parse, valid, normalize, isPrerelease, compare, eq, validRange, satisfies, maxSatisfying };
