// RPM versions: [epoch:]version-release, compared the way rpm itself does it (rpmvercmp), and rule ranges over them.
// Author: Tim Rice
//
// 1:3.0.7-24.el9 is epoch 1, version 3.0.7, release 24.el9. epochs compare as numbers (none is 0), then the version,
// then the release. inside each, runs of digits compare as numbers and runs of letters as text, a digit run beats a
// letter run, ~ sorts before anything (even the end: 1.0~rc1 < 1.0) and ^ after the end but before anything else.
// a rule range is comparators (>=3.0.7, <3.0.7-25.el9) with a space meaning and, and || between alternatives. a
// version without a release in a range means every release of it

const MAX = 128;
const EVR_RE = /^(?:(\d{1,9}):)?([A-Za-z0-9._+~^]+?)(?:-([A-Za-z0-9._+~^]+))?$/;

function parse(text) {
  const s = String(text || '').trim();
  if (!s || s.length > MAX) return null;
  const m = EVR_RE.exec(s);
  if (!m || !/[0-9]/.test(m[2])) return null;
  return { epoch: Number(m[1] || 0), version: m[2], release: m[3] === undefined ? null : m[3] };
}

const valid = (text) => !!parse(text);

// rpm's rpmvercmp, segment by segment
function vercmp(a, b) {
  if (a === b) return 0;
  let i = 0;
  let j = 0;
  for (;;) {
    while (i < a.length && !/[A-Za-z0-9~^]/.test(a[i])) i += 1;
    while (j < b.length && !/[A-Za-z0-9~^]/.test(b[j])) j += 1;
    if (a[i] === '~' || b[j] === '~') {
      if (a[i] !== '~') return 1;
      if (b[j] !== '~') return -1;
      i += 1;
      j += 1;
      continue;
    }
    if (a[i] === '^' || b[j] === '^') {
      if (i >= a.length) return -1;
      if (j >= b.length) return 1;
      if (a[i] !== '^') return 1;
      if (b[j] !== '^') return -1;
      i += 1;
      j += 1;
      continue;
    }
    if (i >= a.length || j >= b.length) break;
    const digits = /[0-9]/.test(a[i]);
    const run = (s, k) => {
      let e = k;
      while (e < s.length && (digits ? /[0-9]/.test(s[e]) : /[A-Za-z]/.test(s[e]))) e += 1;
      return e;
    };
    const ei = run(a, i);
    const ej = run(b, j);
    const sa = a.slice(i, ei);
    const sb = b.slice(j, ej);
    // a number against letters: the number is newer
    if (!sb) return digits ? 1 : -1;
    if (digits) {
      const na = sa.replace(/^0+/, '');
      const nb = sb.replace(/^0+/, '');
      if (na.length !== nb.length) return na.length > nb.length ? 1 : -1;
      if (na !== nb) return na > nb ? 1 : -1;
    } else if (sa !== sb) {
      return sa > sb ? 1 : -1;
    }
    i = ei;
    j = ej;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
}

// -1, 0 or 1. a release left out on either side is not compared (3.0.7 matches every release of 3.0.7)
function compare(x, y) {
  const a = typeof x === 'string' ? parse(x) : x;
  const b = typeof y === 'string' ? parse(y) : y;
  if (!a || !b) return !a && !b ? 0 : !a ? -1 : 1;
  if (a.epoch !== b.epoch) return a.epoch > b.epoch ? 1 : -1;
  const v = vercmp(a.version, b.version);
  if (v || a.release === null || b.release === null) return v;
  return vercmp(a.release, b.release);
}

const eq = (a, b) => valid(a) && valid(b) && compare(a, b) === 0;
// rpm has no pre-release marker a rule could rely on, a ~ is the closest thing to one
const isPrerelease = (text) => {
  const v = parse(text);
  return !!v && v.version.includes('~');
};

function side(text) {
  const m = /^(>=|<=|>|<|==|=)?\s*(\S+)$/.exec(String(text || '').trim());
  if (!m) return null;
  const v = parse(m[2]);
  if (!v) return null;
  switch (m[1] || '=') {
    case '>=': return (x) => compare(x, v) >= 0;
    case '>': return (x) => compare(x, v) > 0;
    case '<=': return (x) => compare(x, v) <= 0;
    case '<': return (x) => compare(x, v) < 0;
    default: return (x) => compare(x, v) === 0;
  }
}

function conjunction(text) {
  const bits = String(text || '').trim().replace(/(>=|<=|==|>|<|=)\s+/g, '$1').split(/\s+/).filter(Boolean);
  if (!bits.length) return null;
  const tests = bits.map(side);
  return tests.every(Boolean) ? (x) => tests.every((f) => f(x)) : null;
}

const alternatives = (range) => String(range || '').split('||').map((a) => a.trim()).filter(Boolean);

function validRange(range) {
  const r = String(range || '').trim();
  if (r.length > MAX) return false;
  if (!r) return true;
  const alts = alternatives(r);
  return alts.length > 0 && alts.every((a) => !!conjunction(a));
}

// prereleases: true lets a ~ version in (a deny rule), 'auto' (the default) only when the range names one
function satisfies(version, range, options = {}) {
  const v = parse(version);
  if (!v) return false;
  const r = String(range || '').trim();
  const pre = options.prereleases === undefined ? 'auto' : options.prereleases;
  if (isPrerelease(version) && pre !== true && !(pre === 'auto' && r.includes('~'))) return false;
  if (!r) return true;
  return alternatives(r).some((a) => {
    const f = conjunction(a);
    return !!f && f(v);
  });
}

function maxSatisfying(versions, range) {
  const ok = versions.filter((x) => valid(x) && satisfies(x, range, { prereleases: false }));
  return ok.length ? ok.sort((a, b) => compare(b, a))[0] : null;
}

// how the version reads with its epoch, which is how the advisory feeds write it: 1:3.0.7-24.el9
const withEpoch = (text) => {
  const v = parse(text);
  return v ? `${v.epoch}:${v.version}${v.release === null ? '' : `-${v.release}`}` : null;
};

module.exports = { MAX, parse, valid, vercmp, compare, eq, isPrerelease, validRange, satisfies, maxSatisfying, withEpoch };
