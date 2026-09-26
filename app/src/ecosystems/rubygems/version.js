// Ruby gem versions and requirements, the way Gem::Version and Gem::Requirement read them.
// Author: Tim Rice
//
// a version is dotted segments, numbers or letters. any letter makes it a pre-release (1.0.0.rc1, 2.0.0.beta). a rule
// range takes gem requirements (~> 4.0, >= 1.2, < 2 with a comma meaning both), 1.2.* for people who think that way,
// and || between alternatives. a bare version is that exact version, as for every other type

const MAX = 128;
const VERSION_RE = /^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

const valid = (v) => {
  const s = String(v || '').trim();
  return !!s && s.length <= MAX && VERSION_RE.test(s);
};

// "1.0-rc1" is written 1.0.pre.rc1 inside Gem::Version, and the segments are the runs of digits and of letters
function segments(v) {
  return String(v).trim().replace(/-/g, '.pre.').match(/[0-9]+|[a-z]+/gi).map((s) => (/^\d+$/.test(s) ? BigInt(s) : s));
}

const isPrerelease = (v) => valid(v) && /[a-zA-Z]/.test(String(v));

function compare(a, b) {
  if (!valid(a) || !valid(b)) return !valid(a) && !valid(b) ? 0 : !valid(a) ? -1 : 1;
  const l = segments(a);
  const r = segments(b);
  for (let i = 0; i < Math.max(l.length, r.length); i += 1) {
    const x = i < l.length ? l[i] : 0n;
    const y = i < r.length ? r[i] : 0n;
    if (x === y) continue;
    if (typeof x === 'string' && typeof y !== 'string') return -1;
    if (typeof x !== 'string' && typeof y === 'string') return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

// what ~> 2.3.4 stops short of: 2.4. letters dropped, then the last number, then the new last one up by one
function bump(v) {
  const s = segments(v);
  while (s.some((x) => typeof x === 'string')) s.pop();
  if (s.length > 1) s.pop();
  s[s.length - 1] += 1n;
  return s.join('.');
}

// one requirement like ">= 1.2" or "~> 4.0" as a test, or null when it does not read
function requirement(text) {
  const m = /^(=|!=|>=|<=|>|<|~>)?\s*(\S+)$/.exec(String(text).trim());
  if (!m || !valid(m[2])) return null;
  const op = m[1] || '=';
  const b = m[2];
  if (op === '~>') {
    const top = bump(b);
    return (v) => compare(v, b) >= 0 && compare(v, top) < 0;
  }
  return (v) => {
    const c = compare(v, b);
    return { '=': c === 0, '!=': c !== 0, '>=': c >= 0, '<=': c <= 0, '>': c > 0, '<': c < 0 }[op];
  };
}

// one alternative: requirements joined by commas (all must hold), or 1.2.*, or * for anything
function side(text) {
  const t = String(text).trim();
  if (!t || t === '*') return () => true;
  const star = /^(\d{1,9}(?:\.\d{1,9}){0,3})\.\*$/.exec(t);
  if (star) return (v) => String(v).startsWith(`${star[1]}.`) && !isPrerelease(v);
  const tests = t.split(',').map((p) => requirement(p));
  if (tests.some((f) => !f)) return null;
  return (v) => tests.every((f) => f(v));
}

function validRange(range) {
  const r = String(range || '').trim();
  if (r.length > MAX) return false;
  if (!r) return true;
  return r.split('||').map((x) => x.trim()).every((a) => a && side(a));
}

// prereleases: true lets any pre-release in (a deny rule), 'auto' (the default) only when the range names one
function satisfies(version, range, options = {}) {
  if (!valid(version)) return false;
  const r = String(range || '').trim();
  const pre = options.prereleases === undefined ? 'auto' : options.prereleases;
  if (isPrerelease(version) && pre !== true && !(pre === 'auto' && /\d\.?[a-zA-Z]/.test(r))) return false;
  if (!r) return true;
  return r.split('||').map((x) => x.trim()).filter(Boolean).some((a) => {
    const f = side(a);
    return !!f && f(version);
  });
}

function maxSatisfying(versions, range) {
  const ok = versions.filter((v) => valid(v) && satisfies(v, range, { prereleases: false }));
  return ok.length ? ok.sort((a, b) => compare(b, a))[0] : null;
}

module.exports = { MAX, valid, compare, isPrerelease, bump, validRange, satisfies, maxSatisfying };
