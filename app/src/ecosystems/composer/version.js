// Composer versions and constraints, the way Composer's own VersionParser reads them.
// Author: Tim Rice
//
// a version is up to four numbers, maybe a v in front, maybe a stability after a dash: 1.2, v3.0.1, 2.0.0-RC1,
// 1.0.0-beta.2, 1.0-patch1. versions compare on their numbers, then dev < alpha < beta < RC < stable < patch. branches
// (dev-main, 2.x-dev) are not releases and never valid here. a rule range takes composer.json's own constraints:
// ^1.2, ~1.2, 1.2.*, >=1.2 <2.0 (space or comma is and), a hyphen range 1.0 - 2.0, with || (or |) between alternatives

const MAX = 128;
const VERSION_RE = /^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:[-_.]?(stable|beta|b|RC|rc|alpha|a|patch|pl|p)(?:[.-]?(\d{1,9}))?)?$/;
const STABILITY = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, stable: 4, patch: 5, pl: 5, p: 5 };

function parse(text) {
  const s = String(text || '').trim();
  if (!s || s.length > MAX) return null;
  const m = VERSION_RE.exec(s);
  if (!m) return null;
  const tag = (m[5] || 'stable').toLowerCase();
  return { parts: [1, 2, 3, 4].map((i) => Number(m[i] || 0)), stability: STABILITY[tag], stabilityNumber: Number(m[6] || 0) };
}

const valid = (text) => !!parse(text);
const isPrerelease = (text) => {
  const v = parse(text);
  return !!v && v.stability < STABILITY.stable;
};

// -1, 0 or 1. not a version sorts first, so a list of rubbish still sorts
function compare(x, y) {
  const a = typeof x === 'string' ? parse(x) : x;
  const b = typeof y === 'string' ? parse(y) : y;
  if (!a || !b) return !a && !b ? 0 : !a ? -1 : 1;
  for (let i = 0; i < 4; i += 1) if (a.parts[i] !== b.parts[i]) return Math.sign(a.parts[i] - b.parts[i]);
  if (a.stability !== b.stability) return Math.sign(a.stability - b.stability);
  return Math.sign(a.stabilityNumber - b.stabilityNumber);
}

const eq = (a, b) => valid(a) && valid(b) && compare(a, b) === 0;

// the lowest version of a line: 2.0 as the floor of everything 2.0 and later, betas included
const floor = (parts) => ({ parts: [...parts, 0, 0, 0, 0].slice(0, 4), stability: STABILITY.dev, stabilityNumber: 0 });

// one comparison as a test, or null when it does not read
function side(text) {
  const t = String(text || '').trim().replace(/@(dev|alpha|beta|rc|stable)$/i, '');
  if (!t) return null;
  if (t === '*' || t === 'x') return () => true;
  const wild = /^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?\.[*x]$/.exec(t);
  if (wild) {
    const nums = [wild[1], wild[2], wild[3]].filter((n) => n !== undefined).map(Number);
    const up = [...nums];
    up[up.length - 1] += 1;
    return (v) => compare(v, floor(nums)) >= 0 && compare(v, floor(up)) < 0;
  }
  const caret = /^\^(.+)$/.exec(t);
  const tilde = /^~(.+)$/.exec(t);
  if (caret || tilde) {
    const v = parse((caret || tilde)[1]);
    const given = ((caret || tilde)[1].replace(/^v/, '').split(/[-_]/)[0].match(/\./g) || []).length + 1;
    if (!v) return null;
    const n = v.parts;
    let up;
    if (caret) {
      const lead = n[0] ? 0 : n[1] || given < 3 ? 1 : 2;
      up = n.slice(0, lead + 1);
    } else {
      up = n.slice(0, Math.max(1, given - 1));
    }
    up[up.length - 1] += 1;
    return (x) => compare(x, v) >= 0 && compare(x, floor(up)) < 0;
  }
  const op = /^(>=|<=|<>|!=|==|>|<|=)?\s*(.+)$/.exec(t);
  const v = parse(op[2]);
  if (!v) return null;
  switch (op[1] || '=') {
    case '>=': return (x) => compare(x, v) >= 0;
    case '>': return (x) => compare(x, v) > 0;
    // below 2.0 means below every 2.0, betas included, the way Composer reads it
    case '<': return (x) => compare(x, v.stability === STABILITY.stable ? floor(v.parts) : v) < 0;
    case '<=': return (x) => compare(x, v) <= 0;
    case '!=':
    case '<>': return (x) => compare(x, v) !== 0;
    default: return (x) => compare(x, v) === 0;
  }
}

// one alternative, the parts of which must all hold
function conjunction(text) {
  const t = String(text || '').trim();
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(t);
  if (hyphen) {
    const lo = parse(hyphen[1]);
    const hi = parse(hyphen[2]);
    if (!lo || !hi) return null;
    // 1.0 - 2.0 takes all of 2.0.x, a partial upper end is a whole line
    const partial = (hyphen[2].replace(/^v/, '').split(/[-_]/)[0].match(/\./g) || []).length < 2;
    const up = [...hi.parts.slice(0, (hyphen[2].replace(/^v/, '').match(/\./g) || []).length + 1)];
    if (partial) up[up.length - 1] += 1;
    return (x) => compare(x, lo) >= 0 && (partial ? compare(x, floor(up)) < 0 : compare(x, hi) <= 0);
  }
  const bits = t.replace(/\s*(>=|<=|<>|!=|==|>|<|=)\s*/g, ' $1').split(/\s*,\s*|\s+/).filter(Boolean);
  if (!bits.length) return null;
  const tests = bits.map(side);
  if (tests.some((f) => !f)) return null;
  return (x) => tests.every((f) => f(x));
}

function alternatives(range) {
  return String(range || '').split(/\s*\|\|?\s*/).map((a) => a.trim()).filter(Boolean);
}

function validRange(range) {
  const r = String(range || '').trim();
  if (r.length > MAX) return false;
  if (!r) return true;
  const alts = alternatives(r);
  return alts.length > 0 && alts.every((a) => !!conjunction(a));
}

// prereleases: true lets any pre-release in (a deny rule), 'auto' (the default) only when the range names one
function satisfies(version, range, options = {}) {
  const v = parse(version);
  if (!v) return false;
  const r = String(range || '').trim();
  const pre = options.prereleases === undefined ? 'auto' : options.prereleases;
  if (v.stability < STABILITY.stable && pre !== true && !(pre === 'auto' && /\d[-_.]?(alpha|beta|rc|a|b)\d*|@(dev|alpha|beta|rc)/i.test(r))) return false;
  if (!r) return true;
  return alternatives(r).some((a) => {
    const f = conjunction(a);
    return !!f && f(v);
  });
}

function maxSatisfying(versions, range) {
  const ok = versions.filter((v) => valid(v) && satisfies(v, range, { prereleases: false }));
  return ok.length ? ok.sort((a, b) => compare(b, a))[0] : null;
}

module.exports = { MAX, parse, valid, isPrerelease, compare, eq, validRange, satisfies, maxSatisfying };
