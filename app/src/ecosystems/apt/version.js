// Debian package versions: [epoch:]upstream[-revision], compared the way dpkg does it, and rule ranges over them.
// Author: Tim Rice
//
// 1:3.0.11-1~deb12u2 is epoch 1, upstream 3.0.11, revision 1~deb12u2. epochs compare as numbers, then the upstream
// part, then the revision, each with dpkg's own order: runs of digits as numbers, everything else by character with
// letters before other characters and ~ before anything, even the end (1.0~rc1 < 1.0). a range is comparators with a
// space meaning and, || between alternatives. a version without a revision in a range means every revision of it

const MAX = 128;
const RE = /^(?:(\d{1,9}):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$/;

function parse(text) {
  const s = String(text || '').trim();
  if (!s || s.length > MAX) return null;
  const m = RE.exec(s);
  if (!m) return null;
  // a colon in the upstream part only when there is an epoch, a dash only when there is a revision, as dpkg says
  if (!m[1] && m[2].includes(':')) return null;
  return { epoch: Number(m[1] || 0), upstream: m[2], revision: m[3] === undefined ? null : m[3] };
}

const valid = (text) => !!parse(text);

function order(c) {
  if (c === undefined) return 0;
  if (c === '~') return -1;
  if (/[A-Za-z]/.test(c)) return c.charCodeAt(0);
  return c.charCodeAt(0) + 256;
}

// dpkg's verrevcmp
function verrevcmp(a, b) {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let first = 0;
    while ((i < a.length && !/\d/.test(a[i])) || (j < b.length && !/\d/.test(b[j]))) {
      const ac = i < a.length && !/\d/.test(a[i]) ? order(a[i]) : 0;
      const bc = j < b.length && !/\d/.test(b[j]) ? order(b[j]) : 0;
      if (ac !== bc) return ac < bc ? -1 : 1;
      i += 1;
      j += 1;
    }
    while (a[i] === '0') i += 1;
    while (b[j] === '0') j += 1;
    while (i < a.length && /\d/.test(a[i]) && j < b.length && /\d/.test(b[j])) {
      if (!first) first = a.charCodeAt(i) - b.charCodeAt(j);
      i += 1;
      j += 1;
    }
    if (i < a.length && /\d/.test(a[i])) return 1;
    if (j < b.length && /\d/.test(b[j])) return -1;
    if (first) return first < 0 ? -1 : 1;
  }
  return 0;
}

// -1, 0 or 1. a revision left out on either side is not compared (3.0.11 matches every revision of 3.0.11)
function compare(x, y) {
  const a = typeof x === 'string' ? parse(x) : x;
  const b = typeof y === 'string' ? parse(y) : y;
  if (!a || !b) return !a && !b ? 0 : !a ? -1 : 1;
  if (a.epoch !== b.epoch) return a.epoch > b.epoch ? 1 : -1;
  const u = verrevcmp(a.upstream, b.upstream);
  if (u || a.revision === null || b.revision === null) return u;
  return verrevcmp(a.revision, b.revision);
}

const eq = (a, b) => valid(a) && valid(b) && compare(a, b) === 0;
const isPrerelease = (text) => {
  const v = parse(text);
  return !!v && v.upstream.includes('~');
};

function side(text) {
  const m = /^(>=|<=|>>|<<|>|<|==|=)?\s*(\S+)$/.exec(String(text || '').trim());
  if (!m) return null;
  const v = parse(m[2]);
  if (!v) return null;
  switch (m[1] || '=') {
    case '>=': return (x) => compare(x, v) >= 0;
    case '>>':
    case '>': return (x) => compare(x, v) > 0;
    case '<=': return (x) => compare(x, v) <= 0;
    case '<<':
    case '<': return (x) => compare(x, v) < 0;
    default: return (x) => compare(x, v) === 0;
  }
}

function conjunction(text) {
  const bits = String(text || '').trim().replace(/(>=|<=|>>|<<|==|>|<|=)\s+/g, '$1').split(/\s+/).filter(Boolean);
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

module.exports = { MAX, parse, valid, verrevcmp, compare, eq, isPrerelease, validRange, satisfies, maxSatisfying };
