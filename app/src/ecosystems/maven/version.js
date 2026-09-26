// Maven versions and ranges, ordered the way Maven's own ComparableVersion orders them.
// Author: Tim Rice
//
// 1.0 < 1.0.1, 1.0-alpha-1 < 1.0-beta < 1.0-rc1 < 1.0-SNAPSHOT < 1.0 = 1.0.0 = 1.0-final < 1.0-sp1, a qualifier nobody
// knows sorts after all of those. ranges are Maven's brackets ([1.0,2.0), (,1.5]), plus 1.2.* and comparators for
// people who think in those, and || between alternatives. a bare version in a rule is that exact version (Maven itself
// reads a bare version as a soft "prefer this", which is no use in a rule)

const MAX = 128;
const QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
const ALIASES = { ga: '', final: '', release: '', cr: 'rc' };
const RELEASE = String(QUALIFIERS.indexOf(''));
// the characters a Maven version is made of, nothing that could mean a path
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/;

const INT = 0;
const STR = 1;
const LIST = 2;

function qualifierKey(q) {
  const i = QUALIFIERS.indexOf(q);
  return i === -1 ? `${QUALIFIERS.length}-${q}` : String(i);
}

function strItem(value, followedByDigit) {
  let v = value;
  if (followedByDigit && v.length === 1) v = { a: 'alpha', b: 'beta', m: 'milestone' }[v] || v;
  if (Object.prototype.hasOwnProperty.call(ALIASES, v)) v = ALIASES[v];
  return { type: STR, value: v };
}

const intItem = (digits) => ({ type: INT, value: BigInt(digits.replace(/^0+(?=\d)/, '') || '0') });

// the "null" items Maven drops from the end of a list: 0, "", and an empty list
function isNull(item) {
  if (item.type === INT) return item.value === 0n;
  if (item.type === STR) return item.value === '';
  return item.items.length === 0;
}

function normalizeList(list) {
  for (let i = list.items.length - 1; i >= 0; i -= 1) {
    const it = list.items[i];
    if (isNull(it)) list.items.splice(i, 1);
    else if (it.type !== LIST) break;
  }
  return list;
}

// Maven's own parse: . separates, - starts a sub list, and a switch between digits and letters is a separator too
function parseItems(text) {
  const v = String(text).toLowerCase();
  const root = { type: LIST, items: [] };
  let list = root;
  const stack = [root];
  let start = 0;
  let digit = false;
  for (let i = 0; i < v.length; i += 1) {
    const c = v[i];
    if (c === '.') {
      list.items.push(i === start ? intItem('0') : digit ? intItem(v.slice(start, i)) : strItem(v.slice(start, i), false));
      start = i + 1;
    } else if (c === '-') {
      if (i === start) list.items.push(intItem('0'));
      else list.items.push(digit ? intItem(v.slice(start, i)) : strItem(v.slice(start, i), false));
      start = i + 1;
      const sub = { type: LIST, items: [] };
      list.items.push(sub);
      list = sub;
      stack.push(sub);
    } else if (c >= '0' && c <= '9') {
      if (!digit && i > start) {
        list.items.push(strItem(v.slice(start, i), true));
        start = i;
        const sub = { type: LIST, items: [] };
        list.items.push(sub);
        list = sub;
        stack.push(sub);
      }
      digit = true;
    } else {
      if (digit && i > start) {
        list.items.push(intItem(v.slice(start, i)));
        start = i;
        const sub = { type: LIST, items: [] };
        list.items.push(sub);
        list = sub;
        stack.push(sub);
      }
      digit = false;
    }
  }
  if (v.length > start) list.items.push(digit ? intItem(v.slice(start)) : strItem(v.slice(start), false));
  while (stack.length) normalizeList(stack.pop());
  return root;
}

function compareItem(a, b) {
  if (!b) {
    if (a.type === INT) return a.value === 0n ? 0 : 1;
    if (a.type === STR) return qualifierKey(a.value) < RELEASE ? -1 : qualifierKey(a.value) > RELEASE ? 1 : 0;
    if (!a.items.length) return 0;
    return compareItem(a.items[0], null);
  }
  if (a.type === INT) {
    if (b.type !== INT) return 1;
    return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
  }
  if (a.type === STR) {
    if (b.type === INT) return -1;
    if (b.type === LIST) return -1;
    const x = qualifierKey(a.value);
    const y = qualifierKey(b.value);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  if (b.type === INT) return -1;
  if (b.type === STR) return 1;
  const n = Math.max(a.items.length, b.items.length);
  for (let i = 0; i < n; i += 1) {
    const l = a.items[i];
    const r = b.items[i];
    const c = !l ? (r ? -compareItem(r, null) : 0) : compareItem(l, r || null);
    if (c) return c;
  }
  return 0;
}

const valid = (text) => {
  const s = String(text || '').trim();
  return !!s && s.length <= MAX && VERSION_RE.test(s) && !s.includes('..');
};

function compare(x, y) {
  if (!valid(x) || !valid(y)) return !valid(x) && !valid(y) ? 0 : !valid(x) ? -1 : 1;
  return compareItem(parseItems(x), parseItems(y));
}

const eq = (a, b) => valid(a) && valid(b) && compare(a, b) === 0;

// a SNAPSHOT is a build in progress, the rest of the pre-releases say what they are in their qualifier
const isSnapshot = (v) => /-SNAPSHOT$/i.test(String(v || ''));
function isPrerelease(v) {
  if (!valid(v)) return false;
  return isSnapshot(v) || /(^|[.-])(alpha|beta|milestone|rc|cr|m|a|b)[.-]?\d*($|[.-])/i.test(String(v)) || /\d(alpha|beta|rc|m)\d/i.test(String(v));
}

// one alternative of a range as a test, or null when it is not one this reads
function side(text) {
  const t = String(text).trim();
  if (!t || t === '*') return () => true;
  const br = /^([[(])\s*([^,\])]*?)\s*(?:,\s*([^\])]*?)\s*)?([\])])$/.exec(t);
  if (br) {
    const [, open, lo, hi, close] = br;
    if (hi === undefined) {
      if (open !== '[' || close !== ']' || !valid(lo)) return null;
      return (v) => compare(v, lo) === 0;
    }
    if ((lo && !valid(lo)) || (hi && !valid(hi)) || (!lo && !hi)) return null;
    return (v) => (!lo || (open === '[' ? compare(v, lo) >= 0 : compare(v, lo) > 0))
      && (!hi || (close === ']' ? compare(v, hi) <= 0 : compare(v, hi) < 0));
  }
  const star = /^(\d{1,9}(?:\.\d{1,9}){0,3})\.\*$/.exec(t);
  if (star) {
    const lead = `${star[1]}.`;
    return (v) => String(v).startsWith(lead) && !isPrerelease(v);
  }
  const tests = [];
  for (const word of t.split(/\s+/)) {
    const m = /^(>=|<=|>|<|=)?(.+)$/.exec(word);
    if (!m || !valid(m[2])) return null;
    const op = m[1] || '=';
    const bound = m[2];
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
  return r.split('||').map((x) => x.trim()).every((a) => a && side(a));
}

// prereleases: true lets any pre-release in (a deny rule), 'auto' (the default) only when the range names one
function satisfies(version, range, options = {}) {
  if (!valid(version)) return false;
  const r = String(range || '').trim();
  const pre = options.prereleases === undefined ? 'auto' : options.prereleases;
  if (isPrerelease(version) && pre !== true && !(pre === 'auto' && r.split('||').some((a) => isPrerelease(a.replace(/[[\]()\s]/g, '').split(',')[0] || '') || isPrerelease(a.replace(/[[\]()\s]/g, '').split(',')[1] || '')))) return false;
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

module.exports = { MAX, valid, compare, eq, isSnapshot, isPrerelease, validRange, satisfies, maxSatisfying };
