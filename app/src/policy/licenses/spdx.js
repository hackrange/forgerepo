// SPDX license expressions. parse, tidy up, judge against the lists
// Author: Tim Rice
// OR = either will do, AND = needs both. can't read it? unknown. we don't guess

const MAX_INPUT = 512;
const MAX_TEXT = 4096;

//ids that actually show up in packages. others still parse, just flagged
const KNOWN = [
  '0BSD', 'AFL-2.1', 'AFL-3.0', 'AGPL-1.0-only', 'AGPL-1.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-1.1',
  'Apache-2.0', 'APSL-2.0', 'Artistic-1.0', 'Artistic-2.0', 'BlueOak-1.0.0', 'BSD-1-Clause', 'BSD-2-Clause',
  'BSD-2-Clause-Patent', 'BSD-3-Clause', 'BSD-3-Clause-Clear', 'BSD-4-Clause', 'BSL-1.0', 'BUSL-1.1', 'CAL-1.0',
  'CC-BY-3.0', 'CC-BY-4.0', 'CC-BY-SA-3.0', 'CC-BY-SA-4.0', 'CC-BY-NC-4.0', 'CC-BY-NC-SA-4.0', 'CC-BY-ND-4.0', 'CC0-1.0',
  'CDDL-1.0', 'CDDL-1.1', 'CECILL-2.1', 'CPAL-1.0', 'CPL-1.0', 'ECL-2.0', 'EFL-2.0', 'Elastic-2.0', 'EPL-1.0', 'EPL-2.0',
  'EUPL-1.1', 'EUPL-1.2', 'GFDL-1.3-only', 'GFDL-1.3-or-later', 'GPL-1.0-only', 'GPL-1.0-or-later', 'GPL-2.0-only',
  'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'HPND', 'ISC', 'JSON', 'LGPL-2.0-only', 'LGPL-2.0-or-later',
  'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'LPL-1.02', 'MIT', 'MIT-0', 'MIT-CMU',
  'MPL-1.0', 'MPL-1.1', 'MPL-2.0', 'MPL-2.0-no-copyleft-exception', 'MS-PL', 'MS-RL', 'MulanPSL-2.0', 'NCSA', 'ODbL-1.0',
  'OFL-1.1', 'OpenSSL', 'OSL-3.0', 'PHP-3.01', 'PostgreSQL', 'PSF-2.0', 'Python-2.0', 'Ruby', 'SSPL-1.0', 'UPL-1.0',
  'Unicode-3.0', 'Unicode-DFS-2016', 'Unlicense', 'Vim', 'W3C', 'WTFPL', 'X11', 'Zlib', 'ZPL-2.1'
];
const EXCEPTIONS = [
  'Classpath-exception-2.0', 'LLVM-exception', 'GCC-exception-3.1', 'Autoconf-exception-3.0', 'Bison-exception-2.2',
  'Font-exception-2.0', 'OpenJDK-assembly-exception-1.0', 'Qt-LGPL-exception-1.1', 'Swift-exception', 'u-boot-exception-2.0'
];
const CANON = new Map(KNOWN.map((id) => [id.toLowerCase(), id]));
const CANON_EXC = new Map(EXCEPTIONS.map((id) => [id.toLowerCase(), id]));

// old spellings SPDX has since retired
const DEPRECATED = {
  'gpl-1.0': 'GPL-1.0-only', 'gpl-1.0+': 'GPL-1.0-or-later', 'gpl-2.0': 'GPL-2.0-only', 'gpl-2.0+': 'GPL-2.0-or-later',
  'gpl-3.0': 'GPL-3.0-only', 'gpl-3.0+': 'GPL-3.0-or-later', 'lgpl-2.0': 'LGPL-2.0-only', 'lgpl-2.0+': 'LGPL-2.0-or-later',
  'lgpl-2.1': 'LGPL-2.1-only', 'lgpl-2.1+': 'LGPL-2.1-or-later', 'lgpl-3.0': 'LGPL-3.0-only', 'lgpl-3.0+': 'LGPL-3.0-or-later',
  'agpl-1.0': 'AGPL-1.0-only', 'agpl-3.0': 'AGPL-3.0-only', 'agpl-3.0+': 'AGPL-3.0-or-later', 'gfdl-1.3': 'GFDL-1.3-only'
};

// what people type instead of an id, squeezed
const ALIASES = {
  'mit': 'MIT', 'mit license': 'MIT', 'the mit license': 'MIT', 'mit x11': 'MIT', 'expat': 'MIT',
  'apache 2': 'Apache-2.0', 'apache 2 0': 'Apache-2.0', 'apache2': 'Apache-2.0', 'apache v2': 'Apache-2.0',
  'apache license 2 0': 'Apache-2.0', 'apache license version 2 0': 'Apache-2.0', 'apache software license': 'Apache-2.0',
  'apache software license 2 0': 'Apache-2.0', 'asl 2 0': 'Apache-2.0', 'apache license v2 0': 'Apache-2.0',
  'bsd 3 clause': 'BSD-3-Clause', 'bsd3': 'BSD-3-Clause', 'new bsd': 'BSD-3-Clause', 'new bsd license': 'BSD-3-Clause',
  'modified bsd': 'BSD-3-Clause', 'revised bsd': 'BSD-3-Clause', '3 clause bsd': 'BSD-3-Clause', 'bsd 3': 'BSD-3-Clause',
  'bsd 2 clause': 'BSD-2-Clause', 'simplified bsd': 'BSD-2-Clause', 'freebsd': 'BSD-2-Clause', '2 clause bsd': 'BSD-2-Clause',
  'isc license': 'ISC', 'mozilla public license 2 0': 'MPL-2.0', 'mpl 2 0': 'MPL-2.0', 'mpl2': 'MPL-2.0',
  'gplv2': 'GPL-2.0-only', 'gpl v2': 'GPL-2.0-only', 'gplv2+': 'GPL-2.0-or-later', 'gplv3': 'GPL-3.0-only', 'gpl v3': 'GPL-3.0-only',
  'gplv3+': 'GPL-3.0-or-later', 'lgplv2': 'LGPL-2.0-only', 'lgplv2 1': 'LGPL-2.1-only', 'lgplv3': 'LGPL-3.0-only',
  'lgplv3+': 'LGPL-3.0-or-later', 'agplv3': 'AGPL-3.0-only', 'psf': 'PSF-2.0', 'psf license': 'PSF-2.0',
  'python software foundation license': 'PSF-2.0', 'zlib license': 'Zlib', 'the unlicense': 'Unlicense',
  'cc0': 'CC0-1.0', 'cc0 1 0': 'CC0-1.0', 'wtfpl': 'WTFPL', 'artistic 2 0': 'Artistic-2.0', 'epl 2 0': 'EPL-2.0',
  'eclipse public license 2 0': 'EPL-2.0', 'public domain': 'LicenseRef-Public-Domain', 'bsd': 'LicenseRef-BSD',
  'bsd license': 'LicenseRef-BSD', 'gpl': 'LicenseRef-GPL', 'lgpl': 'LicenseRef-LGPL', 'proprietary': 'LicenseRef-Proprietary',
  'commercial': 'LicenseRef-Proprietary', 'dual license': null,
  // the way Maven poms write them
  'the apache software license version 2 0': 'Apache-2.0', 'the apache license version 2 0': 'Apache-2.0', 'apache license 2': 'Apache-2.0',
  'apache 2 0 license': 'Apache-2.0', 'the apache software license 2 0': 'Apache-2.0', 'eclipse public license 1 0': 'EPL-1.0',
  'eclipse public license v1 0': 'EPL-1.0', 'eclipse public license v 1 0': 'EPL-1.0', 'eclipse public license v2 0': 'EPL-2.0',
  'eclipse public license v 2 0': 'EPL-2.0', 'eclipse distribution license v 1 0': 'BSD-3-Clause', 'edl 1 0': 'BSD-3-Clause',
  'mozilla public license version 2 0': 'MPL-2.0', 'bouncy castle license': 'MIT', 'the bsd license': 'BSD-3-Clause',
  'bsd 3 clause license': 'BSD-3-Clause', 'the 3 clause bsd license': 'BSD-3-Clause', 'bsd 2 clause license': 'BSD-2-Clause',
  'gnu lesser general public license': 'LicenseRef-LGPL', 'gnu general public license version 2 with the classpath exception': 'GPL-2.0-only WITH Classpath-exception-2.0',
  'gpl2 w cpe': 'GPL-2.0-only WITH Classpath-exception-2.0', 'cddl gplv2 with classpath exception': 'CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0',
  'common development and distribution license cddl v1 0': 'CDDL-1.0', 'go license': 'BSD-3-Clause', 'public domain cc0 1 0': 'CC0-1.0'
};

// trove classifiers, minus the License :: OSI Approved :: bit
const CLASSIFIERS = {
  'mit license': 'MIT', 'mit no attribution license (mit-0)': 'MIT-0', 'apache software license': 'Apache-2.0',
  'bsd license': 'LicenseRef-BSD', 'isc license (iscl)': 'ISC', 'mozilla public license 2.0 (mpl 2.0)': 'MPL-2.0',
  'mozilla public license 1.1 (mpl 1.1)': 'MPL-1.1', 'gnu general public license v2 (gplv2)': 'GPL-2.0-only',
  'gnu general public license v2 or later (gplv2+)': 'GPL-2.0-or-later', 'gnu general public license v3 (gplv3)': 'GPL-3.0-only',
  'gnu general public license v3 or later (gplv3+)': 'GPL-3.0-or-later', 'gnu general public license (gpl)': 'LicenseRef-GPL',
  'gnu lesser general public license v2 (lgplv2)': 'LGPL-2.0-only', 'gnu lesser general public license v2 or later (lgplv2+)': 'LGPL-2.0-or-later',
  'gnu lesser general public license v3 (lgplv3)': 'LGPL-3.0-only', 'gnu lesser general public license v3 or later (lgplv3+)': 'LGPL-3.0-or-later',
  'gnu library or lesser general public license (lgpl)': 'LicenseRef-LGPL', 'gnu affero general public license v3': 'AGPL-3.0-only',
  'gnu affero general public license v3 or later (agplv3+)': 'AGPL-3.0-or-later', 'python software foundation license': 'PSF-2.0',
  'the unlicense (unlicense)': 'Unlicense', 'zlib/libpng license': 'Zlib', 'eclipse public license 2.0 (epl-2.0)': 'EPL-2.0',
  'eclipse public license 1.0 (epl-1.0)': 'EPL-1.0', 'artistic license': 'Artistic-2.0', 'academic free license (afl)': 'AFL-3.0',
  'european union public license 1.2 (eupl 1.2)': 'EUPL-1.2', 'universal permissive license (upl)': 'UPL-1.0',
  'boost software license 1.0 (bsl-1.0)': 'BSL-1.0', 'public domain': 'LicenseRef-Public-Domain',
  'other/proprietary license': 'LicenseRef-Proprietary', 'cc0 1.0 universal (cc0 1.0) public domain dedication': 'CC0-1.0',
  'freely distributable': 'LicenseRef-Freely-Distributable', 'free for non-commercial use': 'LicenseRef-Non-Commercial'
};

// ---------------------------------------------------------------- parsing

function tokens(text) {
  const out = [];
  const re = /\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.+:-]*)\s*/y;
  let pos = 0;
  while (pos < text.length) {
    re.lastIndex = pos;
    const m = re.exec(text);
    if (!m) return null;
    out.push(m[1]);
    pos = re.lastIndex;
  }
  return out;
}

function licenseId(raw) {
  const lower = raw.toLowerCase();
  if (DEPRECATED[lower]) return { id: DEPRECATED[lower], known: true };
  if (lower.startsWith('licenseref-') || lower.startsWith('documentref-')) return { id: raw, known: true, ref: true };
  const plus = lower.endsWith('+');
  const base = plus ? lower.slice(0, -1) : lower;
  if (CANON.has(base)) return { id: CANON.get(base) + (plus ? '+' : ''), known: true };
  return { id: raw, known: false };
}

// OR binds loosest, then AND, then WITH. returns { tree } or { error }
function parse(input) {
  const text = String(input === null || input === undefined ? '' : input).trim();
  if (!text) return { error: 'empty' };
  if (text.length > MAX_INPUT) return { error: 'too long to be a license expression' };
  const t = tokens(text);
  if (!t || !t.length) return { error: 'not an SPDX expression' };
  let i = 0;
  const peek = () => t[i];
  const isOp = (tok, op) => typeof tok === 'string' && tok.toUpperCase() === op;

  function atom() {
    const tok = t[i];
    if (tok === undefined) throw new Error('the expression ends early');
    if (tok === '(') {
      i += 1;
      const inner = or();
      if (t[i] !== ')') throw new Error('a bracket is never closed');
      i += 1;
      return inner;
    }
    if (tok === ')' || isOp(tok, 'AND') || isOp(tok, 'OR') || isOp(tok, 'WITH')) throw new Error(`unexpected "${tok}"`);
    i += 1;
    const lic = licenseId(tok);
    const node = { type: 'license', id: lic.id, known: lic.known };
    if (isOp(peek(), 'WITH')) {
      i += 1;
      const exc = t[i];
      if (!exc || exc === '(' || exc === ')') throw new Error('WITH needs an exception after it');
      i += 1;
      node.exception = CANON_EXC.get(exc.toLowerCase()) || exc;
    }
    return node;
  }
  function and() {
    const items = [atom()];
    while (isOp(peek(), 'AND')) {
      i += 1;
      items.push(atom());
    }
    return items.length === 1 ? items[0] : { type: 'and', items };
  }
  function or() {
    const items = [and()];
    while (isOp(peek(), 'OR')) {
      i += 1;
      items.push(and());
    }
    return items.length === 1 ? items[0] : { type: 'or', items };
  }

  try {
    const tree = or();
    if (i !== t.length) return { error: `unexpected "${t[i]}"` };
    return { tree };
  } catch (err) {
    return { error: err.message };
  }
}

function format(tree, parent) {
  if (!tree) return null;
  if (tree.type === 'license') return tree.exception ? `${tree.id} WITH ${tree.exception}` : tree.id;
  const joined = tree.items.map((x) => format(x, tree.type)).join(tree.type === 'and' ? ' AND ' : ' OR ');
  // AND inside OR needs no brackets, OR inside AND does
  return parent === 'and' && tree.type === 'or' ? `(${joined})` : joined;
}

function leaves(tree, out = []) {
  if (!tree) return out;
  if (tree.type === 'license') out.push(tree);
  else tree.items.forEach((x) => leaves(x, out));
  return out;
}

// plenty of packages spell license with a c in the middle, it is the same license
const squeeze = (s) => String(s).toLowerCase().replace(/[^a-z0-9+]+/g, ' ').replace(/\blicen[cs]e/g, 'license').trim();

// ---------------------------------------------------------------- what packages actually say

function result(tree, source, raw, note) {
  return { tree, expression: format(tree), source, raw: raw === undefined ? null : raw, note: note || null };
}

function fromText(raw, source = 'license') {
  const text = String(raw === null || raw === undefined ? '' : raw).trim();
  if (!text) return result(null, 'none', null, 'no license given');
  if (text.length > MAX_TEXT) return result(null, source, text.slice(0, 200), 'license text with no identifier');
  const upper = text.toUpperCase();
  // npm's own words for "no license granted"
  if (upper === 'UNLICENSED') return result({ type: 'license', id: 'LicenseRef-UNLICENSED', known: true }, source, text);
  if (/^SEE LICEN[CS]E IN\b/.test(upper)) return result(null, source, text, 'points at a license file, not an identifier');
  const parsed = parse(text);
  if (parsed.tree && leaves(parsed.tree).every((l) => l.known)) return result(parsed.tree, source, text);
  const alias = ALIASES[squeeze(text)];
  if (alias) return result(parse(alias).tree, source, text, 'read from a license name');
  if (parsed.tree) return result(parsed.tree, source, text, 'contains an identifier SPDX does not list');
  return result(null, source, text, 'not a license this box can read');
}

// npm: "MIT", { type: "MIT" }, or the old licenses array
function fromNpm(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  const single = typeof m.license === 'string' ? m.license : m.license && typeof m.license.type === 'string' ? m.license.type : null;
  if (single) return fromText(single, 'license');
  if (Array.isArray(m.licenses) && m.licenses.length) {
    const parts = m.licenses.map((l) => (typeof l === 'string' ? l : l && l.type)).filter((x) => typeof x === 'string' && x.trim());
    if (parts.length) {
      const read = parts.map((p) => fromText(p, 'licenses'));
      if (read.every((r) => r.tree)) {
        const tree = read.length === 1 ? read[0].tree : { type: 'or', items: read.map((r) => r.tree) };
        return result(tree, 'licenses', parts.join(', '), read.length > 1 ? 'several licenses listed, read as a choice' : null);
      }
      return result(null, 'licenses', parts.join(', '), 'not a license this box can read');
    }
  }
  return result(null, 'none', null, 'no license given');
}

function classifier(raw) {
  const key = String(raw).replace(/^License ::\s*/i, '').replace(/^OSI Approved ::\s*/i, '').trim().toLowerCase();
  if (key === 'osi approved') return null;
  return CLASSIFIERS[key] || null;
}

function fromPypi(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  if (m.licenseExpression) return fromText(m.licenseExpression, 'license-expression');
  if (m.license && !m.license.isText) {
    const r = fromText(m.license.value, 'license');
    if (r.tree) return r;
  }
  const mapped = (Array.isArray(m.licenseClassifiers) ? m.licenseClassifiers : []).map(classifier).filter(Boolean);
  if (mapped.length) {
    const unique = [...new Set(mapped)].map((id) => parse(id).tree);
    const tree = unique.length === 1 ? unique[0] : { type: 'or', items: unique };
    return result(tree, 'classifier', m.licenseClassifiers.join('; '), unique.length > 1 ? 'several classifiers listed, read as a choice' : null);
  }
  if (m.license && m.license.isText) return result(null, 'license', m.license.value, 'license text with no identifier');
  if (m.license) return fromText(m.license.value, 'license');
  return result(null, 'none', null, 'no license given');
}

// ---------------------------------------------------------------- judging

const RANK = { allowed: 0, review: 1, blocked: 2 };
const NAMES = ['allowed', 'review', 'blocked'];

// * matches anything. no regex, so a pile of stars can't backtrack forever
function glob(pattern, text) {
  const p = pattern.toLowerCase();
  const t = text.toLowerCase();
  let i = 0;
  let j = 0;
  let star = -1;
  let mark = 0;
  while (j < t.length) {
    if (i < p.length && p[i] === '*') {
      star = i;
      i += 1;
      mark = j;
    } else if (i < p.length && p[i] === t[j]) {
      i += 1;
      j += 1;
    } else if (star !== -1) {
      i = star + 1;
      mark += 1;
      j = mark;
    } else {
      return false;
    }
  }
  while (i < p.length && p[i] === '*') i += 1;
  return i === p.length;
}

// one per line (or comma), # notes
function compileList(text) {
  return String(text || '')
    .split(/[\n,]+/)
    .map((s) => s.replace(/#.*$/, '').trim())
    .filter(Boolean)
    .slice(0, 500)
    .map((entry) => ({ entry, test: (id) => glob(entry, id) }));
}

function compile({ allowed, review, blocked, unlisted = 'review', unknown = 'review' }) {
  return {
    allowed: compileList(allowed),
    review: compileList(review),
    blocked: compileList(blocked),
    unlisted: RANK[unlisted] === undefined ? 'review' : unlisted,
    unknown: RANK[unknown] === undefined ? 'review' : unknown
  };
}

// strictest list wins. entries naming an exception only match ids with one
function classifyId(text, lists) {
  const withExc = text.includes(' WITH ');
  for (const name of ['blocked', 'review', 'allowed']) {
    const hit = lists[name].find((p) => p.entry.includes(' WITH ') === withExc && p.test(text));
    if (hit) return { verdict: name, matched: hit.entry };
  }
  return null;
}

function judgeTree(tree, lists) {
  if (tree.type === 'license') {
    const full = tree.exception ? `${tree.id} WITH ${tree.exception}` : tree.id;
    // an entry naming the exception wins, else the bare license decides
    const hit = (tree.exception && classifyId(full, lists)) || classifyId(tree.id, lists);
    if (hit) return { verdict: hit.verdict, why: [`${full} is ${hit.verdict} (${hit.matched})`] };
    return { verdict: lists.unlisted, why: [`${full} is on no list, so ${lists.unlisted}`] };
  }
  const parts = tree.items.map((x) => judgeTree(x, lists));
  const pick = tree.type === 'or'
    ? parts.reduce((a, b) => (RANK[b.verdict] < RANK[a.verdict] ? b : a))
    : parts.reduce((a, b) => (RANK[b.verdict] > RANK[a.verdict] ? b : a));
  if (tree.type === 'or') return { verdict: pick.verdict, why: pick.why };
  return { verdict: pick.verdict, why: parts.flatMap((p) => p.why) };
}

function evaluate(read, lists) {
  if (!read || !read.tree) {
    return {
      verdict: lists.unknown,
      expression: null,
      known: false,
      reason: `${read && read.note ? read.note : 'no license could be read'}, unknown licenses are ${lists.unknown}`
    };
  }
  const j = judgeTree(read.tree, lists);
  return { verdict: j.verdict, expression: read.expression, known: true, reason: j.why.join('; ') };
}

// a Maven pom's <licenses>: each name read on its own, several read as a choice, the way Maven means them
function fromMaven(names) {
  const list = (Array.isArray(names) ? names : []).map((n) => String(n || '').trim()).filter(Boolean);
  if (!list.length) return result(null, 'none', null, 'the pom names no license');
  const read = list.map((n) => fromText(n, 'pom'));
  if (read.every((r) => r.tree)) {
    const ids = [...new Set(read.map((r) => format(r.tree)))];
    const tree = parse(ids.length > 1 ? ids.map((x) => (/\s/.test(x) ? `(${x})` : x)).join(' OR ') : ids[0]).tree;
    return result(tree, 'pom', list.join('; '), ids.length > 1 ? 'several licenses listed, read as a choice' : read[0].note);
  }
  return read.find((r) => !r.tree) || read[0];
}

module.exports = { parse, format, leaves, fromText, fromNpm, fromPypi, fromMaven, compile, evaluate, RANK, NAMES, KNOWN };
