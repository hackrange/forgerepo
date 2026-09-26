// What the rule engine needs to know about OCI images.
// Author: Tim Rice
//
// npm and PyPI have versions a range can be reasoned about. a tag is just a name someone moved, so a rule range here is
// exact tags, a glob like 1.2.*, or a digest. anything cleverer would be pretending to understand what a tag means

const name = require('./name');

// repository names are lower case already, so both rule kinds compare the same folded name
function rulePattern(kind, pattern) {
  return name.foldPattern(pattern);
}

function ruleName(kind, text) {
  return name.fold(text);
}

// * is any run of characters, everything else only itself. no regex: one .* per star backtracked for as long as
// a range full of stars and a long tag allowed, which stalls every pull that asks. tags never hold a line break,
// and a regex . never crossed one, so a line break anywhere is simply no match
const LINE_BREAK = /[\n\r\u2028\u2029]/;

function globMatch(pattern, text) {
  if (LINE_BREAK.test(text)) return false;
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && pattern[p] === '*') {
      star = p;
      mark = t;
      p += 1;
    } else if (p < pattern.length && pattern[p] === text[t]) {
      p += 1;
      t += 1;
    } else if (star !== -1) {
      // the last star takes one more character and the rest is tried again from there
      p = star + 1;
      mark += 1;
      t = mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p += 1;
  return p === pattern.length;
}

// reference is a tag or a digest. range is one or more of those, separated by ||, with * allowed in a tag
function satisfies(reference, range) {
  const ref = String(reference || '').trim();
  if (!ref) return false;
  const parts = String(range || '').split('||').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return false;
  return parts.some((part) => {
    if (part.startsWith('sha256:') || ref.startsWith('sha256:')) return part === ref;
    return part.includes('*') ? globMatch(part, ref) : part === ref;
  });
}

module.exports = {
  id: 'oci',
  rulePattern,
  ruleName,
  satisfies,
  globMatch
};
