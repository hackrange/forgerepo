// @ts-check
// `*` matches anything, nothing else is special. no regex, so a pile of stars can't backtrack forever
// Author: Tim Rice

/**
 * @param {string} p
 * @param {string} t
 * @returns {boolean}
 */
function glob(p, t) {
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

// looks enough like a RegExp for the rule lists, which only ever call test()
class Glob {
  /** @param {string} pattern */
  constructor(pattern) {
    Object.defineProperty(this, 'pattern', { value: String(pattern) });
  }

  /** @param {unknown} text */
  test(text) {
    const t = String(text);
    // the regex this replaced had . for *, and . never crossed a line break. so neither do we
    if (/[\n\r\u2028\u2029]/.test(t)) return false;
    return glob(/** @type {any} */ (this).pattern, t);
  }
}

module.exports = { glob, Glob };
