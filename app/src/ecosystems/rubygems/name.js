// Gem names. rubygems.org keeps them as they were first pushed (RedCloth, rack), so the case is kept.
// Author: Tim Rice
// letters, digits, dots, dashes and underscores, with a letter or digit in it somewhere

const MAX = 128;
const NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

const valid = (n) => {
  const s = String(n || '').trim();
  return !!s && s.length <= MAX && NAME_RE.test(s) && /[A-Za-z0-9]/.test(s) && !s.includes('..');
};

module.exports = { MAX, valid };
