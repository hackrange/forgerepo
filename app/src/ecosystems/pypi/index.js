// What the rule engine needs to know about PyPI.
// Author: Tim Rice
//
// npm's adapter flipped: both rule kinds match the folded name. dodge it by spelling and it's a suggestion

const name = require('./name');
const version = require('./version');

//globs fold too, so zope.* and zope_* are one rule. stars survive
function rulePattern(kind, pattern) {
  return name.normalize(pattern);
}

function ruleName(kind, text) {
  return name.normalize(text);
}

// SBOM imports write `2.31.0 || 2.32.0`, which PEP 440 never heard of. each side is its own
// specifier set, any match wins. Empty sides get dropped, `1.0 ||` must not mean everything
// options.prereleases goes straight to the specifier check: true, false or 'auto'
function satisfies(v, range, options) {
  const alternatives = String(range).split('||').map((part) => part.trim()).filter(Boolean);
  return alternatives.some((part) => version.satisfies(v, part, options));
}

const isPrerelease = (v) => version.valid(v) && version.isPrerelease(v);

module.exports = {
  id: 'pypi',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
