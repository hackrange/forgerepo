// What the rule engine needs to know about Swift packages.
// Author: Tim Rice
// identities fold to lower case on both sides, so apple.* catches Apple.Swift-Log

const name = require('./name');
const version = require('./version');

const rulePattern = (kind, pattern) => name.fold(pattern);
const ruleName = (kind, text) => name.fold(text);
const satisfies = (v, range, options) => version.satisfies(v, range, options);
const isPrerelease = (v) => version.isPrerelease(v);

module.exports = {
  id: 'swift',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
