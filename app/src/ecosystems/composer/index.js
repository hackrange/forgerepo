// What the rule engine needs to know about Composer packages.
// Author: Tim Rice
// names fold to lower case on both sides, so Symfony/* catches symfony/http-kernel

const name = require('./name');
const version = require('./version');

const rulePattern = (kind, pattern) => name.fold(pattern);
const ruleName = (kind, text) => name.fold(text);
const satisfies = (v, range, options) => version.satisfies(v, range, options);
const isPrerelease = (v) => version.isPrerelease(v);

module.exports = {
  id: 'composer',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
