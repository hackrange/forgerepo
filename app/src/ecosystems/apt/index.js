// What the rule engine needs to know about Debian packages.
// Author: Tim Rice
// names match exactly, they are lower case already

const version = require('./version');

const rulePattern = (kind, pattern) => String(pattern).trim();
const ruleName = (kind, text) => String(text).trim();
const satisfies = (v, range, options) => version.satisfies(v, range, options);
const isPrerelease = (v) => version.isPrerelease(v);

module.exports = {
  id: 'apt',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
