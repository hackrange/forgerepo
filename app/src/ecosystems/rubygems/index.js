// What the rule engine needs to know about Ruby gems.
// Author: Tim Rice
// names keep their case, the way rubygems.org serves them. rails-* is a rule

const version = require('./version');

const rulePattern = (kind, pattern) => String(pattern).trim();
const ruleName = (kind, text) => String(text).trim();
const satisfies = (v, range, options) => version.satisfies(v, range, options);
const isPrerelease = (v) => version.isPrerelease(v);

module.exports = {
  id: 'rubygems',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
