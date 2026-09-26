// What the rule engine needs to know about CocoaPods.
// Author: Tim Rice
// names keep their case, the way the CDN files them. Firebase* is a rule

const version = require('./version');

const rulePattern = (kind, pattern) => String(pattern).trim();
const ruleName = (kind, text) => String(text).trim();
const satisfies = (v, range, options) => version.satisfies(v, range, options);
const isPrerelease = (v) => version.isPrerelease(v);

module.exports = {
  id: 'cocoapods',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
