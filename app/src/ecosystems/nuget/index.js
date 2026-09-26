// What the rule engine needs to know about NuGet.
// Author: Tim Rice
// ids fold to lower case on both sides, so Microsoft.Extensions.* catches microsoft.extensions.logging

const name = require('./name');
const version = require('./version');

const rulePattern = (kind, pattern) => name.fold(pattern);
const ruleName = (kind, text) => name.fold(text);
const satisfies = (v, range, options) => version.satisfies(v, range, options);
const isPrerelease = (v) => version.isPrerelease(v);

module.exports = {
  id: 'nuget',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
