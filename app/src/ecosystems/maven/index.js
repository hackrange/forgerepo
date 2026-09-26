// What the rule engine needs to know about Maven.
// Author: Tim Rice
// names are groupId:artifactId, case kept (a repository path is case sensitive). org.apache.maven.plugins:* is a rule.
//
// a milestone or a release candidate (5.11.0-M2, 2.18.0-rc1) is an ordinary version to Maven: poms pin them exactly
// (surefire imports junit-bom 5.11.0-M2) and ranges include them. npm's reason for holding pre-releases back, a latest
// tag somebody can move onto one, does not exist here. so to the rules they are versions like any other, and only a
// snapshot, which this box never serves anyway, counts as a pre-release

const version = require('./version');

const rulePattern = (kind, pattern) => String(pattern).trim();
const ruleName = (kind, text) => String(text).trim();
const satisfies = (v, range) => version.satisfies(v, range, { prereleases: true });
const isPrerelease = (v) => version.isSnapshot(v);

module.exports = {
  id: 'maven',
  rulePattern,
  ruleName,
  satisfies,
  isPrerelease
};
