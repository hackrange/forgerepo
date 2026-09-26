// What the rule engine needs to know about npm to decide anything.
// Author: Tim Rice
// same rules policy.js always had, just lifted out. the golden policy test keeps them honest

const semver = require('semver');

// case sensitive namespace. deny matches lowercased (Event-Stream can't dodge it),
// allow matches exactly so approving JSONStream doesn't approve somebody else's jsonstream
function subject(kind, text) {
  return kind === 'deny' ? String(text).toLowerCase() : String(text);
}

// options.prereleases, like the PyPI side: true (default) every prerelease in the range counts, 'auto' only when the range
// names one, which is npm's own rule. a range semver can't read = no match, not a throw
function satisfies(version, range, options) {
  const mode = options && options.prereleases !== undefined ? options.prereleases : true;
  try {
    return mode === true ? semver.satisfies(version, range, { includePrerelease: true }) : semver.satisfies(version, range);
  } catch (err) {
    return false;
  }
}

function isPrerelease(version) {
  const pre = semver.valid(version) ? semver.prerelease(version) : null;
  return !!(pre && pre.length);
}

module.exports = {
  id: 'npm',
  //same function both sides so a rule and a request can't be spelled differently
  rulePattern: subject,
  ruleName: subject,
  satisfies,
  isPrerelease
};
