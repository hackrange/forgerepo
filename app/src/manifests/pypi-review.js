// The PyPI half of a file review: requirements files, Python lockfiles and the PyPI parts of an SBOM, judged by the PyPI rules.
// Author: Tim Rice
// the review itself is ecosystem-review.js, shared with the newer types. what PyPI brings is its names and specifiers

const pypiName = require('../ecosystems/pypi/name');
const pypiVersion = require('../ecosystems/pypi/version');
const ecosystems = require('../ecosystems');
const shared = require('./ecosystem-review');
const { exactPypi } = require('./formats');

function specKind(spec) {
  if (exactPypi(spec)) return 'exact';
  if (!spec || spec === '*') return 'range';
  return pypiVersion.validSpecifierSet(spec) ? 'range' : 'unparsable';
}

function describeSpec(spec) {
  const exact = exactPypi(spec);
  if (exact) return `exactly ${exact} and nothing else`;
  if (!spec || spec === '*') return 'any version';
  return `versions matching ${spec}`;
}

const profile = {
  id: 'pypi',
  label: 'PyPI',
  setting: 'pypi_enabled',
  validName: (n) => pypiName.valid(n),
  fold: (n) => pypiName.normalize(n),
  exact: exactPypi,
  specKind,
  describe: describeSpec,
  resolver: 'pip'
};

// raw: [{ name, spec, section, file }]. returns the findings and what the advisory feed was asked
const review = (raw, notes) => shared.review(profile, raw, notes);
const matchRule = (rule, kind, spec) => shared.matchRule(profile, ecosystems.adapter('pypi'), rule, kind, spec);

module.exports = { review, matchRule, specKind, describeSpec, profile };
