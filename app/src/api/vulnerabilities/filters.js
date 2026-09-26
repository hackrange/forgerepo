// Portal API, finding list filters, shared with export.
// Author: Tim Rice

const ecosystems = require('../../ecosystems');
const vulnerabilities = require('../../db/repositories/vulnerabilities');
const { fail } = require('../../lib/errors');
const { str, likeTerm, boolFlag, oneOf } = require('../../lib/validate');

// checked here, turned into SQL by the repository, same as rules
function parseFindingFilters(query) {
  const severity = oneOf(query.severity, ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'], null);
  const search = str(query.q, 200, 'search');
  const onlyNew = boolFlag(query.only_new, false);
  const kev = boolFlag(query.kev, false);
  const ecosystem = query.ecosystem ? String(query.ecosystem) : null;
  if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
  return { ecosystem, severity, search: search ? likeTerm(search) : null, onlyNew, kev };
}

function findingFilters(query) {
  return vulnerabilities.findingClause(parseFindingFilters(query));
}

module.exports = { parseFindingFilters, findingFilters };
