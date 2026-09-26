// Portal API, rule list filters, shared with export.
// Author: Tim Rice

const ecosystems = require('../../ecosystems');
const rules = require('../../db/repositories/rules');
const { fail } = require('../../lib/errors');
const { str, likeTerm, oneOf } = require('../../lib/validate');

// checked here, turned into SQL by the repository. the list and the export share it so they can't drift
function parseRuleFilters(query) {
  const kind = oneOf(query.kind, ['allow', 'deny'], null);
  const ecosystem = query.ecosystem ? String(query.ecosystem) : null;
  if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
  const search = str(query.q, 200, 'search');
  const cached = oneOf(query.cached, ['yes', 'no'], null);
  const vuln = oneOf(query.vuln, ['yes', 'no'], null);
  // '' any, 'none' = covers everyone, a number = that one
  const scope = (raw) => {
    const text = raw === undefined ? '' : String(raw);
    if (text === 'none') return 'none';
    return /^[1-9]\d{0,9}$/.test(text) ? Number(text) : null;
  };
  return {
    ecosystem, kind, application: scope(query.application), environment: scope(query.environment),
    search: search ? likeTerm(search) : null, cached, vuln
  };
}

// the export has to match the list, images judged on disk included
async function ruleFilters(query) {
  return rules.filterClause(await require('../../services/rules').withImageCache(parseRuleFilters(query)));
}

module.exports = { parseRuleFilters, ruleFilters };
