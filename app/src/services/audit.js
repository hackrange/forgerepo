// The audit trail from the portal.
// Author: Tim Rice

const repo = require('../db/repositories/audit');
const { audit } = require('../lib/actor');

function list(filters, paging) {
  return repo.page(filters, paging);
}

// the export streams straight to the response, this records that it went out
function exported(actor, format, written) {
  return audit(actor, 'audit.export', format, `${written} rows`);
}

module.exports = { list, exported };
