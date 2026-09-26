// The safe version resolution log from the portal.
// Author: Tim Rice

const resolution = require('../policy/resolution');
const repo = require('../db/repositories/resolutions');

async function list(filters, paging) {
  const { rows, total } = await repo.page(filters, paging);
  return { rows, total, enabled: resolution.enabled(), threshold: resolution.threshold() };
}

module.exports = { list };
