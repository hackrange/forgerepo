// The counters behind the overview lists. emptying them leaves logs, cache and rules alone
// Author: Tim Rice

const db = require('../../db');

function clearClearedPackages() {
  return db.query('DELETE FROM cleared_packages');
}

// returns how many package counters went
async function clearPackageCounters() {
  return (await db.query('DELETE FROM packages')).affectedRows;
}

// the most blocked list only looks back so far
function forgetClearedOlderThan(days) {
  return db.query('DELETE FROM cleared_packages WHERE cleared_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [days]);
}

module.exports = { clearClearedPackages, clearPackageCounters, forgetClearedOlderThan };
