// The overview's resettable lists. these only empty a list on the overview
// Author: Tim Rice

const db = require('../db');
const overview = require('../db/repositories/overview');
const { audit } = require('../lib/actor');

async function clearBlocked(actor) {
  // a line in the sand, not a delete
  await db.settings.set('blocked_cleared_at', new Date().toISOString().slice(0, 19).replace('T', ' '));
  await db.settings.load(true);
  await overview.clearClearedPackages();
  await audit(actor, 'stats.clear.blocked', 'most blocked list', null);
}

async function clearBusiest(actor) {
  const cleared = await overview.clearPackageCounters();
  await audit(actor, 'stats.clear.busiest', `${cleared} package counter(s)`, null);
  return cleared;
}

module.exports = { clearBlocked, clearBusiest };
