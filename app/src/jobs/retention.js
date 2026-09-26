// How long logs are kept. raw traffic by the setting, the compliance trails four times as long.
// Author: Tim Rice

const db = require('../db');
const log = require('../logger');
const accessLog = require('../db/repositories/access-log');
const audit = require('../db/repositories/audit');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const resolutions = require('../db/repositories/resolutions');
const overview = require('../db/repositories/overview');

async function cleanup() {
  const days = db.settings.getInt('log_retention_days', 30);
  if (days > 0) {
    const access = await accessLog.deleteOlderThan(days);
    // audit trail lives 4x as long, it's the one compliance asks about
    const trail = await audit.deleteOlderThan(days * 4);
    // who pulled the bad version? also compliance
    await vulnerabilities.deleteDownloadsOlderThan(days * 4);
    await resolutions.deleteOlderThan(days);
    if (access || trail) {
      log.info(`log cleanup removed ${access} access rows and ${trail} audit rows`);
    }
  }
  // consumers are kept on their own clock, far longer than raw traffic
  const forgotten = await require('../consumption').sweep();
  if (forgotten) log.info(`consumption cleanup forgot ${forgotten} consumer row(s) nobody has seen for a while`);
  // overview only looks back a week
  await overview.forgetClearedOlderThan(7);
}

module.exports = { cleanup };
