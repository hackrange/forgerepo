// consumption starts out with whatever the traffic log still remembers
// Author: Tim Rice

module.exports = async ({ one, log }) => {
  if (await one('SELECT 1 AS ok FROM consumption LIMIT 1')) return;

  // reads ecosystem, application and ci off the traffic log, so it goes last
  const filled = await require('../../consumption').backfill();
  if (filled) log.info(`consumption filled in from the traffic log, ${filled} consumer row(s)`);
};
