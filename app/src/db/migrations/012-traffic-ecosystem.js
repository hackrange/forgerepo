// npm and PyPI share the traffic log
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('access_log', 'ecosystem')) return;

  await query("ALTER TABLE access_log ADD COLUMN ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm' AFTER environment");
  log.info('the traffic log records which kind of registry each request was for now');
};
