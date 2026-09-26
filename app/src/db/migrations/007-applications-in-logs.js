// tokens hold ids, logs hold names as they were. no backfill, a blank beats a guess
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (!(await hasColumn('tokens', 'application_id'))) {
    await query(
      `ALTER TABLE tokens
         ADD COLUMN application_id INT UNSIGNED NULL AFTER name,
         ADD COLUMN environment_id INT UNSIGNED NULL AFTER application_id`
    );
    log.info('tokens can name an application and an environment now');
  }
  if (!(await hasColumn('access_log', 'application'))) {
    await query(
      `ALTER TABLE access_log
         ADD COLUMN application VARCHAR(128) NULL AFTER token_name,
         ADD COLUMN environment VARCHAR(128) NULL AFTER application,
         ADD KEY idx_access_app (application, ts),
         ADD KEY idx_access_env (environment, ts)`
    );
    log.info('the traffic log records the application and environment now');
  }
  if (!(await hasColumn('vuln_downloads', 'application'))) {
    await query(
      `ALTER TABLE vuln_downloads
         ADD COLUMN application VARCHAR(128) NULL AFTER token_name,
         ADD COLUMN environment VARCHAR(128) NULL AFTER application,
         ADD KEY idx_vuln_dl_app (application, ts)`
    );
    log.info('vulnerable downloads record the application and environment now');
  }
};
