//pulled version, filled in from the tarball request via npm's session id
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('access_log', 'pulled_version')) return;

  await query(
    `ALTER TABLE access_log
       ADD COLUMN pulled_version VARCHAR(255) NULL AFTER version,
       ADD COLUMN pulled_exact TINYINT(1) NOT NULL DEFAULT 0 AFTER pulled_version,
       ADD COLUMN npm_session VARCHAR(64) NULL AFTER pulled_exact,
       ADD KEY idx_access_session (npm_session, package_name)`
  );
  // old tarball rows know their version. metadata rows get no guesses
  const filled = await query(
    'UPDATE access_log SET pulled_version = version, pulled_exact = 1 WHERE version IS NOT NULL'
  );
  log.info(`the traffic log records the pulled version now, stamped ${filled.affectedRows} old row(s)`);
};
