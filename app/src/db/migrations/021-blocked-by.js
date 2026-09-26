// which safety check refused a request, so the dashboard counts attempts instead of reading reason text
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('access_log', 'blocked_by')) return;

  await query(
    `ALTER TABLE access_log
       ADD COLUMN blocked_by VARCHAR(16) NULL AFTER reason,
       ADD KEY idx_access_blocked (blocked_by, ts)`
  );
  log.info('the traffic log records which safety check refused a request now');
};
