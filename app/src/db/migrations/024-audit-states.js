// the audit trail records what a thing was before and after, and whether it worked
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('audit_log', 'result')) return;

  await query(
    `ALTER TABLE audit_log
       ADD COLUMN before_state TEXT NULL AFTER detail,
       ADD COLUMN after_state TEXT NULL AFTER before_state,
       ADD COLUMN result ENUM('success','failure','denied') NOT NULL DEFAULT 'success' AFTER after_state,
       ADD KEY idx_audit_action (action, ts),
       ADD KEY idx_audit_result (result, ts)`
  );
  // rows from before this already said so in the action name, so the filter works on old ones too
  await query(
    `UPDATE audit_log SET result = 'failure'
      WHERE action LIKE '%.failed' OR detail LIKE 'failed:%' OR detail LIKE 'failed %'`
  );
  await query(
    "UPDATE audit_log SET result = 'denied' WHERE action IN ('login.blocked', 'login.locked', 'breakglass.throttled')"
  );
  log.info('the audit trail records before, after and the result now');
};
