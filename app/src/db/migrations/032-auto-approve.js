// Auto approve: each request remembers what the automatic check made of it, so Requests can say why it waits.
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('requests', 'auto_state')) return;
  await query(`ALTER TABLE requests
    ADD COLUMN auto_state VARCHAR(16) NULL AFTER decision_note,
    ADD COLUMN auto_note VARCHAR(500) NULL AFTER auto_state,
    ADD COLUMN auto_at DATETIME NULL AFTER auto_note,
    ADD KEY idx_requests_auto (status, auto_state, auto_at)`);
  log.info('requests remember what auto approve made of them');
};
