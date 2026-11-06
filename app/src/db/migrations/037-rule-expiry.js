// Rules can run out: a temporary allow for a time boxed exception lapses on its own instead of someone remembering.
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('rules', 'expires_at')) return;
  await query(`ALTER TABLE rules
    ADD COLUMN expires_at DATETIME NULL AFTER enabled,
    ADD KEY idx_rules_expires (expires_at)`);
  log.info('rules can have an expiry date now');
};
