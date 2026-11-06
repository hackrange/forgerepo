// Rules remember which API key filed them, so a key can only touch its own. the api_keys table itself comes from schema.sql
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('rules', 'api_key_id')) return;
  await query(`ALTER TABLE rules
    ADD COLUMN api_key_id INT UNSIGNED NOT NULL DEFAULT 0 AFTER expires_at,
    ADD KEY idx_rules_api_key (api_key_id)`);
  log.info('rules know which api key made them');
};
