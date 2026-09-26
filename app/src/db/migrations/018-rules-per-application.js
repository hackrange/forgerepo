// rules for one application or environment. the unique key has to include them or dev and prod collide
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('rules', 'application_id')) return;

  // 008 made uq_rules_eco_pattern_kind_range, which is why this one can't run before it
  await query(
    `ALTER TABLE rules
       ADD COLUMN application_id INT UNSIGNED NOT NULL DEFAULT 0 AFTER version_range,
       ADD COLUMN environment_id INT UNSIGNED NOT NULL DEFAULT 0 AFTER application_id,
       DROP INDEX uq_rules_eco_pattern_kind_range,
       ADD UNIQUE KEY uq_rules_scope (ecosystem, pattern, kind, version_range, application_id, environment_id),
       ADD KEY idx_rules_scope (application_id, environment_id)`
  );
  log.info('rules can be scoped to an application or an environment now');
};
