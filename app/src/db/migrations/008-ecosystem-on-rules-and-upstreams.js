// ecosystem on rules and registries, existing rows are npm
// Author: Tim Rice

module.exports = async ({ query, hasColumn, hasIndex, log }) => {
  // key swaps in the same ALTER so the column never exists without it
  if (!(await hasColumn('rules', 'ecosystem'))) {
    const oldKey = await hasIndex('rules', 'uq_rules_pattern_kind_range');
    await query(
      `ALTER TABLE rules
         ADD COLUMN ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm' AFTER id,
         ${oldKey ? 'DROP INDEX uq_rules_pattern_kind_range,' : ''}
         ADD UNIQUE KEY uq_rules_eco_pattern_kind_range (ecosystem, pattern, kind, version_range)`
    );
    log.info('rules record which ecosystem they belong to now, and every existing rule is npm');
  }
  if (!(await hasColumn('upstreams', 'ecosystem'))) {
    await query("ALTER TABLE upstreams ADD COLUMN ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm' AFTER name");
    log.info('upstream registries record which ecosystem they serve now, and every existing one is npm');
  }
};
