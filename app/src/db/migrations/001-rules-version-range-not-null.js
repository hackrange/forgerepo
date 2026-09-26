// version_range used to allow NULL, and NULLs never collide in a unique key
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  const col = await column('rules', 'version_range');
  if (!col || col.IS_NULLABLE !== 'YES') return;

  // kill dupes first (oldest survives) or the ALTER trips on its own key
  const dupes = await query(
    `DELETE r1 FROM rules r1
       JOIN rules r2
         ON r1.pattern = r2.pattern
        AND r1.kind = r2.kind
        AND ((r1.version_range IS NULL AND r2.version_range IS NULL) OR r1.version_range = r2.version_range)
        AND r1.id > r2.id`
  );
  await query("UPDATE rules SET version_range = '' WHERE version_range IS NULL");
  await query("ALTER TABLE rules MODIFY version_range VARCHAR(128) NOT NULL DEFAULT ''");
  log.info(`rules.version_range is now not null, removed ${dupes.affectedRows} duplicate rule(s)`);
};
