// cache rows remember their size and which registry they came from
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  // overview used to read every blob per page load to size the cache. Oops. store the length
  if (!(await hasColumn('packuments', 'bytes'))) {
    await query('ALTER TABLE packuments ADD COLUMN bytes INT UNSIGNED NOT NULL DEFAULT 0 AFTER body');
    const filled = await query('UPDATE packuments SET bytes = LENGTH(body)');
    log.info(`metadata cache sizes are recorded now, filled in ${filled.affectedRows} document(s)`);
  }

  // more than one registry now, so cache rows say where they came from
  for (const [table, key] of [['packuments', 'name'], ['tarballs', 'package_name']]) {
    if (!(await hasColumn(table, 'source'))) {
      await query(`ALTER TABLE ${table} ADD COLUMN source VARCHAR(64) NULL`);
      log.info(`${table} records which registry each ${key === 'name' ? 'document' : 'file'} came from now`);
    }
  }
};
