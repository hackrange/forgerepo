// Who uses what keeps the version pulled, and for an image that is a 71 character digest in a 64 character column.
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  const version = await column('consumption', 'version');
  if (!version || !/varchar\(64\)/i.test(version.COLUMN_TYPE)) return;
  await query(`ALTER TABLE consumption MODIFY version VARCHAR(128) ${version.IS_NULLABLE === 'YES' ? 'NULL' : 'NOT NULL'}`);
  log.info('who uses what can hold an image digest now');
};
