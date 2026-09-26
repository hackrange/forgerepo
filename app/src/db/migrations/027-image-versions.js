// A lifecycle stage or a property on an image is keyed on a tag or a digest. a digest is 71 characters, a tag up to 128,
// and these tables only had room for 64.
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  let widened = 0;
  for (const table of ['lifecycle_stages', 'lifecycle_history', 'artifact_properties']) {
    const version = await column(table, 'version');
    if (!version || !/varchar\(64\)/i.test(version.COLUMN_TYPE)) continue;
    const extra = table === 'artifact_properties' ? " DEFAULT ''" : '';
    await query(`ALTER TABLE ${table} MODIFY version VARCHAR(128) NOT NULL${extra}`);
    widened += 1;
  }
  if (widened) log.info('lifecycle stages and properties can name an image tag or digest now');
};
