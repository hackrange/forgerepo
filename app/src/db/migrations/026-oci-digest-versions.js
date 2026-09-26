// An image is asked for by digest, which is 71 characters, and the traffic log only had room for 64.
// Author: Tim Rice
//
// the row was being dropped and the pull served anyway, so image pulls went missing from the log.
// 128 is the width a tag can be, so it holds either a tag or a digest

module.exports = async ({ query, column, log }) => {
  const version = await column('access_log', 'version');
  if (!version || !/varchar\(64\)/i.test(version.COLUMN_TYPE)) return;

  await query('ALTER TABLE access_log MODIFY version VARCHAR(128) NULL');
  log.info('the traffic log can hold an image digest now');
};
