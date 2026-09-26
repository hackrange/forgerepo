// How bad an image is counting only what an upgrade fixes today, which is what keeps it from being pulled.
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('image_scans', 'fixable_severity')) return;
  await query("ALTER TABLE image_scans ADD COLUMN fixable_severity VARCHAR(16) NOT NULL DEFAULT '' AFTER severity");
  log.info('image scans record how bad they are counting only what has a fix');
};
