// An image finding is keyed on its digest, 71 characters, and the vulnerabilities list only had room for 64.
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  const version = await column('cve_findings', 'version');
  if (!version || !/varchar\(64\)/i.test(version.COLUMN_TYPE)) return;

  await query('ALTER TABLE cve_findings MODIFY version VARCHAR(128) NOT NULL');
  log.info('the vulnerabilities list can hold an image digest now');
};
