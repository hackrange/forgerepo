// ForgeRepo now, unless someone picked their own name
// Author: Tim Rice

module.exports = async ({ query, log }) => {
  const renamed = await query("UPDATE settings SET v = 'ForgeRepo' WHERE k = 'registry_name' AND v = 'npm-repo'");
  if (renamed.affectedRows) log.info('the portal name was still the old default, it says ForgeRepo now');
};
