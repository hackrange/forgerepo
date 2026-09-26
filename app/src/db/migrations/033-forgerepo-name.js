// The project is called ForgeRepo now. A portal still showing the old default name follows, one chosen by hand stays.
// Author: Tim Rice

// the old default, spelled so the rename sweep leaves it alone
const PREVIOUS = ['Repo', 'Forge'].join('');

module.exports = async ({ query, log }) => {
  const renamed = await query("UPDATE settings SET v = 'ForgeRepo' WHERE k = 'registry_name' AND v = ?", [PREVIOUS]);
  if (renamed.affectedRows) log.info('the portal name was the old default, it says ForgeRepo now');
};
