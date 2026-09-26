// eicar was only ever a test string, never a scanner. out of anyone's list
// Author: Tim Rice

module.exports = async ({ query, log }) => {
  const rows = await query("SELECT v FROM settings WHERE k = 'malware_scanners'");
  if (!rows.length || !/(^|,)\s*eicar\s*(,|$)/.test(String(rows[0].v || ''))) return;

  const kept = String(rows[0].v).split(',').map((s) => s.trim()).filter((s) => s && s !== 'eicar').join(',');
  await query("UPDATE settings SET v = ? WHERE k = 'malware_scanners'", [kept]);
  log.info(`the eicar test scanner is gone, scanners are now "${kept}"`);
};
