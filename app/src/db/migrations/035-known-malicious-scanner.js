// The known-malicious scanner (osv) joins the default scanners. A box still on the old default gets it, once. One
// that picked its own scanners keeps them, and so does one that takes osv back out afterward.
// Author: Tim Rice

module.exports = async ({ query, one, log }) => {
  if (await one("SELECT k FROM settings WHERE k = 'malware_osv_offered'")) return;
  const added = await query("UPDATE settings SET v = 'blocklist,clamav,osv' WHERE k = 'malware_scanners' AND v = 'blocklist,clamav'");
  await query("INSERT IGNORE INTO settings (k, v) VALUES ('malware_osv_offered', '1')");
  if (added.affectedRows) log.info('the known-malicious scanner (osv) is on the scanner list now');
};
