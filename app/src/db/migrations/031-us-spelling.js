// US spelling in stored values too: a waiver for a license, a scan that was canceled, an install the license gate held.
// Author: Tim Rice
//
// the old words are never named here. each column goes to plain text, anything outside the allowed set becomes the
// one word it can only have been, and the column goes back to its list

async function relist(ctx, table, column, allowed, fixed, notNull, def) {
  const col = await ctx.column(table, column);
  // the list already has the US word: done, the same test every older step here uses
  if (!col || String(col.COLUMN_TYPE).includes(`'${fixed}'`)) return false;
  await ctx.query(`ALTER TABLE ${table} MODIFY ${column} VARCHAR(32) NOT NULL${def ? ` DEFAULT '${def}'` : ''}`);
  await ctx.query(`UPDATE ${table} SET ${column} = ? WHERE ${column} NOT IN (${allowed.map(() => '?').join(', ')})`, [fixed, ...allowed]);
  await ctx.query(`ALTER TABLE ${table} MODIFY ${column} ENUM(${allowed.map((v) => `'${v}'`).join(',')}) ${notNull}${def ? ` DEFAULT '${def}'` : ''}`);
  return true;
}

module.exports = async (ctx) => {
  const waivers = await relist(ctx, 'waivers', 'kind', ['advisory', 'license', 'cooloff'], 'license', 'NOT NULL');
  const scans = await relist(ctx, 'cve_scans', 'status', ['running', 'done', 'failed', 'canceled'], 'canceled', 'NOT NULL', 'running');
  // the traffic log names the check that refused an install
  const blocked = await ctx.query("UPDATE access_log SET blocked_by = 'license' WHERE blocked_by LIKE 'licen_e' AND blocked_by <> 'license'");
  if (waivers || scans || (blocked && blocked.affectedRows)) ctx.log.info('stored values use US spelling now');
};
