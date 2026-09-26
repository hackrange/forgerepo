// allow_publish never did anything. it is out of the defaults now, so take the row out too rather than leave a
// switch in the settings table that looks like it means something.
// Author: Tim Rice

module.exports = async ({ query, log }) => {
  const gone = await query("DELETE FROM settings WHERE k = 'allow_publish'");
  if (gone.affectedRows) log.info('dropped allow_publish, nothing read it');
};
