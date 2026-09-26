// revoke deletes now, sweep the old-style revoked ones
// Author: Tim Rice

module.exports = async ({ query, log }) => {
  const dead = await query('DELETE FROM breakglass_keys WHERE revoked = 1');
  if (dead.affectedRows) log.info(`removed ${dead.affectedRows} revoked break glass key(s), they opened nothing`);
};
