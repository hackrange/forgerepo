// blocked-install requests keep the token, someone has to be told
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('requests', 'token_name')) return;

  await query('ALTER TABLE requests ADD COLUMN token_name VARCHAR(128) NULL AFTER requested_by');
  log.info('requests record which token a blocked install was using now');
};
