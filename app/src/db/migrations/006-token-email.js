// token contact address, so the digest reaches the team and not whoever minted it years ago
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('tokens', 'email')) return;

  await query('ALTER TABLE tokens ADD COLUMN email VARCHAR(190) NULL AFTER name');
  log.info('tokens can carry a contact address now');
};
