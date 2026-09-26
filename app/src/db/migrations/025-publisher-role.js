// a developer who may also publish private packages, between developer and approver
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  const role = await column('users', 'role');
  if (!role || /'publisher'/.test(role.COLUMN_TYPE)) return;

  await query("ALTER TABLE users MODIFY role ENUM('viewer','developer','publisher','approver','admin') NOT NULL DEFAULT 'developer'");
  log.info('users can be developers with publish rights now');
};
