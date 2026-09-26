// blocking writes a deny rule too, so it gets its own status
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  const status = await column('requests', 'status');
  if (!status || /'blocked'/.test(status.COLUMN_TYPE)) return;

  await query(
    `ALTER TABLE requests MODIFY status
       ENUM('pending','approved','rejected','withdrawn','blocked')
       NOT NULL DEFAULT 'pending'`
  );
  log.info('requests can now be blocked as well as approved and rejected');
};
