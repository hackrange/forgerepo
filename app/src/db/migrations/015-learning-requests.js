// learning mode (audit only) opens requests too, marked so the queue shows where they came from
// Author: Tim Rice

module.exports = async ({ query, column, log }) => {
  const source = await column('requests', 'source');
  if (!source || /'learning'/.test(source.COLUMN_TYPE)) return;

  await query("ALTER TABLE requests MODIFY source ENUM('portal','blocked-install','learning') NOT NULL DEFAULT 'portal'");
  log.info('requests can come from learning mode now');
};
