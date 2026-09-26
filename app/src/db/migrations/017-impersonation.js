// impersonation: whose session this really is, and when it stops
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('sessions', 'impersonator_id')) return;

  await query(
    `ALTER TABLE sessions
       ADD COLUMN impersonator_id INT UNSIGNED NULL AFTER expires_at,
       ADD COLUMN impersonation_ends_at DATETIME NULL AFTER impersonator_id,
       ADD KEY idx_sessions_impersonator (impersonator_id),
       ADD CONSTRAINT fk_sessions_impersonator FOREIGN KEY (impersonator_id) REFERENCES users(id) ON DELETE CASCADE`
  );
  log.info('sessions can be an admin acting as someone else now');
};
