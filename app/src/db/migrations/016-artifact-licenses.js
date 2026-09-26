// license intelligence: what each cached file is licensed under, and the verdict on it
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('artifacts', 'license_verdict')) return;

  await query(
    `ALTER TABLE artifacts
       ADD COLUMN license_expression VARCHAR(512) NULL AFTER status,
       ADD COLUMN license_verdict ENUM('allowed','review','blocked') NULL AFTER license_expression,
       ADD COLUMN license_note VARCHAR(255) NULL AFTER license_verdict,
       ADD COLUMN license_checked_at DATETIME NULL AFTER license_note,
       ADD KEY idx_artifacts_license (license_verdict)`
  );
  log.info('artifacts record their license now, the ones already cached get read in the background');
};
