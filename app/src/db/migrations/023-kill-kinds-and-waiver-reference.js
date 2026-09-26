// kills that name one file by hash or an advisory instead of a package, and a ticket on waivers
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (!(await hasColumn('kill_switches', 'kind'))) {
    await query(
      `ALTER TABLE kill_switches
         ADD COLUMN kind ENUM('package','hash','advisory') NOT NULL DEFAULT 'package' AFTER id,
         ADD COLUMN subject VARCHAR(128) NOT NULL DEFAULT '' AFTER version_range,
         ADD KEY idx_kill_subject (status, kind, subject)`
    );
    log.info('the kill switch can name a file hash or an advisory now');
  }
  if (!(await hasColumn('waivers', 'reference'))) {
    await query(
      `ALTER TABLE waivers
         ADD COLUMN reference VARCHAR(255) NOT NULL DEFAULT '' AFTER reason`
    );
    log.info('waivers carry a ticket or reference now');
  }
};
