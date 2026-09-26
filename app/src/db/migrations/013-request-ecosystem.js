// so approving writes the rule for the right registry
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (await hasColumn('requests', 'ecosystem')) return;

  await query(
    `ALTER TABLE requests
       ADD COLUMN ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm' AFTER id,
       ADD KEY idx_requests_eco_pkg (ecosystem, package_name, status)`
  );
  log.info('package requests record which kind of registry they are for now, and every existing one is npm');
};
