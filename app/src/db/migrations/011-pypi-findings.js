// same deal as rules for findings and downloads, plus the other names an advisory goes by
// Author: Tim Rice

module.exports = async ({ query, hasColumn, hasIndex, log }) => {
  if (!(await hasColumn('cve_findings', 'ecosystem'))) {
    const oldKey = await hasIndex('cve_findings', 'uq_cve_finding');
    await query(
      `ALTER TABLE cve_findings
         ADD COLUMN ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm' AFTER id,
         ${oldKey ? 'DROP INDEX uq_cve_finding,' : ''}
         ADD UNIQUE KEY uq_cve_finding_eco (ecosystem, package_name, version)`
    );
    log.info('vulnerability findings record which ecosystem they belong to now, and every existing one is npm');
  }
  if (!(await hasColumn('vuln_downloads', 'ecosystem'))) {
    await query("ALTER TABLE vuln_downloads ADD COLUMN ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm' AFTER id");
    log.info('vulnerable downloads record which ecosystem they came from now');
  }
  // aliases so GHSA + PYSEC count once. NULL = don't know, refetched when needed
  if (!(await hasColumn('cve_advisories', 'aliases'))) {
    await query('ALTER TABLE cve_advisories ADD COLUMN aliases TEXT NULL AFTER cves');
    log.info('advisories keep the other ids they are known by now');
  }
};
