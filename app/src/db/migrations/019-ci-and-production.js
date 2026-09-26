// dry runs tell pipelines from people, and production stops being a guess off the name
// Author: Tim Rice

module.exports = async ({ query, hasColumn, log }) => {
  if (!(await hasColumn('access_log', 'ci'))) {
    await query('ALTER TABLE access_log ADD COLUMN ci VARCHAR(32) NULL AFTER npm_session');
    log.info('the traffic log records which CI a download came from now');
  }

  // guessed once here, a checkbox from then on
  if (!(await hasColumn('environments', 'production'))) {
    await query('ALTER TABLE environments ADD COLUMN production TINYINT(1) NOT NULL DEFAULT 0 AFTER note');
    const ticked = await query("UPDATE environments SET production = 1 WHERE name LIKE 'prod%'");
    log.info(`environments can be marked production now, ${ticked.affectedRows} named prod-something were ticked`);
  }
};
