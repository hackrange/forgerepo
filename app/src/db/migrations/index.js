// @ts-check
// Changes to tables that already exist, IF NOT EXISTS won't touch them.
// Author: Tim Rice
//
// oldest first, in the order they shipped. a box that skipped a few releases needs exactly that
// order (an 08-25 install used to crash loop here). every step looks before it changes anything,
// so they all run on every boot and a restored old backup still gets caught up

const STEPS = [
  '001-rules-version-range-not-null',
  '002-requests-can-be-blocked',
  '003-cache-sizes-and-sources',
  '004-pulled-version',
  '005-request-token',
  '006-token-email',
  '007-applications-in-logs',
  '008-ecosystem-on-rules-and-upstreams',
  '009-forgerepo-name',
  '010-revoked-breakglass-keys',
  '011-pypi-findings',
  '012-traffic-ecosystem',
  '013-request-ecosystem',
  '014-eicar-is-not-a-scanner',
  '015-learning-requests',
  '016-artifact-licenses',
  '017-impersonation',
  '018-rules-per-application',
  '019-ci-and-production',
  '020-consumption-backfill',
  '021-blocked-by',
  '022-blob-location',
  '023-kill-kinds-and-waiver-reference',
  '024-audit-states',
  '025-publisher-role',
  '026-oci-digest-versions',
  '027-image-versions',
  '028-image-findings',
  '029-consumption-digests',
  '030-image-fixable-severity',
  '031-us-spelling',
  '032-auto-approve',
  '033-forgerepo-name',
  '034-upstream-options',
  '035-known-malicious-scanner',
  '036-drop-allow-publish'
];

/**
 * @param {{ query: Function, one: Function, log: { info: Function } }} db
 */
function helpers(db) {
  /** @param {string} table @param {string} name */
  const column = (table, name) => db.one(
    `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
    [table, name]
  );
  return {
    query: db.query,
    one: db.one,
    log: db.log,
    column,
    /** @param {string} table @param {string} name */
    hasColumn: async (table, name) => !!(await column(table, name)),
    /** @param {string} table @param {string} name */
    hasIndex: async (table, name) => !!(await db.one(
      `SELECT INDEX_NAME FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1`,
      [table, name]
    ))
  };
}

/**
 * @param {{ query: Function, one: Function, log: { info: Function } }} db
 */
async function run(db) {
  const ctx = helpers(db);
  for (const name of STEPS) {
    try {
      await require(`./${name}`)(ctx);
    } catch (err) {
      // which step, or the stack trace is a guessing game
      if (err instanceof Error) err.message = `schema step ${name}: ${err.message}`;
      throw err;
    }
  }
}

module.exports = { STEPS, run };
