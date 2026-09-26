// @ts-check
// Builds the tables on boot and brings old ones up to date. One node at a time.
// Author: Tim Rice

const fs = require('fs');
const path = require('path');
const migrations = require('./migrations');

// how long a booting node waits on another one that is mid-upgrade
const LOCK_WAIT_S = 300;
// GET_LOCK is server wide, so two databases on one server get their own lock. names max out at 64
const LOCK_NAME = "CONCAT('rf_schema_', LEFT(SHA2(DATABASE(), 256), 40))";

/**
 * @param {{ pool: any, query: Function, one: Function, log: { info: Function } }} db
 */
async function load(db) {
  const raw = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  // not a real parser, splits on semicolons. so no semicolons in schema.sql strings, don't add any
  const sql = raw
    .split('\n')
    .filter((line) => !/^\s*--/.test(line))
    .join('\n');
  const statements = sql
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);

  // nodes on a shared db all boot at once after an upgrade. two ALTERs on one table = one crash
  const conn = await db.pool.getConnection();
  try {
    const [got] = await conn.query(`SELECT GET_LOCK(${LOCK_NAME}, ?) AS ok`, [LOCK_WAIT_S]);
    if (!got[0] || Number(got[0].ok) !== 1) {
      throw new Error(`waited ${LOCK_WAIT_S}s for another node to finish upgrading the schema, giving up`);
    }
    try {
      for (const stmt of statements) {
        await db.query(stmt);
      }
      db.log.info(`schema is up to date, ${statements.length} statements ran`);
      await migrations.run(db);
    } finally {
      await conn.query(`SELECT RELEASE_LOCK(${LOCK_NAME})`).catch(() => {});
    }
  } finally {
    conn.release();
  }
}

module.exports = { load, LOCK_WAIT_S };
