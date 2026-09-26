// Streaming a big result a row at a time, for the exports.
// Author: Tim Rice
// the sql comes from another repository, never from a request

const db = require('../../db');

//stream rows, memory stays flat
async function eachRow(sql, params, onRow) {
  const conn = await db.pool.getConnection();
  try {
    const stream = conn.connection.query(sql, params).stream();
    for await (const row of stream) await onRow(row);
  } finally {
    conn.release();
  }
}

module.exports = { eachRow };
