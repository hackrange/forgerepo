// Where each person's digest got to, and the lock that keeps two nodes from sending it twice.
// Author: Tim Rice

const db = require('../../db');

function markFor(userId, kind, recipient) {
  return db.one('SELECT mark FROM email_digest_state WHERE user_id = ? AND kind = ? AND recipient = ?', [userId, kind, recipient]);
}

// the first sighting starts the clock. a row that appeared meanwhile keeps its mark
function startMark(userId, kind, recipient, now) {
  return db.query(
    `INSERT INTO email_digest_state (user_id, kind, recipient, mark) VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE mark = mark`,
    [userId, kind, recipient, now]
  );
}

function moveMark(userId, kind, recipient, now) {
  return db.query(
    `INSERT INTO email_digest_state (user_id, kind, recipient, mark, last_sent_at) VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE mark = VALUES(mark), last_sent_at = VALUES(last_sent_at)`,
    [userId, kind, recipient, now, now]
  );
}

// the database clock, so marks and the rows they are compared with agree
async function now() {
  return (await db.one('SELECT NOW() AS now')).now;
}

// runs work only if this node gets the named lock straight away. null = another node has it
async function withLock(name, work) {
  const conn = await db.pool.getConnection();
  try {
    const [got] = await conn.query('SELECT GET_LOCK(?, 0) AS ok', [name]);
    if (!got[0] || Number(got[0].ok) !== 1) return null;
    try {
      return { result: await work() };
    } finally {
      await conn.query('SELECT RELEASE_LOCK(?)', [name]).catch(() => {});
    }
  } finally {
    conn.release();
  }
}

module.exports = { markFor, startMark, moveMark, now, withLock };
