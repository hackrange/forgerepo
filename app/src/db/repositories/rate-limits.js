// Throttle counters. in the db, not memory, so every node counts together and a restart clears nothing.
// Author: Tim Rice

const db = require('../../db');

// single statement, so concurrent hits can't race
function hit(key, seconds) {
  return db.query(
    `INSERT INTO rate_limits (k, hits, reset_at)
          VALUES (?, 1, DATE_ADD(NOW(), INTERVAL ? SECOND))
     ON DUPLICATE KEY UPDATE
          hits = IF(reset_at <= NOW(), 1, hits + 1),
          reset_at = IF(reset_at <= NOW(), DATE_ADD(NOW(), INTERVAL ? SECOND), reset_at)`,
    [key, seconds, seconds]
  );
}

function read(key) {
  return db.one('SELECT hits, UNIX_TIMESTAMP(reset_at) AS reset_epoch FROM rate_limits WHERE k = ?', [key]);
}

function clear(key) {
  return db.query('DELETE FROM rate_limits WHERE k = ?', [key]);
}

// takes back one hit in the current window, never below zero and never from a window that already ran out
function refund(key) {
  return db.query('UPDATE rate_limits SET hits = hits - 1 WHERE k = ? AND hits > 0 AND reset_at > NOW()', [key]);
}

function sweep() {
  return db.query('DELETE FROM rate_limits WHERE reset_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)');
}

module.exports = { hit, read, clear, refund, sweep };
