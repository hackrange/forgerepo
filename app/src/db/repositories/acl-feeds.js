// Fetched network lists for the client allow list (GitHub's ranges today), and where each sync got to.
// Author: Tim Rice

const db = require('../../db');

// every fetched network for the feeds switched on
function cidrs(feeds) {
  return db.query('SELECT cidr FROM registry_acl_feed WHERE feed IN (?)', [feeds]);
}

async function countIn(feeds) {
  return Number((await db.one('SELECT COUNT(*) AS n FROM registry_acl_feed WHERE feed IN (?)', [feeds])).n);
}

async function countFor(feed) {
  return Number((await db.one('SELECT COUNT(*) AS n FROM registry_acl_feed WHERE feed = ?', [feed])).n);
}

function sections(feed) {
  return db.query('SELECT DISTINCT section FROM registry_acl_feed WHERE feed = ?', [feed]);
}

function countsBySection(feed) {
  return db.query('SELECT section, COUNT(*) AS n FROM registry_acl_feed WHERE feed = ? GROUP BY section', [feed]);
}

function state(feed) {
  return db.one('SELECT feed, etag, synced_at, checked_at, ranges, error FROM acl_feeds WHERE feed = ?', [feed]);
}

// message arrives already cut to fit
function noteError(feed, message) {
  return db.query(
    `INSERT INTO acl_feeds (feed, checked_at, error) VALUES (?, NOW(), ?)
     ON DUPLICATE KEY UPDATE checked_at = NOW(), error = VALUES(error)`,
    [feed, message]
  );
}

// asked, nothing changed (a 304)
function noteChecked(feed) {
  return db.query(
    `INSERT INTO acl_feeds (feed, checked_at, error) VALUES (?, NOW(), NULL)
     ON DUPLICATE KEY UPDATE checked_at = NOW(), error = NULL`,
    [feed]
  );
}

// replace not merge, dropped ranges must stop being allowed. rows are [feed, section, cidr, family]
function replace(feed, rows, etag, batchSize) {
  return db.transaction(async (q) => {
    await q('DELETE FROM registry_acl_feed WHERE feed = ?', [feed]);
    for (let i = 0; i < rows.length; i += batchSize) {
      const batch = rows.slice(i, i + batchSize);
      await q(
        `INSERT INTO registry_acl_feed (feed, section, cidr, family) VALUES ${batch.map(() => '(?, ?, ?, ?)').join(', ')}`,
        batch.flat()
      );
    }
    await q(
      `INSERT INTO acl_feeds (feed, etag, synced_at, checked_at, ranges, error)
       VALUES (?, ?, NOW(), NOW(), ?, NULL)
       ON DUPLICATE KEY UPDATE etag = VALUES(etag), synced_at = NOW(), checked_at = NOW(),
         ranges = VALUES(ranges), error = NULL`,
      [feed, etag, rows.length]
    );
  });
}

async function clear(feed) {
  await db.query('DELETE FROM registry_acl_feed WHERE feed = ?', [feed]);
  await db.query('DELETE FROM acl_feeds WHERE feed = ?', [feed]);
}

module.exports = { cidrs, countIn, countFor, sections, countsBySection, state, noteError, noteChecked, replace, clear };
