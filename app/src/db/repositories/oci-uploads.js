// Image layers on their way in. docker push opens an upload, sends the bytes in one or more pieces, then names the digest.
// Author: Tim Rice
// an upload belongs to the user and repository that opened it, every call asks for both so nobody writes into somebody else's

const db = require('../../db');

const COLUMNS = 'id, repository, user_id, username, size, started_at, updated_at';

function open({ id, repository, userId, username }) {
  return db.query(
    'INSERT INTO oci_uploads (id, repository, user_id, username, size) VALUES (?, ?, ?, ?, 0)',
    [id, repository, userId, String(username).slice(0, 64)]
  );
}

// only the owner finds it. anyone else gets the same answer as for an id that never existed
function mine(id, repository, userId) {
  return db.one(`SELECT ${COLUMNS} FROM oci_uploads WHERE id = ? AND repository = ? AND user_id = ?`, [id, repository, userId]);
}

// the new length, only if nobody else moved it first
async function grow(id, from, to) {
  const result = await db.query('UPDATE oci_uploads SET size = ?, updated_at = NOW() WHERE id = ? AND size = ?', [to, id, from]);
  return result.affectedRows === 1;
}

async function close(id) {
  await db.query('DELETE FROM oci_uploads WHERE id = ?', [id]);
}

async function openFor(userId) {
  const row = await db.one('SELECT COUNT(*) AS n FROM oci_uploads WHERE user_id = ?', [userId]);
  return Number(row ? row.n : 0);
}

// uploads nobody touched for a while. docker finishes or gives up long before this
function stale(minutes, limit = 200) {
  return db.query(
    `SELECT ${COLUMNS} FROM oci_uploads WHERE updated_at < NOW() - INTERVAL ? MINUTE ORDER BY updated_at LIMIT ?`,
    [minutes, limit]
  );
}

// blobs pushed a day ago that no manifest names: a push that was refused (a tag that never moves) or never finished
function orphans(source, limit = 100) {
  return db.query(
    `SELECT a.package_name, a.filename FROM artifacts a
      WHERE a.ecosystem = 'oci' AND a.upstream = ? AND a.first_seen < NOW() - INTERVAL 1 DAY
        AND NOT EXISTS (SELECT 1 FROM oci_refs r WHERE r.repository = a.package_name AND r.child = a.filename)
      LIMIT ?`,
    [source, limit]
  );
}

module.exports = { open, mine, grow, close, openFor, stale, orphans };
