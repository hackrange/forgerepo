// Which digest a tag pointed at, and when it last moved. Tags move, digests do not.
// Author: Tim Rice

const db = require('../../db');

function get(repository, tag) {
  return db.one(
    'SELECT repository, tag, digest, upstream, moved_at, checked_at, moves FROM oci_tags WHERE repository = ? AND tag = ?',
    [repository, tag]
  );
}

function forRepository(repository) {
  return db.query(
    'SELECT tag, digest, checked_at, moved_at, moves FROM oci_tags WHERE repository = ? ORDER BY tag',
    [repository]
  );
}

// the tag still points where it did: only the check time moves
async function touch(repository, tag) {
  await db.query('UPDATE oci_tags SET checked_at = NOW() WHERE repository = ? AND tag = ?', [repository, tag]);
}

// a new tag, or one that now points somewhere else. moves counts how often that has happened
async function point(repository, tag, digest, upstream) {
  const result = await db.query(
    `INSERT INTO oci_tags (repository, tag, digest, upstream, moved_at, checked_at, moves)
     VALUES (?, ?, ?, ?, NOW(), NOW(), 0)
     ON DUPLICATE KEY UPDATE
       moves = moves + IF(digest = VALUES(digest), 0, 1),
       moved_at = IF(digest = VALUES(digest), moved_at, NOW()),
       upstream = VALUES(upstream),
       checked_at = NOW(),
       digest = VALUES(digest)`,
    [repository, tag, digest, upstream || null]
  );
  if (result.affectedRows) await require('./oci-refs').recordTagDigest(repository, tag, digest);
  // 1 = inserted, 2 = changed, 0 = the same digest again
  return { created: result.affectedRows === 1, moved: result.affectedRows === 2 };
}

// a push naming a tag. the first push wins it; after that only the same digest again, or a tag allowed to move (latest).
// a tag fetched from an upstream before the name was reserved is taken over. was = where it points when refused
async function pushTo(repository, tag, digest, source, { movable }) {
  const inserted = await db.query(
    `INSERT IGNORE INTO oci_tags (repository, tag, digest, upstream, moved_at, checked_at, moves)
     VALUES (?, ?, ?, ?, NOW(), NOW(), 0)`,
    [repository, tag, digest, source]
  );
  if (inserted.affectedRows !== 1) {
    const now = await get(repository, tag);
    if (!now || (now.digest === digest && now.upstream === source)) return { ok: !!now, created: false, moved: false };
    // only from where it was just read, so two pushes racing for one tag can not both win
    const changed = await db.query(
      `UPDATE oci_tags SET moves = moves + IF(digest = ?, 0, 1), moved_at = IF(digest = ?, moved_at, NOW()),
         digest = ?, upstream = ?, checked_at = NOW()
       WHERE repository = ? AND tag = ? AND digest = ? AND (upstream IS NULL OR upstream <> ? OR ? = 1)`,
      [digest, digest, digest, source, repository, tag, now.digest, source, movable ? 1 : 0]
    );
    if (changed.affectedRows !== 1) return { ok: false, was: now.digest };
    await require('./oci-refs').recordTagDigest(repository, tag, digest);
    return { ok: true, created: false, moved: now.digest !== digest };
  }
  await require('./oci-refs').recordTagDigest(repository, tag, digest);
  return { ok: true, created: true, moved: false };
}

function forget(repository, tag) {
  return tag
    ? db.query('DELETE FROM oci_tags WHERE repository = ? AND tag = ?', [repository, tag])
    : db.query('DELETE FROM oci_tags WHERE repository = ?', [repository]);
}

module.exports = { get, forRepository, touch, point, pushTo, forget };
