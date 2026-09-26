// Image manifests kept by digest. a digest names exactly one set of bytes, so a kept copy is as good as the registry's,
// and it is what lets an image be pulled with the upstream switched off or down.
// Author: Tim Rice

const db = require('../../db');

function get(repository, digest) {
  return db.one(
    'SELECT repository, digest, media_type, body, upstream, fetched_at FROM oci_manifests WHERE repository = ? AND digest = ?',
    [repository, digest]
  );
}

// first bytes win, a digest cannot mean anything else
async function put(repository, digest, mediaType, body, upstream) {
  await db.query(
    `INSERT IGNORE INTO oci_manifests (repository, digest, media_type, body, size, upstream)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [repository, digest, String(mediaType || '').slice(0, 255), body, body.length, upstream ? String(upstream).slice(0, 64) : null]
  );
}

// the same bytes pushed here after they were fetched from outside: they are ours now. a digest can not mean other bytes
async function claim(repository, digest, source) {
  await db.query('UPDATE oci_manifests SET upstream = ? WHERE repository = ? AND digest = ?', [source, repository, digest]);
}

async function anyFor(repository) {
  return !!(await db.one('SELECT 1 AS x FROM oci_manifests WHERE repository = ? LIMIT 1', [repository]));
}

module.exports = { get, put, claim, anyFor };
