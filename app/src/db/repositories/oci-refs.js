// What an image names: the layers and config of a platform image, the platform images of a list. and every digest a
// tag has pointed at while this box was watching. these are what let an approved tag through without a rule per digest
// Author: Tim Rice

const db = require('../../db');

const MAX_CHILDREN = 1000;

// written only for a manifest that came from upstream with its digest checked and that was let through
async function recordChildren(repository, parent, children) {
  const list = [...new Set(children)].slice(0, MAX_CHILDREN);
  if (!list.length) return;
  await db.query(
    `INSERT IGNORE INTO oci_refs (repository, child, parent) VALUES ${list.map(() => '(?, ?, ?)').join(', ')}`,
    list.flatMap((child) => [repository, child, parent])
  );
}

function parentsOf(repository, child) {
  return db.query('SELECT parent FROM oci_refs WHERE repository = ? AND child = ? LIMIT 50', [repository, child])
    .then((rows) => rows.map((r) => r.parent));
}

async function recordTagDigest(repository, tag, digest) {
  await db.query('INSERT IGNORE INTO oci_tag_digests (repository, tag, digest) VALUES (?, ?, ?)', [repository, tag, digest]);
}

// every tag that points, or has pointed, at this digest
function tagsFor(repository, digest) {
  return db.query(
    `SELECT tag FROM oci_tag_digests WHERE repository = ? AND digest = ?
     UNION SELECT tag FROM oci_tags WHERE repository = ? AND digest = ? LIMIT 100`,
    [repository, digest, repository, digest]
  ).then((rows) => rows.map((r) => r.tag));
}

module.exports = { MAX_CHILDREN, recordChildren, parentsOf, recordTagDigest, tagsFor };
