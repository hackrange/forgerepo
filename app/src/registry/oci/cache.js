// Dropping images from what this box keeps, for a kill switch purge: the manifests a kill covers, the platform images of a
// list it covers, and the layers nothing left behind still names.
// Author: Tim Rice

const db = require('../../db');
const artifacts = require('../../storage/artifacts');

// covered(reference) says whether a tag or digest is one the kill names. everything = null
async function dropImages(repository, covered) {
  const kept = await db.query('SELECT digest FROM oci_manifests WHERE repository = ?', [repository]);
  if (!covered) {
    const dropped = await artifacts.forgetPackage('oci', repository);
    await db.query('DELETE FROM oci_manifests WHERE repository = ?', [repository]);
    return dropped + kept.length;
  }
  const pointers = await db.query(
    'SELECT tag, digest FROM oci_tag_digests WHERE repository = ? UNION SELECT tag, digest FROM oci_tags WHERE repository = ?',
    [repository, repository]
  );
  const doomed = new Set();
  for (const m of kept) if (covered(m.digest)) doomed.add(m.digest);
  for (const p of pointers) if (covered(p.tag)) doomed.add(p.digest);
  // a list takes its platform images with it
  for (const d of [...doomed]) {
    for (const r of await db.query('SELECT child FROM oci_refs WHERE repository = ? AND parent = ?', [repository, d])) {
      if (kept.some((m) => m.digest === r.child)) doomed.add(r.child);
    }
  }
  if (!doomed.size) return 0;
  const list = [...doomed];
  const gone = await db.query(`DELETE FROM oci_manifests WHERE repository = ? AND digest IN (${list.map(() => '?').join(',')})`, [repository, ...list]);
  let dropped = gone.affectedRows || 0;
  // a layer another kept image still names stays
  const children = await db.query(
    `SELECT DISTINCT child FROM oci_refs WHERE repository = ? AND parent IN (${list.map(() => '?').join(',')})`, [repository, ...list]
  );
  for (const { child } of children) {
    const others = await db.query(
      `SELECT r.parent FROM oci_refs r JOIN oci_manifests m ON m.repository = r.repository AND m.digest = r.parent
        WHERE r.repository = ? AND r.child = ? LIMIT 1`, [repository, child]
    );
    if (others.length) continue;
    dropped += await artifacts.forgetFile('oci', repository, child);
  }
  return dropped;
}

module.exports = { dropImages };
