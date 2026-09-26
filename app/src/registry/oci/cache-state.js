// How much of an image this box really holds. A tag counts as cached only when every image in its list, and the
// config and every layer of each, is on disk. Knowing the manifest is not the same thing: walking the dependency tree
// learns that much without downloading a single layer.
// Author: Tim Rice

const db = require('../../db');
const ociName = require('../../ecosystems/oci/name');

// the same ceiling Cache now stops at, so "cached" means what Cache now can deliver
const MAX_PLATFORMS = 64;

// exact tags and digests a rule names, or null when it names none (empty, or a tag with a *)
function pinsOf(range) {
  const text = String(range || '').trim();
  if (!text) return null;
  const pins = text.split('||').map((p) => p.trim()).filter(Boolean);
  if (!pins.length || pins.some((p) => p.includes('*'))) return null;
  return pins;
}

// memo lives for one request, so a page of rules asks for each manifest once
function reader() {
  const docs = new Map();
  const manifest = async (repository, digest) => {
    const key = `${repository}@${digest}`;
    if (!docs.has(key)) {
      const row = await db.one('SELECT body FROM oci_manifests WHERE repository = ? AND digest = ?', [repository, digest]);
      let doc = null;
      try {
        doc = row ? JSON.parse(Buffer.isBuffer(row.body) ? row.body.toString('utf8') : String(row.body)) : null;
      } catch (err) {
        doc = null;
      }
      docs.set(key, doc);
    }
    return docs.get(key);
  };
  const digestOf = async (repository, reference) => {
    if (ociName.isDigest(reference)) return reference;
    const row = await db.one('SELECT digest FROM oci_tags WHERE repository = ? AND tag = ?', [repository, reference]);
    return row ? row.digest : null;
  };
  return { manifest, digestOf };
}

const blobsOf = (doc) => [...(doc && doc.config ? [doc.config] : []), ...(doc && Array.isArray(doc.layers) ? doc.layers : [])]
  .map((b) => b && b.digest).filter((d) => ociName.isDigest(d));

// { complete, images, completeImages } for one tag or digest
async function refState(repository, reference, read = reader()) {
  const none = { complete: false, images: 0, completeImages: 0 };
  const digest = await read.digestOf(repository, reference);
  if (!digest) return none;
  const top = await read.manifest(repository, digest);
  if (!top) return none;
  const list = Array.isArray(top.manifests);
  const children = list ? top.manifests.map((m) => m && m.digest).filter((d) => ociName.isDigest(d)).slice(0, MAX_PLATFORMS) : [digest];
  if (!children.length) return none;
  const images = [];
  for (const child of children) images.push(list ? await read.manifest(repository, child) : top);
  const wanted = [...new Set(images.flatMap((doc) => blobsOf(doc)))].map((d) => d.slice(7));
  const held = new Set();
  for (let i = 0; i < wanted.length; i += 500) {
    const part = wanted.slice(i, i + 500);
    const rows = await db.query(
      `SELECT DISTINCT sha256 FROM artifacts WHERE ecosystem = 'oci' AND sha256 IN (${part.map(() => '?').join(', ')})`, part
    );
    for (const r of rows) held.add(r.sha256);
  }
  const completeImages = images.filter((doc) => doc && blobsOf(doc).length && blobsOf(doc).every((d) => held.has(d.slice(7)))).length;
  // files = every manifest, config and layer one pull needs, so a half done image can say how far along it is
  const manifests = 1 + (list ? children.length : 0);
  const keptManifests = 1 + (list ? images.filter(Boolean).length : 0);
  return {
    complete: completeImages === children.length, images: children.length, completeImages,
    files: manifests + wanted.length + (list ? images.filter((d) => !d).length * 2 : 0), heldFiles: keptManifests + held.size
  };
}

// the rules page columns for image rules, worked out from what is on disk instead of what is known
async function annotate(rows) {
  const read = reader();
  for (const row of rows) {
    if (row.ecosystem !== 'oci') continue;
    row.cache_note = null;
    if (String(row.pattern).includes('*')) {
      row.cached_versions = null;
      row.cached_pins = null;
      row.pinned_versions = null;
      continue;
    }
    const pins = pinsOf(row.version_range);
    if (pins) {
      let have = 0;
      for (const pin of pins) {
        const s = await refState(row.pattern, pin, read);
        if (s.complete) have += 1;
        // how far along a half held image is. an image whose manifest isn't kept yet counts its unknown parts as missing
        else if (!row.cache_note && s.images) row.cache_note = `${pin}: ${s.heldFiles} of ${s.files} files downloaded`;
      }
      row.cached_pins = have;
      row.pinned_versions = pins.length;
      row.cached_versions = have;
    } else {
      const tags = await db.query('SELECT tag FROM oci_tags WHERE repository = ?', [row.pattern]);
      let have = 0;
      for (const t of tags) if ((await refState(row.pattern, t.tag, read)).complete) have += 1;
      row.cached_versions = have;
      row.cached_pins = null;
      row.pinned_versions = null;
    }
  }
  return rows;
}

// fully cached, or not, for the Cache filter. wildcards are never either, same as npm and PyPI
function fullyCached(row) {
  if (String(row.pattern).includes('*')) return null;
  if (row.pinned_versions) return Number(row.cached_pins) >= Number(row.pinned_versions);
  return Number(row.cached_versions) > 0;
}

module.exports = { MAX_PLATFORMS, pinsOf, refState, annotate, fullyCached };
