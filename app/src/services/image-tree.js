// What an image is made of, for the dependency tree: the tag, the digest it points at, each platform image, their layers,
// and every package found inside them with what is known against it.
// Author: Tim Rice
//
// reading manifests is cheap and done every time. opening layers is not: a scan is only started by someone who can decide
// on images, a developer sees what has already been found

const ociName = require('../ecosystems/oci/name');
const ecosystems = require('../ecosystems');
const policy = require('../policy');
const killswitch = require('../policy/killswitch');
const upstream = require('../registry/oci/upstream');
const scans = require('../db/repositories/image-scans');
const scanner = require('../images/scanner');
const { fail } = require('../lib/errors');

const MAX_PLATFORMS = 32;
const MAX_PACKAGES = 2000;
const RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, unrated: 0 };

function platformOf(entry) {
  const p = (entry && entry.platform) || {};
  const text = [p.os, p.architecture, p.variant].filter((x) => typeof x === 'string' && x).join('/');
  return text || 'unknown';
}

// attestations ride along in a list as unknown/unknown with this annotation, they are not something that runs
function isAttestation(entry) {
  const a = (entry && entry.annotations) || {};
  return typeof a['vnd.docker.reference.type'] === 'string' || platformOf(entry) === 'unknown/unknown';
}

async function platformNode(repository, got, label, { scan }) {
  const doc = got.doc || {};
  const layers = (Array.isArray(doc.layers) ? doc.layers : [])
    .filter((l) => l && ociName.isDigest(l.digest))
    .map((l) => ({ digest: l.digest, size: Number.isSafeInteger(l.size) ? l.size : null, mediaType: String(l.mediaType || '') }));
  const row = await scans.byKey(repository, got.digest);
  let queued = false;
  if (scan && scanner.enabled() && layers.length && (!row || row.status === 'failed')) {
    queued = scanner.queue(repository, got.digest, { force: true });
  }
  const node = {
    platform: label,
    digest: got.digest,
    layers,
    bytes: layers.reduce((n, l) => n + (l.size || 0), 0),
    scan: row ? scans.withNotes(row) : null,
    queued,
    packages: []
  };
  if (row && row.status === 'done') {
    node.packages = (await scans.components(row.id, { limit: MAX_PACKAGES })).sort((a, b) =>
      (b.advisories ? 1 : 0) - (a.advisories ? 1 : 0) || (RANK[b.severity] || 0) - (RANK[a.severity] || 0) || a.name.localeCompare(b.name));
  }
  return node;
}

async function tree(type, repository, reference, { scope, canScan, scan }) {
  const ref = String(reference || 'latest').trim() || 'latest';
  if (!ociName.validTag(ref) && !ociName.isDigest(ref)) fail(400, 'an image tree starts from one tag or digest, like latest or sha256:...');
  const adapter = ecosystems.adapter('oci');
  const verdict = await policy.checkVersion(repository, ref, adapter, scope);
  const dead = await killswitch.check('oci', repository, ref);

  let top;
  try {
    top = await upstream.getManifest(repository, ref);
  } catch (err) {
    fail(err.status === 404 ? 404 : err.status || 502, err.message);
  }
  const doc = top.doc || {};
  const platforms = [];
  const skipped = [];
  if (Array.isArray(doc.manifests)) {
    for (const entry of doc.manifests.slice(0, MAX_PLATFORMS)) {
      if (!entry || !ociName.isDigest(entry.digest)) continue;
      if (isAttestation(entry)) {
        skipped.push({ digest: entry.digest, why: 'an attestation, not an image that runs' });
        continue;
      }
      const child = await upstream.getManifest(repository, entry.digest);
      platforms.push(await platformNode(repository, child, platformOf(entry), { scan: scan && canScan }));
    }
    if (doc.manifests.length > MAX_PLATFORMS) skipped.push({ digest: null, why: `${doc.manifests.length - MAX_PLATFORMS} more platform images were left off` });
  } else {
    platforms.push(await platformNode(repository, top, 'single platform', { scan: scan && canScan }));
  }

  const scanned = platforms.filter((p) => p.scan && p.scan.status === 'done');
  const summary = {
    platforms: platforms.length,
    layers: platforms.reduce((n, p) => n + p.layers.length, 0),
    bytes: platforms.reduce((n, p) => n + p.bytes, 0),
    scanned: scanned.length,
    waiting: platforms.filter((p) => p.queued || (p.scan && ['queued', 'scanning'].includes(p.scan.status))).length,
    packages: scanned.reduce((n, p) => n + p.packages.length, 0),
    vulnerable: scanned.reduce((n, p) => n + p.packages.filter((c) => c.advisories).length, 0)
  };
  return {
    ecosystem: 'oci',
    image: true,
    root: `${repository}${ociName.isDigest(ref) ? '@' : ':'}${ref}`,
    repository,
    digest: top.digest,
    list: Array.isArray(doc.manifests),
    allowed: verdict.allowed && !dead,
    reason: dead ? dead.reason : verdict.reason,
    scanning: scanner.enabled(),
    canScan: !!canScan && scanner.enabled(),
    platforms,
    skipped,
    summary
  };
}

module.exports = { tree, _internal: { platformOf, isAttestation } };
