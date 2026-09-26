// Image signatures: which repositories need a cosign signature, from whom, and whether an image has one.
// Author: Tim Rice
//
// a trust policy names repositories (exact, acme/*, or a prefix*) and who may sign them: public keys, keyless signer
// identities, or both. require refuses an image nobody trusted signed, warn lets it through and says so in the log.
// the signature is fetched from wherever the image comes from (the .sig tag next to it) and kept like any other
// manifest, so the answer holds offline too. a signed list covers the platform images it names

const crypto = require('crypto');
const db = require('../db');
const sigstore = require('./sigstore');
const artifacts = require('../storage/artifacts');
const refs = require('../db/repositories/oci-refs');
const log = require('../logger');

const MAX_PAYLOAD = 64 * 1024;
const RETRY_MS = 10 * 60 * 1000; // a failure is asked again after this, someone may have signed it since
const CACHE_MS = 30000;
// cosign's own artifacts next to an image: signatures, attestations, sboms, and the referrers fallback tag the
// newer cosign writes bundles to. nothing to sign there
const COSIGN_TAG = /^sha256-[0-9a-f]{64}(\.(sig|att|sbom))?$/;
const MAX_BUNDLES = 10;

let cached = null;
let cachedAt = 0;

function invalidate() {
  cached = null;
}

function parseSigners(text) {
  try {
    const s = JSON.parse(text || '{}');
    return { keys: Array.isArray(s.keys) ? s.keys : [], identities: Array.isArray(s.identities) ? s.identities : [], requireLog: !!s.requireLog };
  } catch (err) {
    return { keys: [], identities: [], requireLog: false };
  }
}

async function policies() {
  if (cached && Date.now() - cachedAt < CACHE_MS) return cached;
  const rows = await db.query('SELECT id, pattern, mode, signers, note, created_by, created_at FROM image_trust ORDER BY pattern');
  cached = rows.map((r) => ({ ...r, trust: parseSigners(r.signers), hash: crypto.createHash('sha256').update(`${r.mode}\n${r.signers}`).digest('hex') }));
  cachedAt = Date.now();
  return cached;
}

// exact beats a namespace, a longer prefix beats a shorter one
function matches(pattern, repository) {
  if (pattern === repository) return 3000;
  if (pattern.endsWith('/*')) return repository.startsWith(pattern.slice(0, -1)) ? 2000 + pattern.length : 0;
  if (pattern.endsWith('*')) return repository.startsWith(pattern.slice(0, -1)) ? 1000 + pattern.length : 0;
  return 0;
}

async function policyFor(repository) {
  let best = null;
  let score = 0;
  for (const p of await policies()) {
    const s = matches(p.pattern, repository);
    if (s > score) {
      best = p;
      score = s;
    }
  }
  return best;
}

async function remembered(repository, digest, hash) {
  const row = await db.one('SELECT ok, signer, detail, checked_at FROM image_signatures WHERE repository = ? AND digest = ? AND trust_hash = ?', [repository, digest, hash]);
  if (!row) return null;
  if (!row.ok && Date.now() - new Date(row.checked_at).getTime() > RETRY_MS) return null;
  return { ok: !!row.ok, signer: row.signer, reasons: row.detail ? [row.detail] : [] };
}

function remember(repository, digest, hash, verdict) {
  return db.query(
    `INSERT INTO image_signatures (repository, digest, trust_hash, ok, signer, detail, checked_at) VALUES (?, ?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE ok = VALUES(ok), signer = VALUES(signer), detail = VALUES(detail), checked_at = NOW()`,
    [repository, digest, hash, verdict.ok ? 1 : 0, verdict.signer ? String(verdict.signer).slice(0, 512) : null, verdict.ok ? null : verdict.reasons.join('; ').slice(0, 1000)]
  ).catch((err) => log.warn(`could not remember the signature check of ${repository}@${digest}`, err.message));
}

// the .sig manifest and its payloads, from the same place the image comes from
async function fetchSignature(repository, digest) {
  const upstream = require('../registry/oci/upstream');
  let sig;
  try {
    sig = await upstream.getManifest(repository, sigstore.sigTag(digest));
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
  const doc = sig && sig.doc;
  const payloads = new Map();
  for (const layer of (doc && Array.isArray(doc.layers) ? doc.layers : []).filter((l) => l && l.mediaType === sigstore.SIMPLE_SIGNING).slice(0, 20)) {
    if (!/^sha256:[0-9a-f]{64}$/.test(String(layer.digest)) || !(Number(layer.size) > 0 && Number(layer.size) <= MAX_PAYLOAD)) continue;
    const got = await upstream.getBlob(repository, layer.digest);
    payloads.set(layer.digest, await artifacts.readAll({ sha256: got.sha256 }));
  }
  return { doc, payloads };
}

// the newer layout: a referrers index next to the image, each entry a manifest whose layer is a Sigstore bundle
async function fetchBundles(repository, digest) {
  const upstream = require('../registry/oci/upstream');
  let top;
  try {
    top = await upstream.getManifest(repository, sigstore.bundleTag(digest));
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
  const entries = (top && top.doc && Array.isArray(top.doc.manifests) ? top.doc.manifests : [])
    .filter((e) => e && /^sha256:[0-9a-f]{64}$/.test(String(e.digest))).slice(0, MAX_BUNDLES);
  const manifests = [];
  const blobs = new Map();
  for (const e of entries) {
    const child = await upstream.getManifest(repository, e.digest).catch(() => null);
    const doc = child && child.doc;
    if (!doc || !Array.isArray(doc.layers)) continue;
    manifests.push(doc);
    for (const layer of doc.layers.filter((l) => l && sigstore.BUNDLE_TYPE.test(String(l.mediaType)))) {
      if (!/^sha256:[0-9a-f]{64}$/.test(String(layer.digest)) || !(Number(layer.size) > 0 && Number(layer.size) <= MAX_PAYLOAD)) continue;
      const got = await upstream.getBlob(repository, layer.digest);
      blobs.set(layer.digest, await artifacts.readAll({ sha256: got.sha256 }));
    }
  }
  return manifests.length ? { manifests, blobs } : null;
}

async function verifyDigest(repository, digest, policy) {
  const known = await remembered(repository, digest, policy.hash);
  if (known) return known;
  let verdict;
  try {
    const found = await fetchSignature(repository, digest);
    verdict = found ? sigstore.verify({ digest, sig: found.doc, payloads: found.payloads, trust: policy.trust }) : { ok: false, reasons: [] };
    // cosign 3 writes a bundle under the referrers tag instead
    if (!verdict.ok) {
      const bundles = await fetchBundles(repository, digest);
      const second = bundles ? sigstore.verifyBundles({ digest, manifests: bundles.manifests, blobs: bundles.blobs, trust: policy.trust }) : { ok: false, reasons: [] };
      if (second.ok) verdict = second;
      else verdict = { ok: false, reasons: [...verdict.reasons, ...second.reasons].length ? [...verdict.reasons, ...second.reasons] : ['it is not signed'] };
    }
  } catch (err) {
    // the signature could not be fetched this time. not remembered, the next pull asks again
    return { ok: false, reasons: [`its signature could not be fetched: ${err.message}`], transient: true };
  }
  await remember(repository, digest, policy.hash, verdict);
  return verdict;
}

/**
 * whether a manifest about to be served is signed as its repository's trust policy asks.
 * @returns {Promise<null | { ok: boolean, mode: string, signer?: string, reason: string }>} null = no policy covers it
 */
async function check(repository, digest, reference) {
  const policy = await policyFor(repository);
  if (!policy) return null;
  if (reference && COSIGN_TAG.test(reference)) return null;
  let verdict = await verifyDigest(repository, digest, policy);
  // a platform image is covered by a signed list that names it
  if (!verdict.ok) {
    for (const parent of await refs.parentsOf(repository, digest)) {
      const up = await remembered(repository, parent, policy.hash);
      if (up && up.ok) {
        verdict = { ...up, signer: `${up.signer}, on the list that names it` };
        break;
      }
    }
  }
  const reason = verdict.ok
    ? `signed by ${verdict.signer}`
    : `${repository}@${digest} is not signed by anyone the trust policy for ${policy.pattern} names (${[...new Set(verdict.reasons)].slice(0, 3).join('; ') || 'no signature'})`;
  return { ok: verdict.ok, mode: policy.mode, signer: verdict.signer, reason };
}

module.exports = { check, policyFor, policies, invalidate, matches, parseSigners, COSIGN_TAG };
