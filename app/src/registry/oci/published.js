// Images pushed here. A reserved repository is only ever what was pushed to this box, never a copy from an upstream, so
// nobody can put the same name on Docker Hub and have it pulled instead (dependency confusion, image edition).
// Author: Tim Rice
//
// a pushed image is not pulled until every blob it names came back clean from the malware scan. that holds in both
// quarantine modes: permissive is for things fetched from outside that people already relied on, a push is brand new

const artifacts = require('../../storage/artifacts');
const privateNames = require('../../policy/private-names');
const quarantine = require('../../policy/quarantine');
const published = require('../shared/published');
const tags = require('../../db/repositories/oci-tags');
const kept = require('../../db/repositories/oci-manifests');
const { httpError } = require('../../lib/errors');

// the reserved entry covering any name the image goes by, or null
async function reservedBy(names) {
  for (const name of names) {
    const hit = await privateNames.reservedBy('oci', name);
    if (hit) return hit;
  }
  return null;
}

function notHere(repository, reference, hit) {
  const what = reference ? `${repository}${String(reference).startsWith('sha256:') ? '@' : ':'}${reference}` : repository;
  const e = httpError(404, `${what} is reserved (${hit.pattern}) for images pushed to this registry, and nothing like that was pushed here. It is never fetched from an upstream`);
  e.reserved = true;
  return e;
}

// a manifest by tag or digest, from what was pushed and nothing else
async function manifest(repository, reference, hit, fromKept) {
  let digest = reference;
  if (!String(reference).startsWith('sha256:')) {
    const pointer = await tags.get(repository, reference);
    if (!pointer || pointer.upstream !== published.SOURCE) throw notHere(repository, reference, hit);
    digest = pointer.digest;
  }
  const row = await kept.get(repository, digest);
  if (!row || row.upstream !== published.SOURCE) throw notHere(repository, reference, hit);
  const got = fromKept(row);
  if (!got) throw notHere(repository, reference, hit);
  return { ...got, upstream: published.SOURCE, moved: false };
}

// a layer or config blob. the bytes are addressed by their hash, so whoever stored them first they are the same bytes
async function blob(repository, digest, hit) {
  const held = await artifacts.locate('oci', repository, '', digest);
  if (!held) throw notHere(repository, digest, hit);
  return { artifactId: held.id, sha256: held.sha256, size: held.size, cacheHit: true };
}

// why a pushed blob can not go out yet, or null. rejected is a no, a hold still waiting on its scan is a try again
async function blobWaiting(repository, digest) {
  const v = await quarantine.verdict('oci', repository, '', digest);
  if (!v) return null;
  if (/^rejected/.test(v.reason)) return { status: 403, reason: v.reason };
  // the hold every push starts under, see shared/published.js. any other hold is a finding, and says so
  if (v.source === 'malware' && v.reason.includes(published.WAITING_SCAN)) {
    // a scanner that could not answer (down, timed out) is asked again, so the try again below comes true once it is back
    const malware = require('../../malware');
    const problem = await malware.scanProblem(digest.slice(7)).catch(() => null);
    if (problem && problem.tooBig) {
      return { status: 403, reason: `${digest} is larger than the malware scanner accepts, so it can not be scanned. An admin can raise the scanner's limit, or release it under Quarantine` };
    }
    if (problem) {
      malware.enqueue(digest.slice(7));
      return { status: 429, reason: `the malware scan of ${digest} could not finish (${problem.scanner}: ${problem.finding}), it is being tried again. Try again in a few minutes` };
    }
    return { status: 429, reason: `${digest} was pushed a moment ago and is still being scanned for malware. Try again in a few minutes` };
  }
  if (v.source === 'publish') {
    return { status: 403, reason: `${digest} was pushed while malware scanning is off, and waits in quarantine until an admin releases it` };
  }
  return { status: 403, reason: v.reason };
}

// the first blob of a pushed image that can not go out yet. a list is only a list, each platform image is asked for itself
async function imageWaiting(repository, doc) {
  const blobs = [...(doc && doc.config ? [doc.config] : []), ...(doc && Array.isArray(doc.layers) ? doc.layers : [])];
  for (const b of blobs) {
    if (!b || typeof b.digest !== 'string') continue;
    const why = await blobWaiting(repository, b.digest);
    if (why) return why;
  }
  return null;
}

module.exports = { reservedBy, notHere, manifest, blob, blobWaiting, imageWaiting };
