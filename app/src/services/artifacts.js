// Cached files: listing them, checking their bytes and provenance, throwing one away.
// Author: Tim Rice

const cache = require('../registry/npm/cache');
const artifacts = require('../storage/artifacts');
const artifactstore = require('../storage');
const artifactbackfill = require('../storage/backfill');
const provenance = require('../policy/provenance');
const pypiupstream = require('../registry/pypi/upstream');
const log = require('../logger');
const auth = require('../security/auth');
const repo = require('../db/repositories/artifacts');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { idParam } = require('../lib/validate');

const targetOf = (row) => `${row.ecosystem}:${row.package_name}:${row.filename}`;

// canSeeErrors: backfill error text can have file paths in it
async function list(filters, paging, canSeeErrors) {
  const { rows, total, bytes } = await repo.page(filters, paging);
  const blobs = await repo.blobTotals();
  const backfill = artifactbackfill.status();
  if (!canSeeErrors) backfill.errors = [];
  return { artifacts: rows, total, bytes, blobs, backfill };
}

async function get(id) {
  const row = await artifacts.byId(id);
  if (!row) fail(404, 'there is no such artifact');
  return row;
}

async function detail(id) {
  const row = await get(id);
  const blob = await artifactstore.stat(row.sha256);
  const ledger = await repo.blobLedger(row.sha256);
  const sharedWith = await repo.sharedCount(row.sha256, row.id);
  const integrity = await repo.integrityAlerts(row);
  const holds = await repo.holds(row);
  const scans = await repo.scans(row.sha256);
  const prov = await repo.provenanceFor(row);
  let attestation = null;
  try {
    attestation = prov && prov.attestation ? JSON.parse(prov.attestation) : null;
  } catch (err) {
    attestation = null;
  }
  return {
    artifact: { ...row, metadata: artifacts.parseMeta(row.metadata) },
    blob: {
      present: !!blob && blob.size === Number(row.size),
      createdAt: ledger ? ledger.created_at : null,
      verifiedAt: ledger ? ledger.verified_at : null
    },
    sharedWith,
    integrity,
    holds,
    scans,
    provenance: prov ? { ...prov, attestation, stale: prov.sha256 !== row.sha256 } : null,
    // what applies to this version, its own first, then its package's
    properties: await require('./properties').effective(row.ecosystem, row.package_name, row.version)
  };
}

// ask the registry for this file's provenance now instead of waiting for the background check
// throttled before the id is even looked at
async function checkProvenance(actor, rawId) {
  const limited = await auth.rateLimit(`provenance:${actor.id}`, 30, 60000);
  if (!limited.ok) fail(429, 'that is a lot of provenance checks, give it a minute');
  const row = await get(idParam(rawId));
  let result;
  try {
    result = await provenance.checkAndRecord(row);
  } catch (err) {
    if (!err.transient) log.error(`provenance check on ${row.package_name} failed`, err.message);
    fail(503, err.transient ? err.message : 'provenance could not be checked right now');
  }
  await audit(actor, 'provenance.check', targetOf(row), `${result.status}: ${result.reason || ''}`.slice(0, 1000));
  return result;
}

// reads the whole file back, so one at a time
let verifying = false;

async function verify(actor, id) {
  const row = await get(id);
  if (verifying) fail(429, 'another check is still reading its file, try again in a moment');
  verifying = true;
  let ok = false;
  try {
    ok = await artifactstore.verify(row.sha256);
  } finally {
    verifying = false;
  }
  const target = targetOf(row);
  if (ok) {
    await repo.markVerified(row.sha256);
  } else {
    // bad bytes don't get served. next download has to hash right
    log.error(`blob for ${target} does not hash to ${row.sha256} or is missing, removing it`);
    await artifactstore.remove(row.sha256);
  }
  await audit(actor, 'artifact.verify', target, ok ? 'matches' : 'did not match, blob removed');
  return ok;
}

async function purge(actor, id) {
  const row = await get(id);
  if (row.ecosystem === 'npm') await cache.dropTarball(row.package_name, row.version);
  else if (row.ecosystem === 'pypi') await pypiupstream.dropFile(row.package_name, row.filename);
  await artifacts.forgetFile(row.ecosystem, row.package_name, row.filename);
  await audit(actor, 'cache.purge.artifact', targetOf(row), row.sha256);
}

module.exports = { list, get, detail, checkProvenance, verify, purge };
