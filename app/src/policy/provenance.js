// Provenance. where a cached file says it was built, and whether that holds up.
// Author: Tim Rice
// one model for npm, PyPI and later OCI: VERIFIED, PRESENT_UNVERIFIED, MISSING or INVALID per file.
// VERIFIED only when a Sigstore attestation checks out against the pinned root AND names the exact bytes
// we hold AND the signing certificate agrees with what the attestation says about the source

const db = require('../db');
const log = require('../logger');
const provenanceRepo = require('../db/repositories/provenance');
const artifactsRepo = require('../db/repositories/artifacts');
const sigstore = require('../security/sigstore');
const safefetch = require('../security/safefetch');

const STATUSES = ['VERIFIED', 'PRESENT_UNVERIFIED', 'MISSING', 'INVALID'];
const SLSA = ['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2'];
const MAX_ATTESTATION_BYTES = 5 * 1024 * 1024;
const KEEP_ATTESTATION_BYTES = 256 * 1024;
const BATCH = 50;

function mode() {
  const m = String(db.settings.get('provenance_invalid') || 'warn');
  return ['warn', 'hold'].includes(m) ? m : 'warn';
}

// could not get an answer this time. nothing is recorded, it is asked again later
function transient(message) {
  const e = new Error(message);
  e.transient = true;
  return e;
}

const clip = (v, n) => (v === undefined || v === null || v === '' ? null : String(v).slice(0, n));

function keep(obj) {
  const text = JSON.stringify(obj);
  return Buffer.byteLength(text) <= KEEP_ATTESTATION_BYTES ? text : null;
}

async function fetchJson(url, headers, accept) {
  let res;
  try {
    res = await safefetch.request(url, { headers: { accept, ...(headers || {}) }, timeoutMs: 30000, maxBytes: MAX_ATTESTATION_BYTES });
  } catch (err) {
    throw transient(`the attestation could not be fetched: ${err.code === 'EADDRNOTALLOWED' ? err.message : 'the registry did not answer'}`);
  }
  if (res.status === 404) return null;
  if (!res.ok) throw transient(`the registry answered ${res.status} for the attestation`);
  try {
    return await res.json();
  } catch (err) {
    throw transient('the registry sent an attestation that is not JSON');
  }
}

const sameOrigin = (a, b) => {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch (err) {
    return false;
  }
};

// ---------------------------------------------------------------- npm

// a name that isn't valid percent encoding is compared as it is, and so matches nothing it shouldn't
function safeDecode(text) {
  try {
    return decodeURIComponent(text);
  } catch (err) {
    return text;
  }
}

function npmPurl(name, version) {
  return `pkg:npm/${name.replace(/^@/, '%40')}@${version}`;
}

async function checkNpm(a) {
  const upstreams = require('../registry/shared/upstreams');
  const upstream = require('../registry/npm/upstream');
  const up = await upstreams.forPackage(a.package_name, 'npm').catch(() => { throw transient('the registry list could not be read'); });
  if (!up) throw transient('no registry serves it any more');
  let doc;
  try {
    ({ doc } = await upstream.getPackument(a.package_name, 'full'));
  } catch (err) {
    throw transient('the registry did not answer for its metadata');
  }
  const v = doc && doc.versions && doc.versions[a.version];
  if (!v) return { status: 'MISSING', reason: 'the registry no longer lists this version' };
  const dist = v.dist || {};
  const ours = (JSON.parse(a.metadata || '{}') || {}).integrity || dist.integrity;
  const registrySignature = sigstore.verifyRegistrySignature(a.package_name, a.version, { ...dist, integrity: ours }, doc.time && doc.time[a.version]).status;
  const url = dist.attestations && dist.attestations.url;
  if (!url) return { status: 'MISSING', registrySignature, reason: 'the package was published without provenance' };
  if (!sameOrigin(url, up.url)) {
    return { status: 'PRESENT_UNVERIFIED', registrySignature, reason: 'provenance is advertised, but hosted somewhere other than the registry, so it was not fetched' };
  }
  const headers = up.token ? { authorization: `Bearer ${up.token}` } : {};
  const body = await fetchJson(url, headers, 'application/json');
  const entry = body && Array.isArray(body.attestations) ? body.attestations.find((x) => SLSA.includes(x && x.predicateType)) : null;
  if (!entry) {
    return { status: 'PRESENT_UNVERIFIED', registrySignature, reason: body ? 'the registry has a publish attestation but no build provenance' : 'provenance is advertised but the registry does not have it' };
  }
  const b = entry.bundle || {};
  const vm = b.verificationMaterial || {};
  const env = b.dsseEnvelope || {};
  const certRaw = (vm.x509CertificateChain && vm.x509CertificateChain.certificates && vm.x509CertificateChain.certificates[0] && vm.x509CertificateChain.certificates[0].rawBytes)
    || (vm.certificate && vm.certificate.rawBytes);
  const base = { registrySignature, predicateType: entry.predicateType, attestation: keep(entry) };
  let got;
  try {
    got = sigstore.verifyDsse({
      certificate: Buffer.from(String(certRaw || ''), 'base64'),
      payloadType: env.payloadType,
      payload: Buffer.from(String(env.payload || ''), 'base64'),
      signature: Buffer.from(String((env.signatures && env.signatures[0] && env.signatures[0].sig) || ''), 'base64'),
      entry: vm.tlogEntries && vm.tlogEntries[0]
    });
  } catch (err) {
    if (!err.invalid) throw err;
    return { ...base, status: 'INVALID', reason: err.message };
  }
  const integrityHex = /^sha512-/.test(String(ours || '')) ? Buffer.from(ours.slice(7), 'base64').toString('hex') : null;
  if (!integrityHex || !sigstore.subjectMatches(got.statement, { sha512: integrityHex })) {
    return { ...base, status: 'INVALID', reason: 'the provenance is signed, but for different bytes than the file cached here' };
  }
  const want = safeDecode(npmPurl(a.package_name, a.version));
  if (!got.statement.subject.some((s) => s && typeof s === 'object' && safeDecode(String(s.name || '')) === want)) {
    return { ...base, status: 'INVALID', reason: 'the provenance is signed, but names a different package or version' };
  }
  const p = got.statement.predicate || {};
  const wf = ((p.buildDefinition || {}).externalParameters || {}).workflow || {};
  const dep = ((p.buildDefinition || {}).resolvedDependencies || [])[0] || {};
  const commit = (dep.digest || {}).gitCommit || null;
  const id = got.identity;
  // the certificate is what Sigstore checked, the predicate is what the build wrote. they must agree
  if ((wf.repository && id.sourceRepository && wf.repository !== id.sourceRepository) || (commit && id.sourceDigest && commit !== id.sourceDigest)) {
    return { ...base, status: 'INVALID', reason: 'the signing certificate and the provenance disagree about the source' };
  }
  return {
    ...base,
    status: 'VERIFIED',
    reason: 'build provenance verified against Sigstore',
    sourceRepository: id.sourceRepository || wf.repository || null,
    sourceCommit: id.sourceDigest || commit,
    sourceRef: id.sourceRef || wf.ref || null,
    workflow: id.buildConfig || (wf.path ? `${wf.repository}/${wf.path}` : null),
    builder: ((p.runDetails || {}).builder || {}).id || id.runnerEnvironment || null,
    issuer: id.issuer,
    subjectDigest: `sha512:${integrityHex}`,
    verifiedAt: got.integratedTime
  };
}

// ---------------------------------------------------------------- PyPI (PEP 740)

// what PyPI says the trusted publisher is has to be the identity the certificate was issued to
function publisherMatches(publisher, id) {
  if (!publisher || !publisher.repository) return true;
  const host = { GitHub: 'https://github.com/', GitLab: 'https://gitlab.com/' }[publisher.kind];
  if (!host) return true;
  return String(id.sourceRepository || '').toLowerCase() === `${host}${publisher.repository}`.toLowerCase();
}

async function checkPypi(a) {
  const pypiupstream = require('../registry/pypi/upstream');
  const upstreams = require('../registry/shared/upstreams');
  const up = await upstreams.forPackage(a.package_name, 'pypi').catch(() => { throw transient('the registry list could not be read'); });
  if (!up) throw transient('no registry serves it any more');
  let page;
  try {
    page = await pypiupstream.getProject(a.package_name);
  } catch (err) {
    throw transient('the registry did not answer for the project page');
  }
  const file = ((page && page.doc && page.doc.files) || []).find((f) => f.filename === a.filename);
  if (!file) return { status: 'MISSING', reason: 'the registry no longer lists this file' };
  // pages cached before provenance was read have no idea, so ask again once they refresh
  if (file.provenance === undefined) throw transient('the cached project page predates provenance, it is checked again once refreshed');
  if (!file.provenance) return { status: 'MISSING', reason: 'the file was uploaded without attestations' };
  if (!sameOrigin(file.provenance, pypiupstream.indexBase(up))) {
    return { status: 'PRESENT_UNVERIFIED', reason: 'attestations are advertised, but hosted somewhere other than the registry, so they were not fetched' };
  }
  const doc = await fetchJson(file.provenance, pypiupstream.headersFor(up, file.provenance), 'application/vnd.pypi.integrity.v1+json');
  const bundles = doc && Array.isArray(doc.attestation_bundles) ? doc.attestation_bundles : [];
  if (!bundles.length) return { status: 'PRESENT_UNVERIFIED', reason: 'attestations are advertised but the registry does not have them' };
  let firstProblem = null;
  for (const bundle of bundles) {
    if (!bundle || typeof bundle !== 'object') continue;
    for (const att of Array.isArray(bundle.attestations) ? bundle.attestations : []) {
      if (!att || typeof att !== 'object') continue;
      const vm = att.verification_material || {};
      const env = att.envelope || {};
      let got;
      try {
        got = sigstore.verifyDsse({
          certificate: Buffer.from(String(vm.certificate || ''), 'base64'),
          payloadType: sigstore.IN_TOTO,
          payload: Buffer.from(String(env.statement || ''), 'base64'),
          signature: Buffer.from(String(env.signature || ''), 'base64'),
          entry: (vm.transparency_entries || [])[0]
        });
      } catch (err) {
        if (!err.invalid) throw err;
        firstProblem = firstProblem || err.message;
        continue;
      }
      if (!sigstore.subjectMatches(got.statement, { sha256: a.sha256 }) || !got.statement.subject.some((s) => s && s.name === a.filename)) {
        firstProblem = firstProblem || 'the attestation is signed, but for a different file than the one cached here';
        continue;
      }
      if (!publisherMatches(bundle.publisher, got.identity)) {
        firstProblem = firstProblem || 'the signing certificate does not belong to the trusted publisher PyPI names';
        continue;
      }
      const pub = bundle.publisher || {};
      return {
        status: 'VERIFIED',
        reason: `attestation verified against Sigstore, published by ${pub.kind || 'a trusted publisher'}`,
        predicateType: got.statement.predicateType || null,
        sourceRepository: got.identity.sourceRepository,
        sourceCommit: got.identity.sourceDigest,
        sourceRef: got.identity.sourceRef,
        workflow: got.identity.buildConfig || (pub.workflow ? `${pub.repository}/${pub.workflow}` : null),
        builder: got.identity.runnerEnvironment || pub.kind || null,
        issuer: got.identity.issuer,
        subjectDigest: `sha256:${a.sha256}`,
        verifiedAt: got.integratedTime,
        attestation: keep(bundle)
      };
    }
  }
  return { status: 'INVALID', reason: firstProblem || 'no attestation verified', attestation: keep(bundles[0]) };
}

// ---------------------------------------------------------------- recording

// every file ends with a status. something tripping over what a registry or a publisher sent is INVALID, it used to be a
// throw that saved nothing, so the file stayed unchecked, was served, and a hold on invalid provenance never happened.
// only not reaching the registry or the database leaves it for later
async function check(a) {
  try {
    if (a.ecosystem === 'npm') return await checkNpm(a);
    if (a.ecosystem === 'pypi') return await checkPypi(a);
  } catch (err) {
    if (err.transient) throw err;
    return { status: 'INVALID', reason: `the provenance could not be read: ${String(err.message || err).slice(0, 180)}` };
  }
  return { status: 'MISSING', reason: 'provenance is not read for this kind of package yet' };
}

async function save(a, r) {
  await provenanceRepo.save({
    ecosystem: a.ecosystem, packageName: a.package_name, version: a.version || '', filename: a.filename, sha256: a.sha256, status: r.status,
    reason: clip(r.reason, 255), registrySignature: clip(r.registrySignature, 24), sourceRepository: clip(r.sourceRepository, 512),
    sourceCommit: clip(r.sourceCommit, 128), sourceRef: clip(r.sourceRef, 255), builder: clip(r.builder, 512), workflow: clip(r.workflow, 512),
    issuer: clip(r.issuer, 255), subjectDigest: clip(r.subjectDigest, 200), predicateType: clip(r.predicateType, 255), attestation: r.attestation || null,
    verifiedAt: r.verifiedAt ? new Date(r.verifiedAt).toISOString().slice(0, 19).replace('T', ' ') : null
  });
}

// hold (default), warn or off for a downgrade
function downgradeMode() {
  const m = String(db.settings.get('provenance_downgrade') || 'hold');
  return ['hold', 'warn', 'off'].includes(m) ? m : 'hold';
}

const repoKey = (url) => String(url || '').trim().toLowerCase().replace(/^git\+/, '').replace(/\.git$/, '').replace(/\/+$/, '');

function compareVersions(ecosystem, a, b) {
  if (ecosystem === 'npm') {
    const semver = require('semver');
    return semver.valid(a) && semver.valid(b) ? semver.compare(a, b) : null;
  }
  const pv = require('../ecosystems/pypi/version');
  return pv.valid(a) && pv.valid(b) ? pv.compare(a, b) : null;
}

// why this version is a step down from the ones before it, or null. only older versions count, so an old release
// from before the project took up provenance is not flagged
async function downgradeOf(a, r) {
  if (!['npm', 'pypi'].includes(a.ecosystem) || !a.version) return null;
  if (r.status !== 'MISSING' && r.status !== 'VERIFIED') return null;
  const older = (await provenanceRepo.verifiedVersions(a.ecosystem, a.package_name))
    .filter((v) => v.version !== a.version && compareVersions(a.ecosystem, v.version, a.version) < 0)
    .sort((x, y) => compareVersions(a.ecosystem, y.version, x.version));
  if (!older.length) return null;
  const last = older[0];
  if (r.status === 'MISSING') {
    return `${a.version} has no provenance, but ${last.version} came with verified provenance${last.source_repository ? ` from ${last.source_repository}` : ''}`;
  }
  if (r.sourceRepository && last.source_repository && repoKey(r.sourceRepository) !== repoKey(last.source_repository)) {
    return `${a.version} was built from ${r.sourceRepository}, but ${last.version} was built from ${last.source_repository}`;
  }
  return null;
}

async function applyDowngrade(a, r) {
  const how = downgradeMode();
  if (how === 'off') return;
  const why = await downgradeOf(a, r).catch(() => null);
  if (!why) return;
  const file = { ecosystem: a.ecosystem, packageName: a.package_name, version: a.version, filename: a.filename };
  log.warn(`provenance: ${a.ecosystem} ${a.package_name} ${a.filename} is a downgrade: ${why}`);
  require('../integrations/events').emit('policy.violation', {
    ecosystem: a.ecosystem, package: a.package_name, version: a.version, filename: a.filename, artifactHash: a.sha256,
    policy: 'provenance downgrade', reason: why, action: how === 'hold' ? 'held in quarantine' : 'recorded', severity: 'HIGH'
  });
  if (how === 'hold') {
    await require('./quarantine').hold(file, {
      source: 'downgrade', sha256: a.sha256,
      reason: `provenance downgrade: ${why}. A stolen publishing token looks like this. Release it once the maintainers confirm the release`
    });
  }
}

async function apply(a, r) {
  await applyDowngrade(a, r);
  if (r.status !== 'INVALID') return;
  const file = { ecosystem: a.ecosystem, packageName: a.package_name, version: a.version, filename: a.filename };
  log.warn(`provenance: ${a.ecosystem} ${a.package_name} ${a.filename} is INVALID: ${r.reason}`);
  require('../integrations/events').emit('policy.violation', {
    ecosystem: a.ecosystem, package: a.package_name, version: a.version, filename: a.filename, artifactHash: a.sha256,
    policy: 'provenance', reason: `provenance INVALID: ${r.reason}`, action: mode() === 'hold' ? 'held in quarantine' : 'recorded', severity: 'HIGH'
  });
  if (mode() === 'hold') {
    await require('./quarantine').hold(file, { source: 'provenance', reason: `provenance is invalid: ${r.reason}`, sha256: a.sha256 });
  }
}

async function checkAndRecord(a) {
  const r = await check(a);
  await save(a, r);
  await apply(a, r);
  // install-time code and manifest confusion, once per file like this
  await require('./release-checks').run(a);
  return r;
}

// ---------------------------------------------------------------- the background job

let running = false;
const nap = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// files never checked, plus unverified ones once a day in case the registry catches up
async function backfill() {
  if (running || !require('../registry/npm/upstream').upstreamEnabled()) return 0;
  running = true;
  let done = 0;
  try {
    const rows = await artifactsRepo.provenanceBacklog(BATCH);
    for (const a of rows) {
      try {
        await checkAndRecord(a);
        done += 1;
      } catch (err) {
        if (!err.transient) log.error(`provenance check on ${a.package_name} ${a.filename} failed`, err.message);
      }
      await nap(50);
    }
  } finally {
    running = false;
  }
  return done;
}

module.exports = { STATUSES, mode, downgradeMode, downgradeOf, applyDowngrade, check, checkNpm, checkPypi, checkAndRecord, backfill, publisherMatches, npmPurl };
