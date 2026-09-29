// The /v2 side, aka what docker pull talks to.
// Author: Tim Rice
//
// rules decide the repository, the kill switch and quarantine decide the exact bytes, and a tag is only ever a pointer:
// everything served is addressed by the digest the manifest named

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const policy = require('../../policy');
const killswitch = require('../../policy/killswitch');
const quarantine = require('../../policy/quarantine');
const ecosystems = require('../../ecosystems');
const ociName = require('../../ecosystems/oci/name');
const artifacts = require('../../storage/artifacts');
const tags = require('../../db/repositories/oci-tags');
const refs = require('../../db/repositories/oci-refs');
const upstream = require('./upstream');
const gate = require('./gate');
const serving = require('../shared/serving');
const shared = require('../shared/requests');
const imageScanner = require('../../images/scanner');
const signatures = require('../../images/signatures');
const privateNames = require('../../policy/private-names');
const published = require('../shared/published');
const pushed = require('./published');
const push = require('./push');
const { OURS, record, fail, challenge, bearerChallenge, looksLikeOciClient, auditOnly } = require('./respond');
const { wrap } = require('../../lib/http');

const router = express.Router();
const adapter = () => ecosystems.adapter('oci');

// anything not under /v2 belongs to npm, including a package called v2
router.use((req, res, next) => {
  if (!OURS.test(req.path)) return next('router');
  if (!db.settings.getBool('oci_enabled')) return next('router');
  return next();
});

// who is asking. docker tries anonymously first and reads the challenge to find out how to authenticate
router.use(wrap(async (req, res, next) => {
  req.startedAt = Date.now();
  const raw = auth.registryCredential(req);
  if (raw) {
    const token = req.npmIdentity || (await auth.lookupToken(raw));
    if (token) {
      req.npmIdentity = token;
      auth.touchToken(token.id, auth.clientIp(req)).catch(() => {});
    } else if (db.settings.getBool('require_auth')) {
      record(req, { action: 'deny', status: 401, reason: 'bad token' });
      return challenge(req, res, 'that token is not valid on this registry');
    }
  } else if (db.settings.getBool('require_auth')) {
    record(req, { action: 'deny', status: 401, reason: 'no token' });
    return challenge(req, res, 'this registry needs a token: docker login with your username and the token as the password');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeOciClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return fail(res, 'NAME_UNKNOWN', 'not found');
  }
  return next();
}));

// the handshake every client starts with. docker only sends its login to a registry that asked for one here, so with
// image names reserved for pushing, a ping without a token is asked for one. pulls without a login still work after it
router.get(/^\/v2\/?$/, wrap(async (req, res) => {
  res.set('docker-distribution-api-version', 'registry/2.0');
  if (!req.npmIdentity && (await privateNames.anyFor('oci'))) {
    record(req, { action: 'allow', status: 401, reason: 'ping, told how to log in' });
    return bearerChallenge(req, res, 'log in to push here: docker login with your username and a token as the password');
  }
  record(req, { action: 'allow', reason: 'ping' });
  return res.json({});
}));

// where the challenge above sends docker. a good login gets a five minute bearer for it, no login an anonymous one that
// pulls like no login always did. a login that is wrong is a no, so docker login says so
router.get(/^\/v2\/token\/?$/, wrap(async (req, res) => {
  res.set('cache-control', 'no-store');
  if (auth.registryCredential(req) && !req.npmIdentity) {
    record(req, { action: 'deny', status: 401, reason: 'bad token' });
    return challenge(req, res, 'that token is not valid on this registry');
  }
  if (!req.npmIdentity) {
    record(req, { action: 'allow', reason: 'anonymous bearer' });
    return res.json({ token: 'anonymous', access_token: 'anonymous', expires_in: 300, issued_at: new Date().toISOString() });
  }
  const given = await auth.issueBearer(req.npmIdentity);
  record(req, { action: 'allow', reason: `bearer for ${req.npmIdentity.username}` });
  return res.json({ token: given.token, access_token: given.token, expires_in: given.expiresIn, issued_at: new Date().toISOString() });
}));

// /v2/<name>/manifests|blobs|tags/... where the name itself holds slashes. on Docker Hub nginx and library/nginx are the
// same image, so they are one name here and the rules are asked about both
async function named(raw) {
  const folded = ociName.fold(raw);
  if (!ociName.valid(folded)) return null;
  const { name, aliases } = await upstream.canonicalName(folded);
  return { repository: name, aliases };
}

async function parse(path) {
  const m = /^\/v2\/(.+)\/(manifests|blobs|tags)\/(.+)$/.exec(path);
  if (!m) return null;
  let rest;
  try {
    rest = decodeURIComponent(m[3]);
  } catch (err) {
    return null;
  }
  const target = await named(m[1]);
  return target ? { ...target, kind: m[2], rest } : null;
}

// the rules, kill switches and stages, before anything is fetched. how a digest is judged lives in gate.js
async function allowed(req, res, asked, reference, options = {}) {
  const repository = asked.repository;
  const scope = policy.scopeOf(req);
  const verdict = await gate.decide(repository, reference || null, scope, { ...options, aliases: asked.aliases });
  if (!verdict.allowed && (verdict.killed || !auditOnly())) {
    record(req, {
      package_name: repository, version: reference || null, action: 'deny', status: 403, reason: verdict.reason,
      rule_id: verdict.rule && verdict.rule.id, blocked_by: verdict.killed ? 'killswitch' : undefined
    });
    // someone pulling a tag nobody approved yet is somebody to ask. a digest or a layer is not a thing to request
    if (reference && !ociName.isDigest(reference) && !verdict.killed && !(verdict.rule && verdict.rule.kind === 'deny')) {
      await shared.openRequest(req, repository, reference, verdict.reason, { ecosystem: 'oci', looksLikeClient: looksLikeOciClient(req) });
    }
    fail(res, 'DENIED', verdict.killed ? verdict.reason : refusal(repository, reference, verdict.reason));
    return false;
  }
  if (!verdict.allowed) {
    record(req, { package_name: repository, action: 'audit', reason: `would have blocked: ${verdict.reason}` });
    if (reference && !ociName.isDigest(reference)) {
      shared.openRequest(req, repository, reference, verdict.reason, { ecosystem: 'oci', looksLikeClient: looksLikeOciClient(req), source: 'learning' }).catch(() => {});
    }
  }
  return true;
}

// the same sentence npm and pip get, so a pipeline log says what to ask for and where
function refusal(repository, reference, reason) {
  const what = reference ? `${repository}${ociName.isDigest(reference) ? '@' : ':'}${reference}` : repository;
  const publicUrl = db.settings.get('public_url') || '';
  const where = db.settings.getBool('show_help_url') && publicUrl ? ` Ask for it at ${publicUrl}/_admin.` : ' Ask an approver to add it.';
  return `${what} is not approved on this registry. Reason: ${reason}.${where}${require('../../services/auto-approve').refusalHint('oci', reason)}`;
}

// a held image is refused in strict quarantine and warned about in permissive, the same as a held package
async function heldBack(req, res, repository, digest) {
  const verdict = await quarantine.verdict('oci', repository, '', digest);
  if (verdict && verdict.refuse) {
    record(req, { package_name: repository, version: digest, action: 'deny', status: 403, reason: verdict.reason, blocked_by: 'quarantine' });
    fail(res, 'DENIED', verdict.reason);
    return true;
  }
  return false;
}

// ---------------------------------------------------------------- docker push, the work is in push.js

const UPLOADS = /^\/v2\/(.+)\/blobs\/uploads\/?$/;
const UPLOAD = /^\/v2\/(.+)\/blobs\/uploads\/([^/]+)$/;

// which upload, of which repository. the id is only ever looked up together with its owner, see push.js
function upload(fn) {
  return wrap(async (req, res) => {
    const m = UPLOAD.exec(req.path);
    const target = m && (await named(m[1]));
    if (!target) return fail(res, 'NAME_INVALID', 'that is not a valid repository name');
    return fn(req, res, { ...target, kind: 'blobs', upload: m[2] });
  });
}

router.post(UPLOADS, wrap(async (req, res) => {
  const target = await named(UPLOADS.exec(req.path)[1]);
  if (!target) return fail(res, 'NAME_INVALID', 'that is not a valid repository name');
  return push.start(req, res, { ...target, kind: 'blobs' });
}));
router.patch(UPLOAD, upload(push.piece));
router.put(UPLOAD, upload(push.close));
router.get(UPLOAD, upload(push.status));
router.delete(UPLOAD, upload(push.cancel));

router.put(/^\/v2\/(.+)\/manifests\/(.+)$/, wrap(async (req, res) => {
  const asked = await parse(req.path);
  if (!asked) return fail(res, 'NAME_INVALID', 'that is not a valid repository name');
  return push.manifest(req, res, asked);
}));

// ---------------------------------------------------------------- pulls

router.get(/^\/v2\/(.+)\/manifests\/(.+)$/, wrap(async (req, res) => {
  const asked = await parse(req.path);
  if (!asked) return fail(res, 'NAME_INVALID', 'that is not a valid repository name');
  const ref = ociName.reference(asked.rest);
  if (!ref) return fail(res, 'TAG_INVALID', 'that is not a tag or a digest');
  // docker asks what is there before it pushes. someone who may push here gets a plain yes or no
  if (req.method === 'HEAD' && (await push.canPush(req, asked))) return push.head(req, res, asked);
  if (!(await allowed(req, res, asked, asked.rest))) return null;

  let got;
  try {
    got = await upstream.getManifest(asked.repository, asked.rest);
  } catch (err) {
    const status = err.status || 502;
    record(req, { package_name: asked.repository, version: asked.rest, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
    return fail(res, status === 404 ? 'MANIFEST_UNKNOWN' : 'UNSUPPORTED', err.message);
  }
  // a tag that moved is still only a pointer: a deny, kill switch or hold on the digest it points at still refuses
  if (ref.tag && !(await allowed(req, res, asked, got.digest, { pointedAt: true }))) return null;
  // a pushed image goes out once every blob in it is scanned clean, whatever the quarantine mode
  if (got.upstream === published.SOURCE) {
    const why = await pushed.imageWaiting(asked.repository, got.doc);
    if (why) {
      record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: why.status, reason: why.reason, blocked_by: why.status === 429 ? 'scanning' : 'quarantine' });
      return fail(res, why.status === 429 ? 'TOOMANYREQUESTS' : 'DENIED', why.reason);
    }
  }
  if (await heldBack(req, res, asked.repository, got.digest)) return null;
  // a repository with a trust policy: its images go out signed by someone the policy names
  const signed = await signatures.check(asked.repository, got.digest, ref.tag || null);
  if (signed && !signed.ok) {
    if (signed.mode === 'require' && !auditOnly()) {
      record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: 403, reason: signed.reason, blocked_by: 'signature' });
      return fail(res, 'DENIED', signed.reason);
    }
    record(req, { package_name: asked.repository, version: asked.rest, action: 'audit', reason: `let through unsigned: ${signed.reason}`.slice(0, 1000) });
  }
  // the packages inside it: not yet looked at with scan before serve on, or too vulnerable for safe resolution.
  // a list is only a list, each platform image is judged when it is asked for
  if (got.doc && Array.isArray(got.doc.layers) && !auditOnly()) {
    const risk = require('../../images/risk');
    const waiting = await risk.unscanned(asked.repository, got.digest);
    if (waiting) {
      // try again goes out as the registry spec's 429, and the log says what the client got
      record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: waiting.status === 503 ? 429 : waiting.status, reason: waiting.reason, blocked_by: 'scanning' });
      return fail(res, waiting.status === 503 ? 'TOOMANYREQUESTS' : 'DENIED', waiting.reason);
    }
    const bad = await risk.refusal(asked.repository, got.digest, policy.scopeOf(req), ref.tag);
    if (bad) {
      record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: 403, reason: bad.reason, blocked_by: 'security' });
      return fail(res, 'DENIED', bad.reason);
    }
  }
  // what this manifest names can be fetched on the strength of it, and only what it names
  const doc = got.doc && typeof got.doc === 'object' ? got.doc : {};
  const children = [
    ...(Array.isArray(doc.manifests) ? doc.manifests : []),
    ...(doc.config ? [doc.config] : []),
    ...(Array.isArray(doc.layers) ? doc.layers : [])
  ].map((d) => d && d.digest).filter((d) => ociName.isDigest(d));
  await refs.recordChildren(asked.repository, got.digest, children);

  res.set('docker-content-digest', got.digest);
  res.set('content-type', got.contentType || 'application/vnd.oci.image.manifest.v1+json');
  record(req, {
    package_name: asked.repository, version: asked.rest, pulled_version: got.digest, pulled_exact: 1,
    action: 'allow', bytes: got.body.length, reason: ref.tag ? `tag ${ref.tag}` : null, cache_hit: got.cached ? 1 : 0
  });
  // an image with layers gets looked inside, once per digest, after the answer goes out
  if (got.doc && Array.isArray(got.doc.layers)) imageScanner.queue(asked.repository, got.digest);
  // docker asks with HEAD first and refuses an answer with no length ("missing or empty Content-Length header")
  res.set('content-length', String(got.body.length));
  if (req.method === 'HEAD') return res.end();
  return res.send(got.body);
}));

router.get(/^\/v2\/(.+)\/blobs\/(.+)$/, wrap(async (req, res) => {
  const asked = await parse(req.path);
  if (!asked) return fail(res, 'NAME_INVALID', 'that is not a valid repository name');
  if (!ociName.isDigest(asked.rest)) return fail(res, 'DIGEST_INVALID', 'that is not a digest');
  if (req.method === 'HEAD' && (await push.canPush(req, asked))) return push.head(req, res, asked);
  if (!(await allowed(req, res, asked, asked.rest))) return null;
  if (await heldBack(req, res, asked.repository, asked.rest)) return null;
  if (await pushed.reservedBy([asked.repository])) {
    const why = await pushed.blobWaiting(asked.repository, asked.rest);
    if (why) {
      record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: why.status, reason: why.reason, blocked_by: why.status === 429 ? 'scanning' : 'quarantine' });
      return fail(res, why.status === 429 ? 'TOOMANYREQUESTS' : 'DENIED', why.reason);
    }
  }

  let blob;
  try {
    blob = await upstream.getBlob(asked.repository, asked.rest);
  } catch (err) {
    const status = err.status || 502;
    record(req, { package_name: asked.repository, version: asked.rest, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
    return fail(res, status === 404 ? 'BLOB_UNKNOWN' : 'UNSUPPORTED', err.message);
  }

  // the same last checks every file gets: a kill on these exact bytes, and scan before serve
  const scanned = await serving.scanBeforeServe({ ecosystem: 'oci', name: asked.repository, version: '', filename: asked.rest, artifactId: blob.artifactId });
  // a layer of an image refused as too vulnerable is not a way around that. only when every image naming it is refused
  if (!scanned && !auditOnly()) {
    const risk = require('../../images/risk');
    const parents = await refs.parentsOf(asked.repository, asked.rest);
    let refusedAll = parents.length > 0;
    let why = null;
    for (const parent of parents) {
      const bad = await risk.refusal(asked.repository, parent, policy.scopeOf(req), null);
      if (!bad) {
        refusedAll = false;
        break;
      }
      why = why || bad.reason;
    }
    if (refusedAll && why) {
      record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: 403, reason: why, blocked_by: 'security' });
      return fail(res, 'DENIED', why);
    }
  }
  if (scanned) {
    record(req, { package_name: asked.repository, version: asked.rest, action: 'deny', status: scanned.status, reason: scanned.reason, blocked_by: scanned.by });
    return fail(res, scanned.status === 503 ? 'TOOMANYREQUESTS' : 'DENIED', scanned.reason);
  }

  res.set('docker-content-digest', asked.rest);
  res.set('content-type', 'application/octet-stream');
  res.set('content-length', String(blob.size));
  record(req, {
    package_name: asked.repository, version: asked.rest, action: 'allow', bytes: blob.size, cache_hit: blob.cacheHit ? 1 : 0
  });
  if (req.method === 'HEAD') return res.end();
  // every other registry does this, images just never got the memo
  artifacts.touch(blob.artifactId);
  const stream = artifacts.open(blob);
  // a damaged or unreadable blob cuts the connection. left alone, the client would wait on a download that never ends
  stream.on('error', (err) => {
    require('../../logger').error(`could not send ${asked.repository} ${asked.rest}`, err.message);
    res.destroy(err);
  });
  return stream.pipe(res);
}));

// what this box has seen of a repository, not everything the upstream holds
router.get(/^\/v2\/(.+)\/tags\/list$/, wrap(async (req, res) => {
  const asked = await parse(req.path);
  if (!asked || asked.rest !== 'list') return fail(res, 'NAME_INVALID', 'that is not a valid repository name');
  if (!(await allowed(req, res, asked, null))) return null;
  const rows = await tags.forRepository(asked.repository);
  record(req, { package_name: asked.repository, action: 'allow', reason: `${rows.length} tag(s) known here` });
  return res.json({ name: asked.repository, tags: rows.map((r) => r.tag) });
}));

// anything else. nothing is deleted through the registry, a pushed image never changes
router.all(/^\/v2\//, (req, res) => {
  if (['GET', 'HEAD'].includes(req.method)) {
    record(req, { action: 'error', status: 404, reason: 'no such registry endpoint' });
    return fail(res, 'NAME_UNKNOWN', 'not found');
  }
  if (req.method === 'DELETE') {
    record(req, { action: 'deny', status: 405, reason: 'delete attempt' });
    return fail(res, 'UNSUPPORTED', 'nothing is deleted through the registry here, a pushed image never changes');
  }
  record(req, { action: 'deny', status: 405, reason: `${req.method} is not taken` });
  return fail(res, 'UNSUPPORTED', 'that is not something this registry does');
});

module.exports = router;
