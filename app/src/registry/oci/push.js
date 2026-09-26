// docker push: layers in, then the manifest that names them. Publishers only, reserved names only.
// Author: Tim Rice
//
// the order docker uses: HEAD each blob to skip what is here, POST to open an upload, PATCH the bytes, PUT ?digest= to
// close it, then PUT the manifest under its tag. a blob is hashed before it is kept and held until its malware scan is
// clean, a manifest may only name blobs this repository holds, and a pushed tag never moves (latest excepted, the same
// as npm's latest). nothing pushed is ever deleted

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const config = require('../../config');
const auth = require('../../security/auth');
const artifacts = require('../../storage/artifacts');
const store = require('../../storage');
const killswitch = require('../../policy/killswitch');
const quarantine = require('../../policy/quarantine');
const ociName = require('../../ecosystems/oci/name');
const tags = require('../../db/repositories/oci-tags');
const kept = require('../../db/repositories/oci-manifests');
const refs = require('../../db/repositories/oci-refs');
const uploads = require('../../db/repositories/oci-uploads');
const published = require('../shared/published');
const pushed = require('./published');
const upstream = require('./upstream');
const { readBody } = require('../shared/body');
const { CODES, record, fail, askLogin } = require('./respond');
const log = require('../../logger');

const workDir = path.join(config.cacheDir, 'tmp', 'oci-uploads');
const UPLOAD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// docker pushes a handful of layers at once, a pipeline a few images. this many open at once is somebody stuck
const MAX_OPEN = 32;
// an upload nobody touched for this long is given up on, its bytes deleted
const STALE_MINUTES = 60;
// no bytes for this long and the connection is dropped, so a stalled push does not hold a socket forever
const IDLE_MS = 120000;
const MAX_LAYERS = 1000;
const MAX_CHILDREN = 256;

const IMAGE_TYPES = ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'];
const LIST_TYPES = ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'];

function no(code, message, status) {
  const e = new Error(message);
  e.code = code;
  if (status) e.status = status;
  return e;
}

const fileOf = (id) => path.join(workDir, id);
const uploadUrl = (repository, id) => `/v2/${repository}/blobs/uploads/${id}`;

// who is pushing, and where. a session cookie is not a pushing credential, only a token is
async function pusher(req, asked) {
  const token = req.npmIdentity;
  if (!token) throw no('UNAUTHORIZED', 'pushing needs a token: docker login with your username and the token as the password');
  if (!auth.can({ role: token.role }, 'packages:publish')) {
    throw no('DENIED', `${token.username} cannot push here, it needs the publisher, approver or admin role`);
  }
  const hit = await pushed.reservedBy(asked.aliases || [asked.repository]);
  if (!hit) {
    throw no('DENIED', `${asked.repository} is not a reserved name, and only reserved names can be pushed here. An admin reserves them under Settings, Registries`);
  }
  return token;
}

// may this request push here? for the HEAD checks docker makes before it uploads anything
async function canPush(req, asked) {
  const token = req.npmIdentity;
  if (!token || !auth.can({ role: token.role }, 'packages:publish')) return false;
  return !!(await pushed.reservedBy(asked.aliases || [asked.repository]));
}

// every failure goes out in the registry's own words and leaves a line in the traffic log
function refuse(req, res, asked, err) {
  const code = err.code || (err.status === 413 ? 'SIZE_INVALID' : null);
  if (!code) {
    log.error(`a push to ${asked ? asked.repository : 'the registry'} failed`, err);
    record(req, { package_name: asked ? asked.repository : null, action: 'error', status: 500, reason: 'push failed' });
    return res.status(500).json({ errors: [{ code: 'UNKNOWN', message: 'the push failed on our end', detail: null }] });
  }
  record(req, { package_name: asked ? asked.repository : null, action: 'deny', status: err.status || CODES[code] || 400, reason: err.message });
  if (code === 'UNAUTHORIZED') return askLogin(req, res, err.message);
  if (err.range !== undefined) res.set('range', err.range);
  if (err.status) return res.status(err.status).json({ errors: [{ code, message: err.message, detail: null }] });
  return fail(res, code, err.message);
}

const handle = (fn) => async (req, res, asked) => {
  try {
    return await fn(req, res, asked);
  } catch (err) {
    return refuse(req, res, asked, err);
  }
};

// ---------------------------------------------------------------- uploads

// uploads left behind by a push that died, the bytes then the row. and blobs no manifest ever named, so a refused
// push does not leave its layers taking up disk for good. a pulled layer is the cache's business, not this
async function sweep() {
  for (const row of await uploads.stale(STALE_MINUTES)) {
    await fsp.unlink(fileOf(row.id)).catch(() => {});
    await uploads.close(row.id);
  }
  for (const row of await uploads.orphans(published.SOURCE)) {
    const file = { ecosystem: 'oci', packageName: row.package_name, version: '', filename: row.filename };
    for (const source of ['malware', 'publish']) await quarantine.releaseSource(file, source, 'system', 'no pushed manifest named it, removed');
    await artifacts.forgetFile('oci', row.package_name, row.filename);
    log.info(`removed ${row.package_name} ${row.filename}, pushed a day ago and named by no manifest`);
  }
}

async function session(req, asked, id) {
  const token = await pusher(req, asked);
  if (!UPLOAD_ID.test(String(id))) throw no('BLOB_UPLOAD_UNKNOWN', 'there is no such upload');
  const row = await uploads.mine(id, asked.repository, token.userId);
  if (!row) throw no('BLOB_UPLOAD_UNKNOWN', 'there is no such upload');
  return { token, row };
}

function progress(res, repository, id, size) {
  res.set('location', uploadUrl(repository, id));
  res.set('docker-upload-uuid', id);
  res.set('range', `0-${Math.max(0, size - 1)}`);
  res.set('content-length', '0');
}

// one upload takes bytes from one request at a time
const busy = new Set();

// the request body onto the end of the upload. a piece that breaks off is cut back off, so the next try starts clean
async function append(req, row) {
  if (busy.has(row.id)) throw no('BLOB_UPLOAD_INVALID', 'that upload is already taking bytes from another request');
  const from = Number(row.size);
  const range = /^(\d+)-(\d+)$/.exec(String(req.get('content-range') || '').trim());
  if (req.get('content-range') && (!range || Number(range[1]) !== from)) {
    const e = no('BLOB_UPLOAD_INVALID', `that piece does not start where the upload ends (${from} bytes so far)`, 416);
    e.range = `0-${Math.max(0, from - 1)}`;
    throw e;
  }
  const declared = Number(req.get('content-length'));
  if (Number.isFinite(declared) && from + declared > upstream.MAX_LAYER_BYTES) {
    throw no('SIZE_INVALID', `a layer can be at most ${Math.round(upstream.MAX_LAYER_BYTES / 1073741824)}GB`, 413);
  }
  busy.add(row.id);
  const file = fileOf(row.id);
  let added = 0;
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(file, { flags: 'a', mode: 0o640 });
      let timer = null;
      const idle = () => {
        clearTimeout(timer);
        timer = setTimeout(() => req.destroy(new Error('no bytes arrived for two minutes')), IDLE_MS);
      };
      const stop = (err) => {
        clearTimeout(timer);
        req.unpipe(out);
        out.destroy();
        reject(err);
      };
      idle();
      req.on('data', (chunk) => {
        added += chunk.length;
        idle();
        if (from + added > upstream.MAX_LAYER_BYTES) {
          stop(no('SIZE_INVALID', `a layer can be at most ${Math.round(upstream.MAX_LAYER_BYTES / 1073741824)}GB`, 413));
        }
      });
      req.on('aborted', () => stop(no('BLOB_UPLOAD_INVALID', 'the upload broke off before it finished')));
      req.on('error', (err) => stop(no('BLOB_UPLOAD_INVALID', `the upload broke off: ${err.message}`)));
      out.on('error', (err) => stop(err));
      out.on('finish', () => {
        clearTimeout(timer);
        resolve();
      });
      req.pipe(out);
    });
    if (range && Number(range[2]) + 1 !== from + added) {
      throw no('BLOB_UPLOAD_INVALID', `that piece said it ends at byte ${range[2]} and ended at ${from + added - 1}`, 416);
    }
    if (!(await uploads.grow(row.id, from, from + added))) throw no('BLOB_UPLOAD_INVALID', 'that upload moved on under this request');
    return from + added;
  } catch (err) {
    await fsp.truncate(file, from).catch(() => {});
    throw err;
  } finally {
    busy.delete(row.id);
  }
}

const hasBody = (req) => Number(req.get('content-length')) > 0 || !!req.get('transfer-encoding');

async function drop(id) {
  await fsp.unlink(fileOf(id)).catch(() => {});
  await uploads.close(id);
}

// the upload is done: its bytes must be the digest named, and then they are kept like any layer, held until scanned
async function finish(req, res, asked, token, id, digest) {
  if (!ociName.isDigest(digest)) {
    await drop(id);
    throw no('DIGEST_INVALID', 'closing an upload names its digest, as ?digest=sha256:...');
  }
  const file = fileOf(id);
  const got = await store.hashFile(file);
  if (`sha256:${got.sha256}` !== digest) {
    await drop(id);
    throw no('DIGEST_INVALID', `the bytes sent hash to sha256:${got.sha256}, not ${digest}`);
  }
  const dead = await killswitch.checkHash(got.sha256);
  if (dead) {
    await drop(id);
    throw no('DENIED', dead.reason);
  }
  const where = { ecosystem: 'oci', packageName: asked.repository, version: '', filename: digest };
  let hold = null;
  if (!(await artifacts.locate('oci', asked.repository, '', digest))) {
    hold = await published.holdBeforeStore(where, token.username);
    await artifacts.keep({ ...where, upstream: published.SOURCE }, { tmp: file, sha256: got.sha256 });
  }
  await drop(id);
  record(req, {
    package_name: asked.repository, version: digest, action: 'allow', status: 201, bytes: got.size,
    reason: hold ? `pushed, held under ${hold.source}` : 'pushed, already here'
  });
  res.set('location', `/v2/${asked.repository}/blobs/${digest}`);
  res.set('docker-content-digest', digest);
  res.set('content-length', '0');
  return res.status(201).end();
}

// POST: open an upload, or take the whole blob at once with ?digest=
const start = handle(async (req, res, asked) => {
  const token = await pusher(req, asked);
  await sweep().catch((err) => log.warn('could not clear stale image uploads', err.message));
  // a blob this repository already holds needs no upload. mounting from another repository is not done, docker then
  // just uploads it, which keeps one repository's blobs from being reached through another
  const mount = String(req.query.mount || '');
  if (ociName.isDigest(mount) && (await artifacts.locate('oci', asked.repository, '', mount))) {
    res.set('location', `/v2/${asked.repository}/blobs/${mount}`);
    res.set('docker-content-digest', mount);
    res.set('content-length', '0');
    return res.status(201).end();
  }
  if ((await uploads.openFor(token.userId)) >= MAX_OPEN) {
    throw no('TOOMANYREQUESTS', `${token.username} has ${MAX_OPEN} uploads open already, let some finish first`);
  }
  const id = crypto.randomUUID();
  await fsp.mkdir(workDir, { recursive: true, mode: 0o750 });
  await (await fsp.open(fileOf(id), 'wx', 0o640)).close();
  await uploads.open({ id, repository: asked.repository, userId: token.userId, username: token.username });
  if (req.query.digest !== undefined) {
    // all in one go, so nothing to come back to if it fails
    try {
      const row = await uploads.mine(id, asked.repository, token.userId);
      if (hasBody(req)) await append(req, row);
    } catch (err) {
      await drop(id);
      throw err;
    }
    return finish(req, res, asked, token, id, String(req.query.digest));
  }
  progress(res, asked.repository, id, 0);
  return res.status(202).end();
});

// PATCH: the next piece
const piece = handle(async (req, res, asked) => {
  const { row } = await session(req, asked, asked.upload);
  const size = await append(req, row);
  progress(res, asked.repository, row.id, size);
  return res.status(202).end();
});

// PUT ?digest=: the last piece, if any, and done
const close = handle(async (req, res, asked) => {
  const { token, row } = await session(req, asked, asked.upload);
  if (hasBody(req)) await append(req, row);
  return finish(req, res, asked, token, row.id, String(req.query.digest || ''));
});

// GET: how far it got, so a client can pick up where it left off
const status = handle(async (req, res, asked) => {
  const { row } = await session(req, asked, asked.upload);
  progress(res, asked.repository, row.id, Number(row.size));
  return res.status(204).end();
});

// DELETE: the client gave up
const cancel = handle(async (req, res, asked) => {
  const { row } = await session(req, asked, asked.upload);
  await drop(row.id);
  res.set('content-length', '0');
  return res.status(204).end();
});

// ---------------------------------------------------------------- manifests

const isDescriptor = (d) => !!d && typeof d === 'object' && ociName.isDigest(d.digest) && Number.isSafeInteger(d.size) && d.size >= 0;

// what a manifest names must already be in this repository, byte for byte the size it says
async function checkNames(repository, doc, type) {
  if (LIST_TYPES.includes(type)) {
    const list = doc.manifests;
    if (!Array.isArray(list) || !list.length || list.length > MAX_CHILDREN) {
      throw no('MANIFEST_INVALID', `a list names between 1 and ${MAX_CHILDREN} images`);
    }
    for (const d of list) {
      if (!isDescriptor(d)) throw no('MANIFEST_INVALID', 'every image in a list needs a digest and a size');
      const row = await kept.get(repository, d.digest);
      if (!row || row.upstream !== published.SOURCE || Buffer.byteLength(row.body) !== d.size) {
        throw no('MANIFEST_BLOB_UNKNOWN', `${d.digest} is named by the list but was not pushed to ${repository}`);
      }
    }
    return list.map((d) => d.digest);
  }
  const layers = Array.isArray(doc.layers) ? doc.layers : null;
  if (!isDescriptor(doc.config) || !layers || layers.length > MAX_LAYERS) {
    throw no('MANIFEST_INVALID', `an image names its config and at most ${MAX_LAYERS} layers, each with a digest and a size`);
  }
  for (const d of [doc.config, ...layers]) {
    if (!isDescriptor(d)) throw no('MANIFEST_INVALID', 'every layer needs a digest and a size');
    // a layer somewhere else on the internet is a layer nobody here scanned
    if (Array.isArray(d.urls) && d.urls.length) throw no('MANIFEST_INVALID', `${d.digest} is a foreign layer, and those are not taken here`);
    const held = await artifacts.locate('oci', repository, '', d.digest);
    if (!held || Number(held.size) !== d.size) {
      throw no('MANIFEST_BLOB_UNKNOWN', `${d.digest} is named by the manifest but was not pushed to ${repository}`);
    }
  }
  return [doc.config.digest, ...layers.map((d) => d.digest)];
}

// PUT a manifest under a tag or its digest
const manifest = handle(async (req, res, asked) => {
  const token = await pusher(req, asked);
  const ref = ociName.reference(asked.rest);
  if (!ref) throw no('TAG_INVALID', 'that is not a tag or a digest');
  const body = await readBody(req, upstream.MAX_MANIFEST_BYTES).catch((err) => {
    throw no('MANIFEST_INVALID', err.status === 413 ? `a manifest can be at most ${upstream.MAX_MANIFEST_BYTES / 1048576}MB` : err.message);
  });
  let doc;
  try {
    doc = JSON.parse(body.toString('utf8'));
  } catch (err) {
    throw no('MANIFEST_INVALID', 'that manifest is not json');
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || doc.schemaVersion !== 2) {
    throw no('MANIFEST_INVALID', 'only schema version 2 manifests are taken');
  }
  const said = String(req.get('content-type') || '').split(';')[0].trim();
  const type = doc.mediaType || said;
  if (doc.mediaType && said && said !== doc.mediaType) throw no('MANIFEST_INVALID', `the manifest says it is ${doc.mediaType} but was sent as ${said}`);
  if (![...IMAGE_TYPES, ...LIST_TYPES].includes(type)) throw no('MANIFEST_INVALID', `${type || 'a manifest with no media type'} is not a manifest this registry takes`);
  const digest = `sha256:${crypto.createHash('sha256').update(body).digest('hex')}`;
  if (ref.digest && ref.digest !== digest) throw no('DIGEST_INVALID', `that manifest hashes to ${digest}, not ${ref.digest}`);

  const dead = (ref.tag && (await killswitch.check('oci', asked.repository, ref.tag))) || (await killswitch.checkHash(digest.slice(7)));
  if (dead) throw no('DENIED', dead.reason);
  // said before anything is kept, so a refused tag leaves nothing behind
  if (ref.tag && ref.tag !== 'latest') {
    const now = await tags.get(asked.repository, ref.tag);
    if (now && now.upstream === published.SOURCE && now.digest !== digest) {
      throw no('TAG_INVALID', `${asked.repository}:${ref.tag} was pushed before as ${now.digest}, and a pushed tag never moves. Push it under a new tag`);
    }
  }
  const children = await checkNames(asked.repository, doc, type);

  await kept.put(asked.repository, digest, type, body, published.SOURCE);
  await kept.claim(asked.repository, digest, published.SOURCE);
  await refs.recordChildren(asked.repository, digest, children);
  if (ref.tag) {
    const pointed = await tags.pushTo(asked.repository, ref.tag, digest, published.SOURCE, { movable: ref.tag === 'latest' });
    if (!pointed.ok) {
      throw no('TAG_INVALID', `${asked.repository}:${ref.tag} was pushed a moment ago as ${pointed.was}, and a pushed tag never moves. Push it under a new tag`);
    }
    if (pointed.moved) log.info(`${asked.repository}:${ref.tag} moved to ${digest}`);
  }

  const what = `${asked.repository}${ref.tag ? `:${ref.tag}` : `@${digest}`}`;
  await auth.audit(token.userId, token.username, auth.clientIp(req), 'package.publish', `oci:${what}`,
    `${digest}, ${children.length} ${LIST_TYPES.includes(type) ? 'image(s)' : 'blob(s)'}`,
    { after: { tag: ref.tag, digest, mediaType: type, names: children.length } });
  require('../../integrations/events').emit('package.published', {
    ecosystem: 'oci', package: asked.repository, version: ref.tag || digest, artifactHash: digest.slice(7), user: token.username,
    sourceIp: auth.clientIp(req), reason: 'pushed, each blob waits for its malware scan', action: 'published'
  });
  // an image with layers gets looked inside for known vulnerabilities, like a pulled one
  if (IMAGE_TYPES.includes(type) && Array.isArray(doc.layers) && doc.layers.length) require('../../images/scanner').queue(asked.repository, digest);
  log.info(`${token.username} pushed ${what} (${digest})`);
  record(req, { package_name: asked.repository, version: ref.tag || digest, pulled_version: digest, pulled_exact: 1, action: 'allow', status: 201, bytes: body.length, reason: 'pushed' });
  res.set('location', `/v2/${asked.repository}/manifests/${digest}`);
  res.set('docker-content-digest', digest);
  res.set('content-length', '0');
  return res.status(201).end();
});

// ---------------------------------------------------------------- what docker checks before it uploads

// HEAD from someone who may push here: is it here or not, whatever the rules, holds and scans say about pulling it
const head = handle(async (req, res, asked) => {
  if (asked.kind === 'blobs') {
    if (!ociName.isDigest(asked.rest)) throw no('DIGEST_INVALID', 'that is not a digest');
    const held = await artifacts.locate('oci', asked.repository, '', asked.rest);
    if (!held) return res.status(404).end();
    res.set('docker-content-digest', asked.rest);
    res.set('content-type', 'application/octet-stream');
    res.set('content-length', String(held.size));
    return res.status(200).end();
  }
  const ref = ociName.reference(asked.rest);
  if (!ref) throw no('TAG_INVALID', 'that is not a tag or a digest');
  const hit = await pushed.reservedBy(asked.aliases || [asked.repository]);
  let got;
  try {
    got = await pushed.manifest(asked.repository, asked.rest, hit, upstream.fromKept);
  } catch (err) {
    if (err.reserved) return res.status(404).end();
    throw err;
  }
  res.set('docker-content-digest', got.digest);
  res.set('content-type', got.contentType || 'application/vnd.oci.image.manifest.v1+json');
  res.set('content-length', String(got.body.length));
  return res.status(200).end();
});

module.exports = { IMAGE_TYPES, LIST_TYPES, STALE_MINUTES, pusher, canPush, sweep, start, piece, close, status, cancel, manifest, head };
