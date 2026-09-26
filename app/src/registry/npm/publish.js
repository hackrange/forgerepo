// npm publish, deprecate and dist-tag, for reserved names only. a published version never changes and is never deleted.
// Author: Tim Rice
// the bytes go through the same store, hold and scan as anything fetched; serving them is the normal packument path

const crypto = require('crypto');
const semver = require('semver');
const config = require('../../config');
const auth = require('../../security/auth');
const upstream = require('./upstream');
const cache = require('./cache');
const artifacts = require('../../storage/artifacts');
const privateNames = require('../../policy/private-names');
const published = require('../shared/published');
const { readBody } = require('../shared/body');
const { record } = require('../shared/access');
const log = require('../../logger');

const MAX_TAG = 64;
const TAG = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
// fields a version manifest keeps. anything else a client sends is left out rather than served to everyone
const MANIFEST_FIELDS = ['name', 'version', 'description', 'main', 'module', 'types', 'exports', 'bin', 'files', 'license',
  'dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta', 'bundleDependencies', 'engines', 'os', 'cpu',
  'keywords', 'homepage', 'repository', 'bugs', 'author', 'type', 'deprecated'];
const ABBREVIATED_FIELDS = ['name', 'version', 'dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta',
  'bundleDependencies', 'bin', 'engines', 'os', 'cpu', 'dist', 'deprecated'];

const own = (obj, k) => !!obj && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, k);
const short = (name) => (name.includes('/') ? name.split('/')[1] : name);

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (own(obj, k)) out[k] = obj[k];
  return out;
}

// who is publishing: a token whose owner may publish. a session cookie is not a publishing credential
function publisherOf(req) {
  const token = req.npmIdentity;
  if (!token) throw httpErr(401, 'publishing needs a token, run: npm config set //<host>/:_authToken <your token>');
  if (!auth.can({ role: token.role }, 'packages:publish')) {
    throw httpErr(403, `${token.username} cannot publish here, it needs the publisher, approver or admin role`);
  }
  return token;
}

async function reservedOrRefuse(name) {
  if (!upstream.validName(name)) throw httpErr(400, 'that is not a valid package name');
  const hit = await privateNames.reservedBy('npm', name);
  if (!hit) throw httpErr(403, `${name} is not a reserved name, and only reserved names can be published here. An admin reserves them under Settings, Registries`);
  return hit;
}

// the documents this box keeps for a published package. a copy fetched before the name was reserved does not count
async function publishedDocs(name) {
  const full = await cache.getPackument(name, 'full');
  if (full && published.isPublished(full)) return full.doc;
  return null;
}

function abbreviate(doc) {
  const versions = {};
  for (const [v, meta] of Object.entries(doc.versions || {})) versions[v] = pick(meta, ABBREVIATED_FIELDS);
  return { name: doc.name, modified: doc.time && doc.time.modified, 'dist-tags': doc['dist-tags'] || {}, versions };
}

async function saveDocs(name, doc) {
  await cache.putPackument(name, 'full', doc, null, published.SOURCE);
  await cache.putPackument(name, 'abbreviated', abbreviate(doc), null, published.SOURCE);
}

function audit(req, token, action, target, detail, extra) {
  return auth.audit(token.userId, token.username, auth.clientIp(req), action, target, detail, extra);
}

// the tarball out of _attachments, checked against what the manifest says it is
function tarballFrom(body, name, version, manifest) {
  const attachments = body._attachments;
  const keys = attachments && typeof attachments === 'object' ? Object.keys(attachments) : [];
  if (keys.length !== 1) throw httpErr(400, 'a publish carries exactly one tarball');
  // npm names it after the whole package, scope and all (@acme/tools-1.0.0.tgz); the short form is taken too
  const expected = [`${name}-${version}.tgz`, `${short(name)}-${version}.tgz`];
  if (!expected.includes(keys[0])) throw httpErr(400, `the tarball has to be called ${expected[0]}`);
  const att = attachments[keys[0]];
  if (!att || typeof att.data !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(att.data)) throw httpErr(400, 'the tarball is not base64');
  const buffer = Buffer.from(att.data, 'base64');
  if (!buffer.length) throw httpErr(400, 'the tarball is empty');
  if (att.length !== undefined && Number(att.length) !== buffer.length) throw httpErr(400, 'the tarball is not the length it says it is');
  if (buffer[0] !== 0x1f || buffer[1] !== 0x8b) throw httpErr(400, 'the tarball is not gzip');
  const dist = manifest.dist && typeof manifest.dist === 'object' ? manifest.dist : {};
  if (!dist.integrity && !dist.shasum) throw httpErr(400, 'the manifest has no integrity or shasum for its tarball');
  if (!cache.verifyIntegrity(buffer, dist.integrity, dist.shasum)) throw httpErr(400, 'the tarball does not match the integrity in its manifest');
  const integrity = dist.integrity && String(dist.integrity).startsWith('sha512-')
    ? dist.integrity
    : `sha512-${crypto.createHash('sha512').update(buffer).digest('base64')}`;
  const shasum = crypto.createHash('sha1').update(buffer).digest('hex');
  return { buffer, integrity, shasum };
}

async function publishVersion(req, token, name, body, existing) {
  const versions = body.versions && typeof body.versions === 'object' ? body.versions : {};
  const fresh = Object.keys(versions).filter((v) => !existing || !own(existing.versions, v));
  const repeats = Object.keys(versions).filter((v) => existing && own(existing.versions, v));
  if (!fresh.length && repeats.length) {
    throw httpErr(409, `${name}@${repeats[0]} is already published, and a published version never changes. Publish a new version`);
  }
  if (fresh.length !== 1) throw httpErr(400, 'a publish adds exactly one new version');
  const version = fresh[0];
  if (!semver.valid(version)) throw httpErr(400, `${version} is not a valid version`);
  const manifest = versions[version];
  if (!manifest || typeof manifest !== 'object' || manifest.name !== name || manifest.version !== version) {
    throw httpErr(400, 'the version manifest does not name this package and version');
  }
  const tar = tarballFrom(body, name, version, manifest);

  const file = { ecosystem: 'npm', packageName: name, version, filename: artifacts.npmFilename(name, version) };
  const hold = await published.holdBeforeStore(file, token.username, tar.buffer);
  const saved = await cache.putTarball(name, version, tar.buffer, tar.integrity, published.SOURCE);
  const sha256 = crypto.createHash('sha256').update(tar.buffer).digest('hex');
  // two publishes of one version at once: the first bytes stay, the other one is told so
  if (saved.sha256 !== sha256) throw httpErr(409, `${name}@${version} was published a moment ago with different contents`);

  const now = new Date().toISOString();
  const doc = existing ? JSON.parse(JSON.stringify(existing)) : { _id: name, name, 'dist-tags': {}, versions: {}, time: { created: now } };
  if (own(doc.versions, version)) throw httpErr(409, `${name}@${version} was published a moment ago`);
  const kept = pick(manifest, MANIFEST_FIELDS);
  kept.dist = { integrity: tar.integrity, shasum: tar.shasum, tarball: `/${name}/-/${short(name)}-${version}.tgz` };
  doc.versions[version] = kept;
  doc.time = { ...(doc.time || {}), [version]: now, modified: now };
  if (typeof manifest.description === 'string') doc.description = manifest.description.slice(0, 1000);
  const tags = body['dist-tags'] && typeof body['dist-tags'] === 'object' ? body['dist-tags'] : {};
  const set = Object.entries(tags).filter(([tag, v]) => v === version && TAG.test(tag)).map(([tag]) => tag);
  for (const tag of set.length ? set : ['latest']) doc['dist-tags'][tag] = version;
  await saveDocs(name, doc);

  await audit(req, token, 'package.publish', `npm:${name}@${version}`, `${tar.buffer.length} bytes, held under ${hold.source}`,
    { after: { version, sha256, integrity: tar.integrity, tags: set.length ? set : ['latest'], hold: hold.source } });
  require('../../integrations/events').emit('package.published', {
    ecosystem: 'npm', package: name, version, artifactHash: sha256, user: token.username, sourceIp: auth.clientIp(req),
    reason: hold.scanning ? 'published, waiting for its malware scan' : 'published, waiting for an admin to release it', action: 'published'
  });
  log.info(`${token.username} published ${name}@${version}, held under ${hold.source}`);
  return { version, hold, bytes: tar.buffer.length };
}

// npm deprecate sends the whole document back with deprecated set on some versions. that is all it may change
async function deprecate(req, token, name, body, existing) {
  const versions = body.versions && typeof body.versions === 'object' ? body.versions : {};
  const changed = [];
  const doc = JSON.parse(JSON.stringify(existing));
  for (const [v, meta] of Object.entries(versions)) {
    if (!own(doc.versions, v) || !meta || typeof meta !== 'object') continue;
    const was = doc.versions[v].deprecated || '';
    const now = typeof meta.deprecated === 'string' ? meta.deprecated.slice(0, 1000) : '';
    if (was === now) continue;
    if (now) doc.versions[v].deprecated = now;
    else delete doc.versions[v].deprecated;
    changed.push({ version: v, was, now });
  }
  if (!changed.length) throw httpErr(400, 'nothing to change: a published version only takes a deprecation message');
  doc.time = { ...(doc.time || {}), modified: new Date().toISOString() };
  await saveDocs(name, doc);
  for (const c of changed) {
    await audit(req, token, c.now ? 'package.deprecate' : 'package.undeprecate', `npm:${name}@${c.version}`, c.now || null,
      { before: { deprecated: c.was || null }, after: { deprecated: c.now || null } });
  }
  return changed.length;
}

function fail(req, res, err, name) {
  const status = err.status || 500;
  if (status >= 500) log.error(`publishing ${name || 'a package'} failed`, err);
  record(req, { package_name: name || null, action: status < 500 ? 'deny' : 'error', status, reason: status >= 500 ? 'publish failed' : err.message });
  return res.status(status).json({ error: status >= 500 ? 'the publish failed on our end' : err.message });
}

// PUT /<name>
async function handlePut(req, res, name) {
  try {
    const token = publisherOf(req);
    await reservedOrRefuse(name);
    const raw = await readBody(req, config.maxImportBytes);
    let body;
    try {
      body = JSON.parse(raw.toString('utf8'));
    } catch (err) {
      throw httpErr(400, 'that publish is not JSON');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body) || body.name !== name) throw httpErr(400, 'the document does not name this package');
    const existing = await publishedDocs(name);
    if (body._attachments && Object.keys(body._attachments).length) {
      const out = await publishVersion(req, token, name, body, existing);
      record(req, { package_name: name, version: out.version, action: 'allow', status: 201, bytes: out.bytes, reason: `published, held under ${out.hold.source}` });
      // npm prints this as a notice line
      if (out.hold.note) res.set('npm-notice', `${out.hold.note}. It is held until an admin looks`.replace(/[^\x20-\x7e]/g, ' ').slice(0, 500));
      return res.status(201).json({ ok: true, id: name, version: out.version });
    }
    if (!existing) throw httpErr(404, `${name} has nothing published here yet`);
    const n = await deprecate(req, token, name, body, existing);
    record(req, { package_name: name, action: 'allow', status: 200, reason: `deprecation changed on ${n} version(s)` });
    return res.json({ ok: true, id: name });
  } catch (err) {
    return fail(req, res, err, name);
  }
}

// PUT /-/package/<name>/dist-tags/<tag> with the version as a JSON string, DELETE to take a tag away
async function handleTag(req, res, name, tag) {
  try {
    const token = publisherOf(req);
    await reservedOrRefuse(name);
    if (!TAG.test(tag) || tag.length > MAX_TAG) throw httpErr(400, 'that is not a valid tag name');
    if (semver.validRange(tag) && !/^[a-z]/i.test(tag)) throw httpErr(400, 'a tag cannot look like a version range');
    const existing = await publishedDocs(name);
    if (!existing) throw httpErr(404, `${name} has nothing published here yet`);
    const doc = JSON.parse(JSON.stringify(existing));
    const was = doc['dist-tags'][tag] || null;
    let now = null;
    if (req.method === 'DELETE') {
      if (tag === 'latest') throw httpErr(400, 'latest cannot be taken away, point it at another version instead');
      if (!was) throw httpErr(404, `${name} has no ${tag} tag`);
      delete doc['dist-tags'][tag];
    } else {
      let version;
      try {
        version = JSON.parse((await readBody(req, 1024)).toString('utf8'));
      } catch (err) {
        throw httpErr(400, 'send the version as a JSON string');
      }
      if (typeof version !== 'string' || !own(doc.versions, version)) throw httpErr(404, `${name}@${version} is not published here`);
      doc['dist-tags'][tag] = version;
      now = version;
    }
    doc.time = { ...(doc.time || {}), modified: new Date().toISOString() };
    await saveDocs(name, doc);
    await audit(req, token, 'package.dist-tag', `npm:${name}`, `${tag}: ${was || 'none'} -> ${now || 'removed'}`,
      { before: { [tag]: was }, after: { [tag]: now } });
    record(req, { package_name: name, action: 'allow', status: 200, reason: `dist-tag ${tag} ${now ? `set to ${now}` : 'removed'}` });
    return res.json({ ok: true, id: name, 'dist-tags': doc['dist-tags'] });
  } catch (err) {
    return fail(req, res, err, name);
  }
}

module.exports = { MANIFEST_FIELDS, publisherOf, reservedOrRefuse, publishedDocs, abbreviate, tarballFrom, handlePut, handleTag };
