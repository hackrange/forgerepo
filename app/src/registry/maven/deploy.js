// mvn deploy, to reserved coordinates only. a deployed file never changes and is never deleted, like every other
// publish here.
// Author: Tim Rice
//
// maven sends each file of a release as its own PUT, with a checksum file after each one, and a maven-metadata.xml at
// the end. the checksums are checked against what was stored rather than kept, and the metadata this box serves is
// built from what was really deployed, so a client can not write the version list itself

const crypto = require('crypto');
const config = require('../../config');
const auth = require('../../security/auth');
const artifacts = require('../../storage/artifacts');
const docs = require('../../db/repositories/package-documents');
const privateNames = require('../../policy/private-names');
const published = require('../shared/published');
const { readBody } = require('../shared/body');
const { record, text } = require('./respond');
const log = require('../../logger');

const ECO = 'maven';
const ALGORITHMS = { sha1: 'sha1', md5: 'md5', sha256: 'sha256', sha512: 'sha512' };
const MAX_CHECKSUM = 1024;

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function deployerOf(req) {
  const token = req.npmIdentity;
  if (!token) throw httpErr(401, 'deploying needs a token: put your ForgeRepo token as the password of this server in your settings.xml');
  if (!auth.can({ role: token.role }, 'packages:publish')) {
    throw httpErr(403, `${token.username} cannot deploy here, it needs the publisher, approver or admin role`);
  }
  return token;
}

// the versions really deployed, newest last, as the box keeps them
const docOf = async (name) => (await docs.get(ECO, name, published.KIND).catch(() => null))?.doc || { name, versions: [] };

async function reserved(name) {
  const hit = await privateNames.reservedBy(ECO, name);
  if (!hit) throw httpErr(403, `${name} is not a reserved coordinate, and only reserved ones can be deployed here. An admin reserves them under Settings, Registries`);
}

// a checksum file: it has to match what was stored, and it is not kept. maven asks the box for checksums of its own
async function checkedChecksum(asked, body) {
  const want = String(body.toString('utf8') || '').trim().split(/\s+/)[0].toLowerCase();
  if (!/^[0-9a-f]{32,128}$/.test(want)) throw httpErr(400, 'that is not a checksum');
  const held = await artifacts.locate(ECO, asked.name, asked.version, asked.filename);
  if (!held) throw httpErr(409, `${asked.filename} has not been deployed here, so its ${asked.checksum} is not taken`);
  const got = await require('./upstream').checksum({ ...held, artifactId: held.id }, ALGORITHMS[asked.checksum]);
  if (got !== want) throw httpErr(409, `the ${asked.checksum} does not match the ${asked.filename} that was deployed`);
  return got;
}

async function handlePut(req, res) {
  const asked = require('../../ecosystems/maven/path').parse(req.path);
  let name = asked && asked.name;
  try {
    const token = deployerOf(req);
    if (!asked) throw httpErr(400, 'that is not a Maven path this repository takes');
    if (asked.kind === 'snapshot') throw httpErr(400, 'snapshots are not deployed here, only releases: a deployed version never changes');
    await reserved(asked.name);
    name = asked.name;

    // the version list is the box's own, built from what was deployed. maven sends one, and it is not kept
    if (asked.kind === 'metadata') {
      await readBody(req, MAX_CHECKSUM * 1024);
      record(req, { package_name: name, action: 'allow', status: 200, reason: 'metadata put, answered from what was deployed' });
      return text(res, 200, '');
    }

    if (asked.checksum) {
      const body = await readBody(req, MAX_CHECKSUM);
      await checkedChecksum(asked, body);
      record(req, { package_name: name, version: asked.version, action: 'allow', status: 200, reason: `${asked.checksum} of ${asked.filename} checked` });
      return text(res, 200, '');
    }

    const data = await readBody(req, config.maxImportBytes);
    if (!data.length) throw httpErr(400, `${asked.filename} is empty`);
    const sha256 = crypto.createHash('sha256').update(data).digest('hex');
    const held = await artifacts.locate(ECO, asked.name, asked.version, asked.filename);
    if (held) {
      // the same bytes again is a retry, different bytes are a change, and a deployed file never changes
      if (held.sha256 === sha256) {
        record(req, { package_name: name, version: asked.version, action: 'allow', status: 200, reason: `${asked.filename} deployed again, same bytes` });
        return text(res, 200, '');
      }
      throw httpErr(409, `${asked.filename} is already deployed and a deployed file never changes. Deploy a new version`);
    }

    const file = { ecosystem: ECO, packageName: asked.name, version: asked.version, filename: asked.filename };
    const hold = await published.holdBeforeStore(file, token.username, data);
    const kept = await artifacts.keep({ ...file, packageName: asked.name, upstream: published.SOURCE }, { buffer: data });
    if (kept.sha256 !== sha256) throw httpErr(409, `${asked.filename} was deployed a moment ago with different contents`);

    const doc = await docOf(asked.name);
    let entry = doc.versions.find((v) => v.version === asked.version);
    if (!entry) {
      entry = { version: asked.version, published: new Date().toISOString(), files: [] };
      doc.versions.push(entry);
    }
    if (!entry.files.some((f) => f.filename === asked.filename)) entry.files.push({ filename: asked.filename, sha256, size: data.length });
    doc.lastUpdated = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    await docs.put(ECO, asked.name, published.KIND, doc, published.SOURCE);

    await auth.audit(token.userId, token.username, auth.clientIp(req), 'package.publish', `maven:${asked.name}@${asked.version}`,
      `${asked.filename}, ${data.length} bytes, held under ${hold.source}`,
      { after: { version: asked.version, filename: asked.filename, sha256, hold: hold.source } });
    require('../../integrations/events').emit('package.published', {
      ecosystem: ECO, package: asked.name, version: asked.version, filename: asked.filename, artifactHash: sha256, user: token.username,
      sourceIp: auth.clientIp(req), reason: hold.scanning ? 'deployed, waiting for its malware scan' : 'deployed, waiting for an admin to release it', action: 'published'
    });
    log.info(`${token.username} deployed ${asked.name} ${asked.version} ${asked.filename}, held under ${hold.source}`);
    record(req, { package_name: name, version: asked.version, action: 'allow', status: 201, bytes: data.length, reason: `deployed, held under ${hold.source}` });
    return text(res, 201, '');
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) log.error(`a deploy of ${name || 'something'} failed`, err);
    record(req, { package_name: name, action: status < 500 ? 'deny' : 'error', status, reason: status >= 500 ? 'deploy failed' : err.message });
    return text(res, status, status >= 500 ? 'the deploy failed on our end' : err.message, status >= 500 ? 'the deploy failed on our end' : err.message);
  }
}

// mvn deploy asks whether a file is there before it sends it
function handleOther(req, res) {
  record(req, { action: 'deny', status: 405, reason: `${req.method} attempt` });
  res.set('allow', 'GET, HEAD, PUT');
  return text(res, 405, 'a deployed file is never changed or deleted here. Deploy a new version, or ask an admin to block this one',
    'that is not something this repository takes');
}

module.exports = { handlePut, handleOther };
