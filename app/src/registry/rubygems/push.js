// gem push. only to reserved gem names, and a pushed version never changes and is never yanked.
// Author: Tim Rice
//
// the .gem goes through the same store, hold and scan as anything fetched. what the compact index says about a
// reserved name comes from what was pushed here, never from rubygems.org, so nobody can publish the same name
// outside and have it installed instead. the name, version, dependencies and license are read from its metadata

const crypto = require('crypto');
const config = require('../../config');
const auth = require('../../security/auth');
const artifacts = require('../../storage/artifacts');
const docs = require('../../db/repositories/package-documents');
const gemName = require('../../ecosystems/rubygems/name');
const gemVersion = require('../../ecosystems/rubygems/version');
const privateNames = require('../../policy/private-names');
const published = require('../shared/published');
const gemfile = require('./gemfile');
const marshal = require('./marshal');
const { readBody } = require('../shared/body');
const { record, text } = require('./respond');
const log = require('../../logger');

const ECO = 'rubygems';
const PLATFORM = /^[a-z0-9][a-z0-9_.-]{0,40}$/i;

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// gem push sends the api key in Authorization as it is, no Bearer in front of it
function pusherOf(req) {
  const token = req.npmIdentity;
  if (!token) throw httpErr(401, 'pushing needs a token: gem push --key with your ForgeRepo token, or put it in ~/.gem/credentials');
  if (!auth.can({ role: token.role }, 'packages:publish')) {
    throw httpErr(403, `${token.username} cannot push here, it needs the publisher, approver or admin role`);
  }
  return token;
}

const fileNameOf = (spec) => `${spec.name}-${spec.version}${spec.platform ? `-${spec.platform}` : ''}.gem`;

// everything about the push checked before anything is held or stored
async function checked(req) {
  const data = await readBody(req, config.maxImportBytes);
  if (!data.length) throw httpErr(400, 'there is no gem in that push');
  let spec;
  try {
    spec = gemfile.read(data);
  } catch (err) {
    throw httpErr(400, `the .gem could not be read: ${err.message}`);
  }
  if (!gemName.valid(spec.name)) throw httpErr(400, 'the gem metadata has no valid name');
  if (!gemVersion.valid(spec.version)) throw httpErr(400, `${spec.version || 'that'} is not a version a gem can have`);
  if (spec.platform && !PLATFORM.test(spec.platform)) throw httpErr(400, 'that platform is not one this registry takes');
  if (!spec.hasData) throw httpErr(400, 'the .gem has no data.tar.gz in it');
  const hit = await privateNames.reservedBy(ECO, spec.name);
  if (!hit) throw httpErr(403, `${spec.name} is not a reserved gem name, and only reserved names can be pushed here. An admin reserves them under Settings, Registries`);
  return { spec, data, sha256: crypto.createHash('sha256').update(data).digest('hex'), filename: fileNameOf(spec) };
}

// pushes of one name, one at a time, so two versions pushed together both land in its index
const locks = new Map();
function exclusive(key, work) {
  const before = locks.get(key) || Promise.resolve();
  const run = before.then(work, work);
  const tail = run.catch(() => {});
  locks.set(key, tail);
  tail.then(() => {
    if (locks.get(key) === tail) locks.delete(key);
  });
  return run;
}

async function handlePush(req, res) {
  let name = null;
  try {
    const token = pusherOf(req);
    const up = await checked(req);
    name = up.spec.name;
    const hold = await exclusive(name, async () => {
      const held = await docs.get(ECO, name, published.KIND);
      const doc = (held && held.doc) || { name, files: [] };
      if (doc.files.some((f) => f.version === up.spec.version && (f.platform || '') === (up.spec.platform || ''))) {
        throw httpErr(409, `${name} ${up.spec.version} is already pushed, and a pushed version never changes. Push a new version`);
      }
      const kept = await artifacts.locate(ECO, name, up.spec.version, up.filename);
      if (kept && kept.upstream === published.SOURCE) throw httpErr(409, `${up.filename} is already pushed. Push a new version`);
      const placed = await published.holdBeforeStore({ ecosystem: ECO, packageName: name, version: up.spec.version, filename: up.filename }, token.username, up.data);
      const stored = await artifacts.keep({ ecosystem: ECO, packageName: name, version: up.spec.version, filename: up.filename, upstream: published.SOURCE }, { buffer: up.data });
      if (stored.sha256 !== up.sha256) throw httpErr(409, `${up.filename} was pushed a moment ago with different contents. Push a new version`);
      doc.files.push({
        version: up.spec.version, platform: up.spec.platform || '', sha256: up.sha256,
        published: new Date().toISOString(), line: gemfile.infoLine(up.spec, up.sha256),
        license: up.spec.licenses.join(' OR ') || null
      });
      // gem install asks for the gemspec before it downloads anything, and a pushed gem has none until it is written
      const rz = marshal.rz(up.spec);
      await artifacts.keep({ ecosystem: ECO, packageName: name, version: up.spec.version, filename: `${up.filename.slice(0, -4)}.gemspec.rz`, upstream: published.SOURCE }, { buffer: rz });
      await docs.put(ECO, name, published.KIND, doc, published.SOURCE);
      require('./upstream').invalidateNames();
      return placed;
    });

    await auth.audit(token.userId, token.username, auth.clientIp(req), 'package.publish', `rubygems:${name}@${up.spec.version}`,
      `${up.filename}, ${up.data.length} bytes, held under ${hold.source}`,
      { after: { version: up.spec.version, filename: up.filename, sha256: up.sha256, hold: hold.source } });
    require('../../integrations/events').emit('package.published', {
      ecosystem: ECO, package: name, version: up.spec.version, filename: up.filename, artifactHash: up.sha256, user: token.username,
      sourceIp: auth.clientIp(req), reason: hold.scanning ? 'pushed, waiting for its malware scan' : 'pushed, waiting for an admin to release it', action: 'published'
    });
    log.info(`${token.username} pushed ${up.filename}, held under ${hold.source}`);
    record(req, { package_name: name, version: up.spec.version, action: 'allow', status: 200, bytes: up.data.length, reason: `pushed, held under ${hold.source}` });
    const note = hold.note ? ` ${hold.note}, so an admin has to release it.` : '';
    return text(res, 200, `${name} (${up.spec.version}) is pushed. It is listed once its malware scan is clean${hold.scanning ? '' : ', or an admin releases it'}.${note}`);
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) log.error(`a push of ${name || 'a gem'} failed`, err);
    record(req, { package_name: name, action: status < 500 ? 'deny' : 'error', status, reason: status >= 500 ? 'push failed' : err.message });
    return text(res, status, status >= 500 ? 'the push failed on our end' : err.message, status >= 500 ? 'the push failed on our end' : err.message);
  }
}

// gem yank: a pushed version stays, the same as everywhere else here
function handleYank(req, res) {
  record(req, { action: 'deny', status: 405, reason: 'yank attempt' });
  res.set('allow', 'POST');
  return text(res, 405, 'a pushed gem is never yanked here. Push a new version, or ask an admin to block this one with a rule or the kill switch',
    'yanking is not taken here');
}

module.exports = { handlePush, handleYank, checked, fileNameOf };
