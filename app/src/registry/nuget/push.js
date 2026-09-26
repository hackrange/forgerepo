// dotnet nuget push, for reserved package ids only. a pushed version never changes and is never deleted or unlisted,
// like npm publish and twine upload here.
// Author: Tim Rice
//
// the .nupkg goes through the same store, hold and scan as anything fetched. what the feed says about a reserved id
// comes from what was pushed here, never from nuget.org, so nobody can publish the same id outside and have it
// installed instead. the id, version, license and dependencies are read from the .nuspec inside the package

const crypto = require('crypto');
const config = require('../../config');
const auth = require('../../security/auth');
const artifacts = require('../../storage/artifacts');
const docs = require('../../db/repositories/package-documents');
const nugetName = require('../../ecosystems/nuget/name');
const nugetVersion = require('../../ecosystems/nuget/version');
const privateNames = require('../../policy/private-names');
const published = require('../shared/published');
const multipart = require('../shared/multipart');
const zip = require('../shared/zip');
const { readBody } = require('../shared/body');
const { record, json, warn } = require('./respond');
const log = require('../../logger');

const ECO = 'nuget';
const MAX_NUSPEC_BYTES = 1024 * 1024;
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// the publisher's token: the API key dotnet sends, or the password of the source's credentials
function pusherOf(req) {
  const token = req.npmIdentity;
  if (!token) throw httpErr(401, 'pushing needs a token: dotnet nuget push --api-key <your token>');
  if (!auth.can({ role: token.role }, 'packages:publish')) {
    throw httpErr(403, `${token.username} cannot push here, it needs the publisher, approver or admin role`);
  }
  return token;
}

const XML_TEXT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const unxml = (s) => String(s).replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos);/gi, (all, code) => {
  if (code[0] !== '#') return XML_TEXT[code.toLowerCase()];
  const n = code[1].toLowerCase() === 'x' ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
  return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
}).trim();

// the elements of a .nuspec are found with indexOf, not regexes like /<name\b[^>]*>([\s\S]*?)<\/name>/, which go
// quadratic on a file stuffed with openings that never close. each helper gives what that regex would have
const WORD = /\w/;

// the first <name ...>inner</name>, as { attrs, inner }, or null
function element(text, name) {
  const open = `<${name}`;
  for (let at = text.indexOf(open); at >= 0; at = text.indexOf(open, at + 1)) {
    if (WORD.test(text[at + open.length] || '')) continue;
    const gt = text.indexOf('>', at + open.length);
    if (gt < 0) return null;
    const end = text.indexOf(`</${name}>`, gt + 1);
    if (end < 0) return null;
    return { attrs: text.slice(at + open.length, gt), inner: text.slice(gt + 1, end) };
  }
  return null;
}

// the first few <name ...> opening tags, whole
function openTags(text, name, limit) {
  const open = `<${name}`;
  const out = [];
  for (let at = text.indexOf(open); at >= 0 && out.length < limit; ) {
    if (WORD.test(text[at + open.length] || '')) {
      at = text.indexOf(open, at + 1);
      continue;
    }
    const gt = text.indexOf('>', at + open.length);
    if (gt < 0) break;
    out.push(text.slice(at, gt + 1));
    at = text.indexOf(open, gt + 1);
  }
  return out;
}

// the first few <group .../> and <group ...>body</group>, as { attrs, body }, body undefined when self closed
function groupsOf(text, limit) {
  const out = [];
  // where the next </group> is, -1 once there are none left, so a run of groups that never close is not searched again
  let close = 0;
  for (let at = text.indexOf('<group'); at >= 0 && out.length < limit; ) {
    if (WORD.test(text[at + 6] || '')) {
      at = text.indexOf('<group', at + 1);
      continue;
    }
    const gt = text.indexOf('>', at + 6);
    if (gt < 0) break;
    if (gt > at + 6 && text[gt - 1] === '/') {
      out.push({ attrs: text.slice(at + 6, gt - 1), body: undefined });
      at = text.indexOf('<group', gt + 1);
      continue;
    }
    if (close >= 0 && close <= gt) close = text.indexOf('</group>', gt + 1);
    // an open group that never closes is skipped, as a self closed one further on still counts
    if (close >= 0) out.push({ attrs: text.slice(at + 6, gt), body: text.slice(gt + 1, close) });
    at = text.indexOf('<group', close >= 0 ? close + 8 : gt + 1);
  }
  return out;
}

// what a .nuspec says: id, version, license expression and dependency groups. a DOCTYPE or an entity is refused
// outright, a nuspec never needs one and they are how XML files are turned against their readers
function readNuspec(text) {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw httpErr(400, 'the .nuspec declares a DOCTYPE or entities, which a package never needs');
  const meta = element(text, 'metadata');
  if (!meta) throw httpErr(400, 'the .nuspec has no metadata');
  const tag = (name) => {
    const m = element(meta.inner, name);
    return m ? unxml(m.inner) : '';
  };
  const lic = element(meta.inner, 'license');
  const license = lic && /type\s*=\s*["']expression["']/.test(lic.attrs) ? unxml(lic.inner).slice(0, 255) : null;
  const attr = (el, name) => {
    const m = new RegExp(`\\s${name}\\s*=\\s*"([^"]*)"|\\s${name}\\s*=\\s*'([^']*)'`).exec(el);
    return m ? unxml(m[1] === undefined ? m[2] : m[1]) : '';
  };
  const dependency = (el) => ({ id: attr(el, 'id'), range: attr(el, 'version').slice(0, 128) });
  const deps = [];
  const block = element(meta.inner, 'dependencies');
  if (block) {
    const groups = groupsOf(block.inner, 50);
    if (groups.length) {
      for (const g of groups) {
        deps.push({ framework: attr(g.attrs, 'targetFramework').slice(0, 64), dependencies: openTags(String(g.body || ''), 'dependency', 200).map(dependency).filter((d) => nugetName.valid(d.id)) });
      }
    } else {
      deps.push({ framework: '', dependencies: openTags(block.inner, 'dependency', 200).map(dependency).filter((d) => nugetName.valid(d.id)) });
    }
  }
  return { id: tag('id'), version: tag('version'), license, deps };
}

// everything about the push checked before anything is held or stored
async function checked(req) {
  const raw = await readBody(req, config.maxImportBytes);
  const form = multipart.parse(raw, req.headers['content-type'], { fileBytes: config.maxImportBytes });
  if (form.files.length !== 1) throw httpErr(400, 'a push carries exactly one .nupkg');
  const data = form.files[0].data;
  if (!data.length || !data.subarray(0, 4).equals(ZIP_MAGIC)) throw httpErr(400, 'that is not a .nupkg, a package is a zip');
  let spec;
  try {
    const list = zip.entries(data);
    // the manifest sits at the top of the package, one of it
    const specs = list.filter((e) => !e.name.includes('/') && /\.nuspec$/i.test(e.name));
    if (specs.length !== 1) throw httpErr(400, `a package has exactly one .nuspec at its top, this one has ${specs.length}`);
    spec = readNuspec(zip.read(data, specs[0], MAX_NUSPEC_BYTES).toString('utf8'));
  } catch (err) {
    if (err.status) throw err;
    throw httpErr(400, `the package could not be read: ${err.message}`);
  }
  if (!nugetName.valid(spec.id)) throw httpErr(400, 'the .nuspec has no valid package id');
  const version = nugetVersion.normalize(spec.version);
  if (!version) throw httpErr(400, 'the .nuspec has no valid version');
  const folded = nugetName.fold(spec.id);
  const hit = await privateNames.reservedBy(ECO, folded);
  if (!hit) throw httpErr(403, `${spec.id} is not a reserved package id, and only reserved ids can be pushed here. An admin reserves them under Settings, Registries`);
  return { ...spec, folded, version, data, sha256: crypto.createHash('sha256').update(data).digest('hex') };
}

// pushes of one id, one at a time, so two versions pushed together both land in its list
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

function answer(res, status, message) {
  warn(res, message);
  res.statusMessage = String(message).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 300);
  return json(res, status, status < 300 ? { ok: true, message } : { error: message });
}

async function handlePush(req, res) {
  let id = null;
  try {
    const token = pusherOf(req);
    const up = await checked(req);
    id = up.id;
    const filename = `${up.folded}.${up.version}.nupkg`;
    const hold = await exclusive(up.folded, async () => {
      const held = await docs.get(ECO, up.folded, 'summary');
      const own = held && held.source === published.SOURCE ? held.doc : null;
      // only what was pushed here counts. a public copy cached before the id was reserved is never this package
      const kept = await artifacts.locate(ECO, up.id, up.version, filename);
      if ((own && own.versions.some((v) => v.version === up.version)) || (kept && kept.upstream === published.SOURCE)) {
        throw httpErr(409, `${up.id} ${up.version} is already pushed, and a pushed version never changes. Push a new version`);
      }
      const placed = await published.holdBeforeStore({ ecosystem: ECO, packageName: up.id, version: up.version, filename }, token.username, up.data);
      const stored = await artifacts.keep({ ecosystem: ECO, packageName: up.id, version: up.version, filename, upstream: published.SOURCE }, { buffer: up.data });
      if (stored.sha256 !== up.sha256) throw httpErr(409, `${up.id} ${up.version} was pushed a moment ago, or fetched from outside before the id was reserved, with different contents. Push a new version`);
      const doc = own || { id: up.id, versions: [] };
      doc.versions.push({ version: up.version, listed: true, published: new Date().toISOString(), license: up.license, deprecated: null, deps: up.deps });
      doc.versions.sort((a, b) => nugetVersion.compare(a.version, b.version));
      await docs.put(ECO, up.folded, 'summary', doc, published.SOURCE);
      return placed;
    });

    await auth.audit(token.userId, token.username, auth.clientIp(req), 'package.publish', `nuget:${up.id}@${up.version}`,
      `${filename}, ${up.data.length} bytes, held under ${hold.source}`,
      { after: { version: up.version, filename, sha256: up.sha256, hold: hold.source } });
    require('../../integrations/events').emit('package.published', {
      ecosystem: ECO, package: up.id, version: up.version, filename, artifactHash: up.sha256, user: token.username,
      sourceIp: auth.clientIp(req), reason: hold.scanning ? 'pushed, waiting for its malware scan' : 'pushed, waiting for an admin to release it', action: 'published'
    });
    log.info(`${token.username} pushed ${up.id} ${up.version}, held under ${hold.source}`);
    record(req, { package_name: up.id, version: up.version, action: 'allow', status: 201, bytes: up.data.length, reason: `pushed, held under ${hold.source}` });
    if (hold.note) return answer(res, 201, `${up.id} ${up.version} is pushed and held: ${hold.note}. An admin has to release it`);
    return answer(res, 201, `${up.id} ${up.version} is pushed. It is listed once its malware scan is clean${hold.scanning ? '' : ', or an admin releases it'}`);
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) log.error(`a push of ${id || 'a package'} failed`, err);
    record(req, { package_name: id, action: status < 500 ? 'deny' : 'error', status, reason: status >= 500 ? 'push failed' : err.message });
    if (status === 401) res.set('www-authenticate', 'Basic realm="ForgeRepo", charset="UTF-8"');
    return answer(res, status, status >= 500 ? 'the push failed on our end' : err.message);
  }
}

// dotnet nuget delete: a pushed version stays, the same as everywhere else here
function handleDelete(req, res) {
  record(req, { action: 'deny', status: 405, reason: 'delete or unlist attempt' });
  res.set('allow', 'PUT');
  return answer(res, 405, 'a pushed version is never deleted or unlisted here. Push a new version, or ask an admin to block this one with a rule or the kill switch');
}

module.exports = { readNuspec, checked, handlePush, handleDelete };
