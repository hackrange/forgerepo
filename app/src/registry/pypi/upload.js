// twine upload, for reserved projects only. an uploaded file never changes and is never deleted, like npm publish here.
// Author: Tim Rice
// the bytes go through the same store, hold and scan as anything fetched; serving them is the normal project page path

const crypto = require('crypto');
const config = require('../../config');
const auth = require('../../security/auth');
const artifacts = require('../../storage/artifacts');
const pypiFiles = require('../../db/repositories/pypi-files');
const pypiName = require('../../ecosystems/pypi/name');
const pypiVersion = require('../../ecosystems/pypi/version');
const simple = require('../../ecosystems/pypi/simple');
const privateNames = require('../../policy/private-names');
const published = require('../shared/published');
const pages = require('./published-pages');
const multipart = require('../shared/multipart');
const { readBody } = require('../shared/body');
const { record, text } = require('./respond');
const log = require('../../logger');

const FILETYPES = ['sdist', 'bdist_wheel'];

function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

const field = (fields, name) => (fields[name] && fields[name].length ? String(fields[name][0]).trim() : '');

function uploaderOf(req) {
  const token = req.npmIdentity;
  if (!token) throw httpErr(401, 'uploading needs a token: username __token__ and the token as the password');
  if (!auth.can({ role: token.role }, 'packages:publish')) {
    throw httpErr(403, `${token.username} cannot upload here, it needs the publisher, approver or admin role`);
  }
  return token;
}

// everything about the upload checked before anything is held or stored
async function checked(req) {
  const raw = await readBody(req, config.maxImportBytes);
  const form = multipart.parse(raw, req.headers['content-type'], { fileBytes: config.maxImportBytes });
  const action = field(form.fields, ':action');
  if (action !== 'file_upload') throw httpErr(400, `${action || 'an empty action'} is not something this index does, only file_upload`);
  const typed = field(form.fields, 'name');
  const version = field(form.fields, 'version');
  if (!pypiName.valid(typed)) throw httpErr(400, 'that is not a valid project name');
  if (!pypiVersion.valid(version)) throw httpErr(400, 'that is not a valid version');
  const project = pypiName.normalize(typed);
  const filetype = field(form.fields, 'filetype');
  if (filetype && !FILETYPES.includes(filetype)) throw httpErr(400, `${filetype} uploads are not taken, only sdist and bdist_wheel`);

  const hit = await privateNames.reservedBy('pypi', project);
  if (!hit) throw httpErr(403, `${project} is not a reserved name, and only reserved names can be uploaded here. An admin reserves them under Settings, Registries`);

  const files = form.files.filter((f) => f.field === 'content');
  if (files.length !== 1 || form.files.length !== 1) throw httpErr(400, 'an upload carries exactly one file, as the content field');
  const file = files[0];
  const released = simple.releaseOf(file.filename, project);
  if (!released || !pypiVersion.eq(released, version)) {
    throw httpErr(400, `${file.filename} is not a file of ${project} ${version}`);
  }
  if (!file.data.length) throw httpErr(400, `${file.filename} is empty`);
  const sha256 = crypto.createHash('sha256').update(file.data).digest('hex');
  const claimed = field(form.fields, 'sha256_digest').toLowerCase();
  if (claimed && claimed !== sha256) throw httpErr(400, `${file.filename} does not match the sha256 the upload says it has`);
  return { project, version, filename: file.filename, data: file.data, sha256, requiresPython: field(form.fields, 'requires_python') || null };
}

async function handleUpload(req, res) {
  let project = null;
  try {
    const token = uploaderOf(req);
    const up = await checked(req);
    project = up.project;

    const page = (await pages.read(up.project)) || { name: up.project, files: [], versions: [] };
    if (page.files.some((f) => f.filename === up.filename)) {
      throw httpErr(409, `${up.filename} is already uploaded, and an uploaded file never changes. Upload a new version`);
    }

    const file = { ecosystem: 'pypi', packageName: up.project, version: up.version, filename: up.filename };
    const hold = await published.holdBeforeStore(file, token.username, up.data);
    const legacyPath = require('./upstream').filePath(up.project, up.filename);
    const kept = await artifacts.keep({
      ecosystem: 'pypi', packageName: up.project, version: up.version, filename: up.filename, upstream: published.SOURCE, legacyPath
    }, { buffer: up.data });
    // two uploads of one file name at once: the first bytes stay, the other one is told so
    if (kept.sha256 !== up.sha256) throw httpErr(409, `${up.filename} was uploaded a moment ago with different contents`);
    await pypiFiles.cacheFile({
      project: up.project, version: up.version, filename: up.filename, path: legacyPath, size: up.data.length, sha256: up.sha256, source: published.SOURCE
    });

    // read again right before writing, so an upload of another file of the same project in the meantime is kept
    const latest = (await pages.read(up.project)) || page;
    if (!latest.files.some((f) => f.filename === up.filename)) {
      latest.files.push({
        filename: up.filename, url: `${up.project}/${up.filename}`, hashes: { sha256: up.sha256 }, requiresPython: up.requiresPython,
        yanked: false, coreMetadata: false, size: up.data.length, uploadTime: new Date().toISOString(), provenance: null
      });
    }
    latest.versions = [...new Set([...(latest.versions || []), up.version])].sort((a, b) => pypiVersion.compare(a, b));
    await pages.write(up.project, latest);

    await auth.audit(token.userId, token.username, auth.clientIp(req), 'package.publish', `pypi:${up.project}==${up.version}`,
      `${up.filename}, ${up.data.length} bytes, held under ${hold.source}`,
      { after: { version: up.version, filename: up.filename, sha256: up.sha256, hold: hold.source } });
    require('../../integrations/events').emit('package.published', {
      ecosystem: 'pypi', package: up.project, version: up.version, filename: up.filename, artifactHash: up.sha256, user: token.username,
      sourceIp: auth.clientIp(req), reason: hold.scanning ? 'uploaded, waiting for its malware scan' : 'uploaded, waiting for an admin to release it', action: 'published'
    });
    log.info(`${token.username} uploaded ${up.filename}, held under ${hold.source}`);
    record(req, { package_name: up.project, version: up.version, action: 'allow', status: 200, bytes: up.data.length, reason: `uploaded, held under ${hold.source}` });
    return text(res, 200, hold.note ? `OK, held: ${hold.note}` : 'OK');
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) log.error(`an upload to ${project || 'the index'} failed`, err);
    record(req, { package_name: project, action: status < 500 ? 'deny' : 'error', status, reason: status >= 500 ? 'upload failed' : err.message });
    if (status === 401) res.set('www-authenticate', 'Basic realm="ForgeRepo", charset="UTF-8"');
    return text(res, status, status >= 500 ? 'the upload failed on our end' : err.message);
  }
}

module.exports = { FILETYPES, uploaderOf, checked, handleUpload };
