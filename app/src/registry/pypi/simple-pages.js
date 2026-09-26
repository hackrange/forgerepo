// The simple index: the project list, and one project's page of files.
// Author: Tim Rice

const policy = require('../../policy');
const simple = require('../../ecosystems/pypi/simple');
const pypi = require('./upstream');
const killswitch = require('../../policy/killswitch');
const typosquat = require('../../policy/typosquat');
const resolution = require('../../policy/resolution');
const { MOUNT, record, text, redirect, auditOnly, askFor, refuse, failed, fileUrl, projectFrom } = require('./respond');
const { adapter, filterPage } = require('./filter');

const NOT_ACCEPTABLE = 'this index serves application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html and text/html';

async function projectList(req, res) {
  if (!req.path.endsWith('/')) return redirect(req, res, `${MOUNT}/simple/`);
  const kind = simple.negotiate(req.get('accept'), req.query.format);
  if (!kind) return text(res, 406, NOT_ACCEPTABLE);

  const listed = [];
  for (const name of await pypi.knownProjects()) {
    if (await killswitch.check('pypi', name, null)) continue;
    if ((await policy.checkPackage(name, adapter, policy.scopeOf(req))).allowed || auditOnly()) listed.push(name);
  }
  const body = simple.renderIndex(listed, kind);
  record(req, { action: 'allow', reason: `project list, ${listed.length} project(s)`, bytes: Buffer.byteLength(body) });
  res.set('content-type', simple.CONTENT_TYPE[kind]);
  res.set('vary', 'Accept');
  res.set('cache-control', 'no-cache');
  return res.send(body);
}

async function projectPage(req, res) {
  const raw = req.params[0];
  const project = projectFrom(raw);
  if (!project) {
    record(req, { action: 'error', status: 404, reason: 'bad project name' });
    return text(res, 404, 'that is not a valid project name');
  }
  // PEP 503: one address per project, normalized name plus trailing slash. no exceptions
  if (raw !== project || !req.path.endsWith('/')) return redirect(req, res, `${MOUNT}/simple/${project}/`);

  const kind = simple.negotiate(req.get('accept'), req.query.format);
  if (!kind) return text(res, 406, NOT_ACCEPTABLE);

  const dead = await killswitch.check('pypi', project, null);
  if (dead) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: dead.reason, blocked_by: 'killswitch' });
    return refuse(req, res, project, null, dead.reason);
  }
  const verdict = await policy.checkPackage(project, adapter, policy.scopeOf(req));
  if (!verdict.allowed && !auditOnly()) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: verdict.reason, rule_id: verdict.rule && verdict.rule.id });
    await askFor(req, project, null, verdict.reason);
    return refuse(req, res, project, null, verdict.reason);
  }
  if (!verdict.allowed) record(req, { package_name: project, action: 'audit', reason: `would have blocked: ${verdict.reason}` });
  // learning mode: nothing covers this project yet, so it goes in the approval queue
  if (auditOnly() && !(verdict.allowed && verdict.rule && verdict.rule.kind === 'allow')) {
    askFor(req, project, null, verdict.reason, 'learning').catch(() => {});
  }
  const squat = await typosquat.verdict('pypi', project);
  if (squat && squat.block) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: squat.reason, blocked_by: 'typosquat' });
    await askFor(req, project, null, squat.reason);
    return refuse(req, res, project, null, squat.reason);
  }

  let got;
  try {
    got = await pypi.getProject(project);
  } catch (err) {
    return failed(req, res, err, { package_name: project });
  }

  const { files, versions, removed, excluded } = await filterPage(project, got.doc, policy.scopeOf(req));
  resolution.record(req, {
    ecosystem: 'pypi',
    name: project,
    offered: new Set(files.map((f) => f.version)).size,
    latest: versions && versions.length ? versions[versions.length - 1] : null,
    excluded
  });
  if (!files.length && got.doc.files.length && !auditOnly()) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: 'every release is blocked' });
    await askFor(req, project, null, 'no release of this project is approved');
    return refuse(req, res, project, null, 'no release of this project is approved');
  }

  const body = simple.renderProject({ name: project, files, versions }, kind, (f) => fileUrl(req, project, f.filename));
  record(req, {
    package_name: project,
    action: 'allow',
    cache_hit: got.cacheHit ? 1 : 0,
    bytes: Buffer.byteLength(body),
    reason: removed ? `${removed} file(s) filtered out` : null
  });
  res.set('content-type', simple.CONTENT_TYPE[kind]);
  res.set('vary', 'Accept');
  res.set('cache-control', 'no-cache');
  return res.send(body);
}

module.exports = { projectList, projectPage };
