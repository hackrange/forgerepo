// PyPI files. checked AGAIN on request, anyone can type a filename.
// Author: Tim Rice

const db = require('../../db');
const policy = require('../../policy');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const simple = require('../../ecosystems/pypi/simple');
const pypi = require('./upstream');
const artifacts = require('../../storage/artifacts');
const quarantine = require('../../policy/quarantine');
const license = require('../../policy/licenses');
const typosquat = require('../../policy/typosquat');
const killswitch = require('../../policy/killswitch');
const resolution = require('../../policy/resolution');
const log = require('../../logger');
const { scanBeforeServe, killedFile, downloader } = require('../shared/serving');
const { record, text, auditOnly, askFor, refuse, failed, projectFrom } = require('./respond');
const { adapter, pypiCooling } = require('./filter');

async function serveFile(req, res) {
  const project = projectFrom(req.params[0]);
  const requested = req.params[1];
  // we only ever hand out normalized addresses, so anything else isn't one of ours
  if (!project || project !== req.params[0] || !simple.validFilename(requested)) {
    record(req, { action: 'error', status: 404, reason: 'bad file address' });
    return text(res, 404, 'there is no such file');
  }

  const metadata = requested.endsWith('.metadata');
  const filename = metadata ? requested.slice(0, -'.metadata'.length) : requested;
  const version = simple.releaseOf(filename, project);
  if (!version) {
    record(req, { package_name: project, action: 'error', status: 404, reason: 'file does not belong to the project' });
    return text(res, 404, `${filename} is not a file of ${project}`);
  }

  // a hash kill takes one file of a release (and its .metadata), not the whole release
  const dead = (await killswitch.check('pypi', project, version)) || (await killswitch.checkFile('pypi', project, filename));
  if (dead) {
    record(req, { package_name: project, version, action: 'deny', status: 403, reason: dead.reason, blocked_by: 'killswitch' });
    return refuse(req, res, project, version, dead.reason);
  }
  const verdict = await policy.checkVersion(project, version, adapter, policy.scopeOf(req));
  if (!verdict.allowed && !auditOnly()) {
    record(req, {
      package_name: project, version, action: 'deny', status: 403, reason: verdict.reason, rule_id: verdict.rule && verdict.rule.id
    });
    if (!verdict.lifecycle) await askFor(req, project, `==${version}`, verdict.reason);
    return refuse(req, res, project, version, verdict.reason);
  }
  // learning mode: the exact release pulled goes on the request, unless an allow rule already covers it
  if (!metadata && auditOnly() && !(verdict.allowed && verdict.rule && verdict.rule.kind === 'allow')) {
    askFor(req, project, version, verdict.reason, 'learning').catch(() => {});
  }
  const squat = await typosquat.verdict('pypi', project);
  if (squat && squat.block) {
    record(req, { package_name: project, version, action: 'deny', status: 403, reason: squat.reason, blocked_by: 'typosquat' });
    return refuse(req, res, project, version, squat.reason);
  }

  const lic = await license.gate({ ecosystem: 'pypi', packageName: project, version, filename });
  if (lic && lic.unavailable) {
    record(req, { package_name: project, version, action: 'deny', status: 503, reason: lic.reason, blocked_by: 'license' });
    return text(res, 503, `${filename}: ${lic.reason}`);
  }

  // a hold on the wheel covers its .metadata too
  const held = await quarantine.verdict('pypi', project, version, filename);
  if (held && held.refuse) {
    record(req, { package_name: project, version, action: 'deny', status: 403, reason: held.reason, blocked_by: held.source === 'malware' ? 'malware' : 'quarantine' });
    return refuse(req, res, project, version, held.reason);
  }

  const risky = auditOnly() ? null : await resolution.securityReason('pypi', project, version, policy.scopeOf(req));
  if (risky) {
    record(req, { package_name: project, version, action: 'deny', status: 403, reason: risky, blocked_by: 'resolution' });
    return refuse(req, res, project, version, risky);
  }
  const young = await pypiCooling(project, version, verdict, policy.scopeOf(req));
  if (young) {
    record(req, { package_name: project, version, action: 'deny', status: 403, reason: young, blocked_by: 'cooloff' });
    return refuse(req, res, project, version, young);
  }

  let got;
  try {
    got = await pypi.getFile(project, filename, version, { metadata });
  } catch (err) {
    return failed(req, res, err, { package_name: project, version });
  }

  const deadFile = metadata ? null : await killedFile(got.artifactId);
  if (deadFile) {
    if (got.temporary) require('fs').promises.unlink(got.file).catch(() => {});
    record(req, { package_name: project, version, action: 'deny', status: 403, reason: deadFile.reason, blocked_by: 'killswitch' });
    return refuse(req, res, project, version, deadFile.reason);
  }

  // scan before serve, on the real file. its .metadata rides on the wheel's verdict
  const blocked = metadata ? null : await scanBeforeServe({ ecosystem: 'pypi', name: project, version, filename, artifactId: got.artifactId });
  if (blocked) {
    record(req, { package_name: project, version, action: 'deny', status: blocked.status, reason: blocked.reason, blocked_by: blocked.by });
    return text(res, blocked.status, `${filename}: ${blocked.reason}`);
  }

  if (!metadata) {
    const keep = db.settings.getBool('audit_log_downloads');
    const who = downloader(req, got.cacheHit);
    if (keep) {
      const finding = await audit.findingFor(project, version, 'pypi').catch(() => null);
      if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
    }
    // new release, ask the vuln feed now
    if (!got.cacheHit) {
      cvescan.checkVersion(project, version, 'pypi')
        .then((found) => (found && keep ? audit.noteDownload(found, who) : null))
        .catch(() => {});
    }
  }

  record(req, {
    package_name: project,
    version,
    pulled_version: metadata ? null : version,
    pulled_exact: metadata ? 0 : 1,
    action: verdict.allowed ? 'allow' : 'audit',
    reason: metadata ? 'metadata' : null,
    bytes: got.size,
    cache_hit: got.cacheHit ? 1 : 0
  });
  artifacts.touch(got.artifactId);
  if (!metadata) resolution.noteSelected(req, 'pypi', project, version);
  if (!metadata && lic && !lic.stored) license.save(got.artifactId, lic).catch(() => {});

  res.set('content-type', 'application/octet-stream');
  res.set('content-length', String(got.size));
  res.set('cache-control', 'private, max-age=31536000, immutable');
  const tidy = () => {
    if (got.temporary) require('fs').promises.unlink(got.file).catch(() => {});
  };
  if (req.method === 'HEAD') {
    tidy();
    return res.end();
  }
  const stream = pypi.openFile(got);
  stream.on('error', (err) => {
    log.error(`could not send ${filename}`, err.message);
    res.destroy(err);
  });
  res.on('close', tidy);
  return stream.pipe(res);
}

module.exports = { serveFile };
