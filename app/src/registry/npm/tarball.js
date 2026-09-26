// npm tarballs. every check runs again here, a lockfile goes straight to the file.
// Author: Tim Rice

const semver = require('semver');
const db = require('../../db');
const policy = require('../../policy');
const upstream = require('./upstream');
const cache = require('./cache');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const artifacts = require('../../storage/artifacts');
const quarantine = require('../../policy/quarantine');
const license = require('../../policy/licenses');
const cooloff = require('../../policy/cooloff');
const typosquat = require('../../policy/typosquat');
const killswitch = require('../../policy/killswitch');
const waivers = require('../../policy/waivers');
const resolution = require('../../policy/resolution');
const log = require('../../logger');
const { record, notePulled } = require('../shared/access');
const { scanBeforeServe, killedFile, downloader } = require('../shared/serving');
const { refuse, openRequest, explicitlyAllowed, countServed, countBlocked } = require('./client');

// why this exact version is still too new, or null. no publish time known counts as setting says
async function npmCooling(name, version, verdict, scope) {
  if (!cooloff.enabled() || cooloff.exempt(name) || cooloff.pinned(verdict, version)) return null;
  if (await waivers.coolingWaived('npm', name, version, scope)) return null;
  const doc = await upstream.getPackument(name, 'full').then((r) => r.doc).catch(() => null);
  return cooloff.reasonFor(doc && doc.time ? doc.time[version] : null);
}

async function serveTarball(req, res, name, filename) {
  if (!upstream.validName(name)) {
    record(req, { action: 'error', status: 400, reason: 'bad package name' });
    return res.status(400).json({ error: 'that is not a valid package name' });
  }

  const short = name.includes('/') ? name.split('/')[1] : name;
  if (!filename.startsWith(`${short}-`) || !filename.endsWith('.tgz')) {
    record(req, { package_name: name, action: 'error', status: 400, reason: 'tarball name does not match' });
    return res.status(400).json({ error: 'that tarball name does not belong to that package' });
  }
  const version = filename.slice(short.length + 1, -4);
  if (!semver.valid(version)) {
    record(req, { package_name: name, action: 'error', status: 400, reason: 'bad version' });
    return res.status(400).json({ error: 'that is not a valid version' });
  }

  const dead = await killswitch.check('npm', name, version);
  if (dead) {
    record(req, { package_name: name, version, action: 'deny', status: 403, reason: dead.reason, blocked_by: 'killswitch' });
    return refuse(res, req, name, version, { reason: dead.reason });
  }
  const verdict = await policy.checkVersion(name, version, undefined, policy.scopeOf(req));
  if (!verdict.allowed && !db.settings.getBool('audit_mode')) {
    record(req, {
      package_name: name,
      version,
      action: 'deny',
      status: 403,
      reason: verdict.reason,
      rule_id: verdict.rule && verdict.rule.id
    });
    countBlocked(name);
    if (!verdict.lifecycle) await openRequest(req, name, version, verdict.reason);
    return refuse(res, req, name, version, verdict);
  }
  // learning mode: the exact version pulled goes on the request, unless an allow rule already covers it
  if (db.settings.getBool('audit_mode') && !explicitlyAllowed(verdict)) {
    openRequest(req, name, version, verdict.reason, { source: 'learning' }).catch(() => {});
  }

  // a lockfile goes straight to the tarball, so the name gets checked here too
  const squat = await typosquat.verdict('npm', name);
  if (squat && squat.block) {
    record(req, { package_name: name, version, action: 'deny', status: 403, reason: squat.reason, blocked_by: 'typosquat' });
    countBlocked(name);
    await openRequest(req, name, version, squat.reason);
    return refuse(res, req, name, version, { reason: squat.reason });
  }

  // license first, enforce turns it into a quarantine hold the next line picks up
  const lic = await license.gate({ ecosystem: 'npm', packageName: name, version, filename: artifacts.npmFilename(name, version) });
  if (lic && lic.unavailable) {
    record(req, { package_name: name, version, action: 'deny', status: 503, reason: lic.reason, blocked_by: 'license' });
    return res.status(503).json({ error: `${name}@${version}: ${lic.reason}`, reason: lic.reason, package: name, version });
  }

  // quarantine after the rules. rejected, or held in strict mode, is a no
  const held = await quarantine.verdict('npm', name, version, artifacts.npmFilename(name, version));
  if (held && held.refuse) {
    record(req, { package_name: name, version, action: 'deny', status: 403, reason: held.reason, blocked_by: held.source === 'malware' ? 'malware' : 'quarantine' });
    return refuse(res, req, name, version, { reason: held.reason });
  }

  // a lockfile asking straight for a version safe resolution leaves out gets told why
  const risky = db.settings.getBool('audit_mode') ? null : await resolution.securityReason('npm', name, version, policy.scopeOf(req));
  if (risky) {
    record(req, { package_name: name, version, action: 'deny', status: 403, reason: risky, blocked_by: 'resolution' });
    return refuse(res, req, name, version, { reason: risky });
  }
  // same for a version still too new
  const young = await npmCooling(name, version, verdict, policy.scopeOf(req));
  if (young) {
    record(req, { package_name: name, version, action: 'deny', status: 403, reason: young, blocked_by: 'cooloff' });
    return refuse(res, req, name, version, { reason: young });
  }

  try {
    const result = await upstream.getTarball(name, version, undefined, { serve: true });

    const deadFile = await killedFile(result.artifactId);
    if (deadFile) {
      record(req, { package_name: name, version, action: 'deny', status: 403, reason: deadFile.reason, blocked_by: 'killswitch' });
      return refuse(res, req, name, version, { reason: deadFile.reason });
    }

    const blocked = await scanBeforeServe({ ecosystem: 'npm', name, version, filename: artifacts.npmFilename(name, version), artifactId: result.artifactId });
    if (blocked) {
      record(req, { package_name: name, version, action: 'deny', status: blocked.status, reason: blocked.reason, blocked_by: blocked.by });
      return res.status(blocked.status).json({ error: `${name}@${version}: ${blocked.reason}`, reason: blocked.reason, package: name, version });
    }

    res.set('content-type', 'application/octet-stream');
    res.set('cache-control', 'private, max-age=31536000, immutable');

    const warn = db.settings.getBool('audit_warn_install');
    const keep = db.settings.getBool('audit_log_downloads');
    const who = downloader(req, result.cacheHit);
    const finding = warn || keep ? await audit.findingFor(name, version).catch(() => null) : null;

    // npm shows an npm-notice header as a notice line during install
    const notices = [];
    if (held && held.warn) notices.push(`QUARANTINE: ${name}@${version} ${held.reason}`);
    if (finding && warn) notices.push(`SECURITY: ${audit.warningLine(finding)}`);
    if (lic && lic.warn) notices.push(license.noticeLine(`${name}@${version}`, lic));
    if (squat && squat.warn) notices.push(`TYPOSQUAT: ${name} ${squat.reason}`);
    if (lic && !lic.stored) license.save(result.artifactId, lic).catch(() => {});
    if (notices.length) res.set('npm-notice', notices.join(' | ').replace(/[^\x20-\x7e]/g, ' '));
    if (finding && keep) {
      audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
    }

    // first time through, ask the feed now instead of waiting for the scan
    if (!result.cacheHit) {
      cvescan.checkVersion(name, version)
        .then((found) => (found && keep ? audit.noteDownload(found, who) : null))
        .catch(() => {});
    }

    record(req, {
      package_name: name,
      version,
      pulled_version: version,
      pulled_exact: 1,
      action: verdict.allowed ? 'allow' : 'audit',
      bytes: result.size,
      cache_hit: result.cacheHit ? 1 : 0
    });
    notePulled(req, name, version);
    resolution.noteSelected(req, 'npm', name, version);
    // real package, not a scanner
    countServed(name);
    artifacts.touch(result.artifactId);

    if (result.buffer) return res.send(result.buffer);
    res.set('content-length', String(result.size));
    const stream = cache.openTarball(result);
    // a file coming back from a bucket can fail part way, a cut connection beats half a tarball
    stream.on('error', (err) => {
      log.error(`could not send ${name}@${version}`, err.message);
      res.destroy(err);
    });
    // an unkept download was lent to this request alone, it goes once the response is done either way
    if (result.temporary) res.on('close', () => require('fs').promises.unlink(result.file).catch(() => {}));
    return stream.pipe(res);
  } catch (err) {
    record(req, { package_name: name, version, action: 'error', status: err.status || 502, reason: err.message });
    return res.status(err.status || 502).json({ error: err.message });
  }
}

module.exports = { serveTarball, npmCooling };
