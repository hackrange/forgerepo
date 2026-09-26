// The PyPI JSON API, trimmed to what policy allows, file urls pointing back here.
// Author: Tim Rice

const policy = require('../../policy');
const pypiVersion = require('../../ecosystems/pypi/version');
const simple = require('../../ecosystems/pypi/simple');
const pypi = require('./upstream');
const quarantine = require('../../policy/quarantine');
const cooloff = require('../../policy/cooloff');
const typosquat = require('../../policy/typosquat');
const killswitch = require('../../policy/killswitch');
const waivers = require('../../policy/waivers');
const resolution = require('../../policy/resolution');
const registryMode = require('../../policy/mode');
const pypiFiles = require('../../db/repositories/pypi-files');
const { MOUNT, record, text, redirect, auditOnly, refuse, failed, normVersion, fileUrl, projectFrom } = require('./respond');
const { adapter, pypiCooling } = require('./filter');

// point file urls back here, unreadable ones dropped
function rewriteFiles(req, project, list, hidden = new Set()) {
  return (Array.isArray(list) ? list : [])
    .filter((f) => f && typeof f.filename === 'string' && simple.releaseOf(f.filename, project) && !hidden.has(f.filename))
    .map((f) => ({ ...f, url: fileUrl(req, project, f.filename) }));
}

function newestOf(versions) {
  const valid = versions.filter((v) => pypiVersion.valid(v)).sort((a, b) => pypiVersion.compare(b, a));
  return valid.find((v) => !pypiVersion.isPrerelease(v)) || valid[0] || null;
}

async function serveJson(req, res) {
  const raw = req.params[0];
  const version = req.params[1] || null;
  const project = projectFrom(raw);
  if (!project) {
    record(req, { action: 'error', status: 404, reason: 'bad project name' });
    return text(res, 404, 'that is not a valid project name');
  }
  if (raw !== project) return redirect(req, res, `${MOUNT}/pypi/${project}/${version ? `${encodeURIComponent(version)}/` : ''}json`);

  const dead = await killswitch.check('pypi', project, null);
  if (dead) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: dead.reason, blocked_by: 'killswitch' });
    return refuse(req, res, project, null, dead.reason);
  }
  const verdict = await policy.checkPackage(project, adapter, policy.scopeOf(req));
  if (!verdict.allowed && !auditOnly()) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: verdict.reason, rule_id: verdict.rule && verdict.rule.id });
    return refuse(req, res, project, null, verdict.reason);
  }
  const squat = await typosquat.verdict('pypi', project);
  if (squat && squat.block) {
    record(req, { package_name: project, action: 'deny', status: 403, reason: squat.reason, blocked_by: 'typosquat' });
    return refuse(req, res, project, null, squat.reason);
  }

  const send = (doc, fields) => {
    const body = JSON.stringify(doc);
    record(req, { package_name: project, action: 'allow', bytes: Buffer.byteLength(body), ...fields });
    res.set('content-type', 'application/json; charset=utf-8');
    res.set('cache-control', 'no-cache');
    return res.send(body);
  };

  try {
    // same quarantine hiding as the project page
    const hidden = auditOnly() ? new Set() : new Set((await quarantine.hiddenFor('pypi', project)).map((h) => h.filename));
    // lockdown: only files already cached are offered
    const onDisk = registryMode.lockdown() ? new Set((await pypiFiles.cachedFiles(project)).map((r) => r.filename)) : null;
    const cachedOnly = (list) => (onDisk ? (Array.isArray(list) ? list : []).filter((f) => f && onDisk.has(f.filename)) : list);
    // and the same safe resolution, on normalized versions
    const normV = normVersion;
    const risky = new Map();
    if (!auditOnly()) for (const [v, why] of await resolution.securityExclusions('pypi', project, policy.scopeOf(req))) risky.set(normV(v), why);
    if (version) {
      if (!pypiVersion.valid(version)) return text(res, 404, 'that is not a valid version');
      const killedOne = await killswitch.check('pypi', project, version);
      if (killedOne) {
        record(req, { package_name: project, version, action: 'deny', status: 403, reason: killedOne.reason, blocked_by: 'killswitch' });
        return refuse(req, res, project, version, killedOne.reason);
      }
      const allowed = await policy.checkVersion(project, version, adapter, policy.scopeOf(req));
      if (!allowed.allowed && !auditOnly()) {
        record(req, { package_name: project, version, action: 'deny', status: 403, reason: allowed.reason, rule_id: allowed.rule && allowed.rule.id });
        return refuse(req, res, project, version, allowed.reason);
      }
      if (risky.has(normV(version))) {
        const why = risky.get(normV(version));
        record(req, { package_name: project, version, action: 'deny', status: 403, reason: why, blocked_by: 'resolution' });
        return refuse(req, res, project, version, why);
      }
      const young = await pypiCooling(project, version, allowed, policy.scopeOf(req));
      if (young) {
        record(req, { package_name: project, version, action: 'deny', status: 403, reason: young, blocked_by: 'cooloff' });
        return refuse(req, res, project, version, young);
      }
      const got = await pypi.getJson(project, version);
      const doc = JSON.parse(JSON.stringify(got.doc));
      doc.urls = rewriteFiles(req, project, cachedOnly(doc.urls), hidden);
      delete doc.releases;
      return send(doc, { version, cache_hit: got.cacheHit ? 1 : 0 });
    }

    const got = await pypi.getJson(project);
    const doc = JSON.parse(JSON.stringify(got.doc));
    const releases = {};
    let removed = 0;
    const killedReleases = await killswitch.killedVersions('pypi', project, Object.keys(doc.releases || {}));
    const cooling = !auditOnly() && cooloff.enabled() && !cooloff.exempt(project);
    const jsonTimes = cooling ? cooloff.mergeJsonTimes(new Map(), doc.releases, normV) : null;
    for (const [v, files] of Object.entries(doc.releases || {})) {
      if (!pypiVersion.valid(v)) {
        removed += 1;
        continue;
      }
      if (killedReleases.has(v)) {
        removed += 1;
        continue;
      }
      if (!(await policy.checkVersion(project, v, adapter, policy.scopeOf(req))).allowed && !auditOnly()) {
        removed += 1;
        continue;
      }
      if (risky.has(normV(v))) {
        removed += 1;
        continue;
      }
      if (cooling && cooloff.pypiReason(jsonTimes, v, normV) && !cooloff.pinned(await policy.checkVersion(project, v, adapter, policy.scopeOf(req)), v)
        && !(await waivers.coolingWaived('pypi', project, v, policy.scopeOf(req)))) {
        removed += 1;
        continue;
      }
      const kept = cachedOnly(files);
      if (onDisk && !kept.length) {
        removed += 1;
        continue;
      }
      releases[v] = rewriteFiles(req, project, kept, hidden);
    }
    if (!Object.keys(releases).length && !auditOnly()) {
      record(req, { package_name: project, action: 'deny', status: 403, reason: 'every release is blocked' });
      return refuse(req, res, project, null, 'no release of this project is approved');
    }
    doc.releases = releases;

    // newest release blocked? swap in the newest allowed one or clients definitely go looking
    const current = doc.info && doc.info.version;
    if (!releases[current]) {
      const newest = newestOf(Object.keys(releases));
      if (newest) {
        // that release's own document, or when it can't be had (lockdown, upstream off) its files off the list
        const pinned = await pypi.getJson(project, newest).catch(() => null);
        if (pinned) {
          doc.info = pinned.doc.info;
          doc.urls = pinned.doc.urls;
          doc.vulnerabilities = pinned.doc.vulnerabilities;
        } else {
          doc.info = { ...doc.info, version: newest };
          doc.urls = releases[newest];
          // they were about a release this answer no longer offers
          delete doc.vulnerabilities;
        }
      }
    }
    doc.urls = rewriteFiles(req, project, cachedOnly(doc.urls), hidden);
    return send(doc, { cache_hit: got.cacheHit ? 1 : 0, reason: removed ? `${removed} release(s) filtered out` : null });
  } catch (err) {
    return failed(req, res, err, { package_name: project, version });
  }
}

module.exports = { serveJson, rewriteFiles, newestOf };
