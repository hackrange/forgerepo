// A .nupkg going out. checked AGAIN here: anyone can type the address of a version the lists never offered.
// Author: Tim Rice

const db = require('../../db');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const nugetName = require('../../ecosystems/nuget/name');
const nugetVersion = require('../../ecosystems/nuget/version');
const gate = require('../shared/gate');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const log = require('../../logger');
const { record, json, refuse, failed, looksLikeNugetClient } = require('./respond');

// /v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg, all lower case, the only file this feed hands out
async function servePackage(req, res) {
  const [rawId, rawVersion, file] = [req.params[0], req.params[1], req.params[2]];
  const version = nugetVersion.normalize(rawVersion);
  if (!nugetName.valid(rawId) || !version || String(file).toLowerCase() !== upstream.fileName(rawId, version)) {
    record(req, { action: 'error', status: 404, reason: 'bad package address' });
    return json(res, 404, { error: 'there is no such package file' });
  }
  let summary;
  try {
    summary = (await upstream.summary(rawId)).doc;
  } catch (err) {
    return failed(req, res, err, { package_name: rawId, version });
  }
  const id = summary.id;
  const known = summary.versions.find((v) => v.version === version);
  if (!known) {
    record(req, { package_name: id, version, action: 'deny', status: 404, reason: 'not a version of the package' });
    return refuse(res, id, version, 'the feed has no such version', 404);
  }
  const f = {
    ecosystem: 'nuget', adapter: ecosystems.adapter('nuget'), name: id, version, filename: upstream.fileName(id, version),
    published: known.published, pin: version, looksLikeClient: looksLikeNugetClient(req)
  };
  const pre = await gate.before(req, f);
  if (pre.refused) {
    record(req, { package_name: id, version, action: 'deny', status: pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    return refuse(res, id, version, pre.refused.reason, pre.refused.status);
  }

  let got;
  try {
    got = await upstream.getPackage(id, version);
  } catch (err) {
    return failed(req, res, err, { package_name: id, version });
  }
  const post = await gate.after(f, got);
  if (post) {
    record(req, { package_name: id, version, action: 'deny', status: post.status, reason: post.reason, blocked_by: post.by });
    return refuse(res, id, version, post.reason, post.status === 503 ? 503 : 403);
  }

  const keep = db.settings.getBool('audit_log_downloads');
  const who = downloader(req, got.cacheHit);
  if (keep) {
    const finding = await audit.findingFor(id, version, 'nuget').catch(() => null);
    if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
  }
  // a version this box has not held before gets asked about now, not at the next scheduled scan
  if (!got.cacheHit) {
    cvescan.checkVersion(id, version, 'nuget').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
  }
  record(req, {
    package_name: id, version, pulled_version: version, pulled_exact: 1, action: pre.verdict.allowed ? 'allow' : 'audit',
    bytes: got.size, cache_hit: got.cacheHit ? 1 : 0
  });
  artifacts.touch(got.artifactId);
  resolution.noteSelected(req, 'nuget', id, version);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});

  res.set('content-type', 'application/octet-stream');
  res.set('content-length', String(got.size));
  res.set('cache-control', 'private, max-age=31536000, immutable');
  if (req.method === 'HEAD') return res.end();
  const stream = upstream.open(got);
  stream.on('error', (err) => {
    log.error(`could not send ${f.filename}`, err.message);
    res.destroy(err);
  });
  return stream.pipe(res);
}

module.exports = { servePackage };
