// What pod asks for: the CDN's version file, the shards of pods and versions, podspecs, and the source archives.
// Author: Tim Rice
//
// a shard is rebuilt with only the pods and versions the rules let through, so pod only ever resolves to an allowed
// version. a podspec is handed out with its source pointed at this box, and the archive behind that address is checked
// again when it is asked for, fetched, kept and scanned like any package

const db = require('../../db');
const audit = require('../../audit');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const podName = require('../../ecosystems/cocoapods/name');
const podVersion = require('../../ecosystems/cocoapods/version');
const versionFilter = require('../shared/versions');
const gate = require('../shared/gate');
const access = require('../shared/access');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const log = require('../../logger');
const { record, text, refuse, failed, auditOnly, looksLikePodClient } = require('./respond');

const adapter = () => ecosystems.adapter('cocoapods');

async function versionFile(req, res) {
  try {
    const body = await upstream.versionFile();
    record(req, { action: 'allow', reason: 'CocoaPods-version.yml' });
    res.set('content-type', 'text/yaml; charset=utf-8');
    return res.status(200).send(body);
  } catch (err) {
    return failed(req, res, err, {});
  }
}

// the CDN lists deprecated and all pods too. nothing here depends on them, so they are empty
function emptyList(req, res) {
  record(req, { action: 'allow', reason: 'empty list' });
  res.set('content-type', 'text/plain; charset=utf-8');
  return res.status(200).send('');
}

// the versions of one pod this caller may see
async function visibleVersions(req, name, versions) {
  // most pods are a GitHub tag, a tar.gz. an archive of another type is still checked on its own when it is asked for
  const filenameOf = (v) => upstream.archiveName(name, v, 'tar.gz');
  const { allowed } = await versionFilter.visible({
    ecosystem: 'cocoapods', adapter: adapter(), name, versions: versions.map((v) => ({ version: v, published: null })),
    fileOf: filenameOf, scope: policy.scopeOf(req), lenient: auditOnly()
  });
  return allowed.map((v) => v.version);
}

// a shard, with only the pods and versions allowed. a pod no rule mentions at all is left out before any version of it
// is looked at, a shard holds a few hundred of them
async function serveShard(req, res, file) {
  let got;
  try {
    got = await upstream.shard(file);
  } catch (err) {
    return failed(req, res, err, {});
  }
  const lines = [];
  const scope = policy.scopeOf(req);
  for (const [name, versions] of got.pods) {
    if (!auditOnly() && !(await policy.checkPackage(name, adapter(), scope)).allowed) continue;
    const ok = await visibleVersions(req, name, versions);
    if (ok.length) lines.push(`${name}/${ok.join('/')}`);
  }
  record(req, { action: 'allow', reason: `${file}, ${lines.length} of ${got.pods.size} pods`, cache_hit: got.cacheHit ? 1 : 0 });
  res.set('content-type', 'text/plain; charset=utf-8');
  return res.status(200).send(lines.length ? `${lines.join('\n')}\n` : '');
}

// Specs/d/a/2/Alamofire/5.9.1/Alamofire.podspec.json, the source pointed at this box
async function servePodspec(req, res, parts) {
  const [a, b, c, name, v, file] = parts;
  if (!podName.valid(name) || !podVersion.valid(v) || file !== `${name}.podspec.json` || podName.shard(name).join('') !== `${a}${b}${c}`) {
    record(req, { action: 'error', status: 404, reason: 'bad podspec address' });
    return text(res, 404, 'there is no such podspec');
  }
  let known;
  try {
    known = await upstream.versions(name);
  } catch (err) {
    return failed(req, res, err, { package_name: name, version: v });
  }
  if (!known.includes(v)) {
    record(req, { package_name: name, version: v, action: 'deny', status: 404, reason: 'not a version of the pod' });
    return refuse(res, name, v, 'the CDN has no such version', 404);
  }
  // the podspec is not the code, but handing it out is what lets pod go and get the code, so it gets the rules too
  const verdict = await policy.checkVersion(name, v, adapter(), policy.scopeOf(req));
  const ok = (await visibleVersions(req, name, [v])).length > 0;
  if (!ok && !auditOnly()) {
    record(req, { package_name: name, version: v, action: 'deny', status: 403, reason: verdict.reason, rule_id: verdict.rule ? verdict.rule.id : undefined });
    return refuse(res, name, v, verdict.allowed ? 'it is not offered here (a kill, a hold or an advisory)' : verdict.reason, 403);
  }
  let spec;
  try {
    spec = await upstream.podspec(name, v);
  } catch (err) {
    return failed(req, res, err, { package_name: name, version: v });
  }
  const src = upstream.sourceOf(spec);
  if (src.refuse) {
    record(req, { package_name: name, version: v, action: 'deny', status: 403, reason: src.refuse });
    return refuse(res, name, v, `it can not be mirrored here: ${src.refuse}`, 403, false);
  }
  const out = { ...spec };
  out.source = { http: `${access.baseUrl(req)}/cocoapods/archives/${encodeURIComponent(name)}/${encodeURIComponent(v)}/${encodeURIComponent(upstream.archiveName(name, v, src.ext))}`, type: src.ext === 'tar.gz' ? 'tgz' : src.ext === 'tar.bz2' ? 'tbz' : src.ext === 'tar.xz' ? 'txz' : src.ext };
  if (src.flatten) out.source.flatten = true;
  record(req, { package_name: name, version: v, action: verdict.allowed ? 'allow' : 'audit', reason: 'podspec' });
  res.set('content-type', 'application/json');
  return res.status(200).send(JSON.stringify(out, null, 2));
}

// archives/<pod>/<version>/<pod>-<version>.<ext>: the code, checked, fetched, kept and scanned
async function serveArchive(req, res, name, v, file) {
  if (!podName.valid(name) || !podVersion.valid(v) || !Object.values(upstream.ARCHIVE_TYPES).some((ext) => file === upstream.archiveName(name, v, ext))) {
    record(req, { action: 'error', status: 404, reason: 'bad archive address' });
    return text(res, 404, 'there is no such archive');
  }
  let known;
  try {
    known = await upstream.versions(name);
  } catch (err) {
    return failed(req, res, err, { package_name: name, version: v });
  }
  if (!known.includes(v)) {
    record(req, { package_name: name, version: v, action: 'deny', status: 404, reason: 'not a version of the pod' });
    return refuse(res, name, v, 'the CDN has no such version', 404);
  }
  const g = { ecosystem: 'cocoapods', adapter: adapter(), name, version: v, filename: file, published: null, pin: v, looksLikeClient: looksLikePodClient(req) };
  const pre = await gate.before(req, g);
  if (pre.refused) {
    record(req, { package_name: name, version: v, action: 'deny', status: pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    return refuse(res, name, v, pre.refused.reason, pre.refused.status);
  }
  let got;
  try {
    got = await upstream.getArchive(name, v);
  } catch (err) {
    return failed(req, res, err, { package_name: name, version: v });
  }
  if (got.filename !== file) {
    record(req, { package_name: name, version: v, action: 'error', status: 404, reason: `the source is ${got.filename}` });
    return text(res, 404, `the source of ${name} ${v} is ${got.filename}`);
  }
  const post = await gate.after(g, got);
  if (post) {
    record(req, { package_name: name, version: v, action: 'deny', status: post.status, reason: post.reason, blocked_by: post.by });
    return refuse(res, name, v, post.reason, post.status === 503 ? 503 : 403);
  }
  const keep = db.settings.getBool('audit_log_downloads');
  if (keep) {
    const finding = await audit.findingFor(name, v, 'cocoapods').catch(() => null);
    if (finding) audit.noteDownload(finding, downloader(req, got.cacheHit)).catch((err) => log.error('could not record a download', err.message));
  }
  resolution.noteSelected(req, 'cocoapods', name, v);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  record(req, { package_name: name, version: v, pulled_version: v, pulled_exact: 1, action: pre.verdict.allowed ? 'allow' : 'audit', bytes: got.size, cache_hit: got.cacheHit ? 1 : 0 });
  artifacts.touch(got.artifactId);
  res.set('content-type', 'application/octet-stream');
  res.set('content-length', String(got.size));
  res.set('cache-control', 'private, max-age=31536000, immutable');
  if (req.method === 'HEAD') return res.end();
  const stream = upstream.open(got);
  stream.on('error', (err) => {
    log.error(`could not send ${file}`, err.message);
    res.destroy(err);
  });
  return stream.pipe(res);
}

module.exports = { versionFile, emptyList, serveShard, servePodspec, serveArchive };
