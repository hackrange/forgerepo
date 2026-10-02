// What SwiftPM asks a package registry (SE-0292): a package's releases, one release's metadata, its Package.swift and
// its source archive, and which identity a repository URL is.
// Author: Tim Rice
//
// the release list holds only allowed versions, so a range in Package.swift resolves to one of them. the manifest and
// the archive are checked again when they are asked for, and the checksum in the metadata is of the archive this box
// keeps, which SwiftPM checks the download against

const db = require('../../db');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const swiftName = require('../../ecosystems/swift/name');
const swiftVersion = require('../../ecosystems/swift/version');
const upstreams = require('../shared/upstreams');
const versionFilter = require('../shared/versions');
const gate = require('../shared/gate');
const shared = require('../shared/requests');
const access = require('../shared/access');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const log = require('../../logger');
const { record, json, problem, refuse, failed, auditOnly, looksLikeSwiftClient } = require('./respond');

const adapter = () => ecosystems.adapter('swift');
const base = (req) => `${access.baseUrl(req)}/swift`;

// the releases of a package this caller may see, or null once a refusal has gone out
async function visible(req, res, id) {
  let got;
  try {
    got = await upstream.summary(id);
  } catch (err) {
    failed(req, res, err, { package_name: swiftName.fold(id) });
    return null;
  }
  const { doc } = got;
  const { allowed, excluded } = await versionFilter.visible({
    ecosystem: 'swift', adapter: adapter(), name: doc.id, versions: doc.versions.map((r) => ({ version: r.version, published: null })),
    fileOf: (v) => upstream.archiveName(doc.id, v), scope: policy.scopeOf(req), lenient: auditOnly()
  });
  if (!allowed.length) {
    const why = (excluded.find((e) => e.kind === 'rule') || excluded[0] || { reason: 'the repository has no semver tags' }).reason;
    // SwiftPM says only "package not found" for a 404, and prints the detail of anything else. so a no is 403
    const status = excluded.length ? 403 : 404;
    record(req, { package_name: doc.id, action: 'deny', status, reason: why });
    if (excluded.some((e) => e.kind === 'rule')) {
      await shared.openRequest(req, doc.id, null, why, { ecosystem: 'swift', looksLikeClient: looksLikeSwiftClient(req) });
    }
    refuse(res, doc.id, null, why, status, true);
    return null;
  }
  return { doc, allowed: allowed.map((v) => v.version), cacheHit: got.cacheHit };
}

async function listReleases(req, res, scope, name) {
  const got = await visible(req, res, `${scope}.${name}`);
  if (!got) return null;
  const releases = {};
  for (const v of got.allowed.sort((a, b) => swiftVersion.compare(b, a))) releases[v] = { url: `${base(req)}/${scope}/${name}/${v}` };
  record(req, { package_name: got.doc.id, action: 'allow', reason: `${got.allowed.length} of ${got.doc.versions.length} releases`, cache_hit: got.cacheHit ? 1 : 0 });
  return json(res, 200, { releases });
}

// the checks for one release, then the archive: kept, scanned, and cleared. { got, pre, id } or null once refused
async function release(req, res, scope, name, v) {
  const id = swiftName.fold(`${scope}.${name}`);
  if (!swiftVersion.valid(v)) {
    record(req, { package_name: id, action: 'error', status: 404, reason: 'not a version' });
    problem(res, 404, `${v} is not a version`);
    return null;
  }
  let doc;
  try {
    doc = (await upstream.summary(id)).doc;
  } catch (err) {
    failed(req, res, err, { package_name: id, version: v });
    return null;
  }
  if (!doc.versions.some((r) => r.version === v)) {
    record(req, { package_name: id, version: v, action: 'deny', status: 404, reason: 'not a release of the package' });
    refuse(res, id, v, 'the repository has no such release', 404);
    return null;
  }
  const g = { ecosystem: 'swift', adapter: adapter(), name: id, version: v, filename: upstream.archiveName(id, v), published: null, pin: v, looksLikeClient: looksLikeSwiftClient(req) };
  const pre = await gate.before(req, g);
  if (pre.refused) {
    record(req, { package_name: id, version: v, action: 'deny', status: pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    refuse(res, id, v, pre.refused.reason, pre.refused.status);
    return null;
  }
  let got;
  try {
    got = await upstream.getArchive(id, v);
  } catch (err) {
    failed(req, res, err, { package_name: id, version: v });
    return null;
  }
  const post = await gate.after(g, got);
  if (post) {
    record(req, { package_name: id, version: v, action: 'deny', status: post.status, reason: post.reason, blocked_by: post.by });
    refuse(res, id, v, post.reason, post.status === 503 ? 503 : 403);
    return null;
  }
  return { got, pre, id };
}

async function releaseInfo(req, res, scope, name, v) {
  const r = await release(req, res, scope, name, v);
  if (!r) return null;
  const up = await upstreams.forPackage(r.id, 'swift');
  record(req, { package_name: r.id, version: v, action: r.pre.verdict.allowed ? 'allow' : 'audit', reason: 'release metadata' });
  return json(res, 200, {
    id: r.id,
    version: v,
    resources: [{ name: 'source-archive', type: 'application/zip', checksum: r.got.sha256 }],
    metadata: { repositoryURLs: up ? [`${String(up.url).replace(/\/+$/, '')}/${scope.toLowerCase()}/${name.toLowerCase()}`] : [] }
  });
}

async function manifest(req, res, scope, name, v) {
  const r = await release(req, res, scope, name, v);
  if (!r) return null;
  let files;
  try {
    files = await upstream.manifests(r.got);
  } catch (err) {
    return failed(req, res, err, { package_name: r.id, version: v });
  }
  const want = String(req.query['swift-version'] || '');
  // own keys only, ?swift-version=constructor is not a manifest
  const key = want || '';
  const body = Object.prototype.hasOwnProperty.call(files, key) ? files[key] : null;
  if (!body) {
    // no manifest just for that swift, so the plain one it is. the protocol says to send SwiftPM there
    record(req, { package_name: r.id, version: v, action: 'allow', status: 303, reason: `no Package@swift-${want.slice(0, 20)}.swift, sent to Package.swift` });
    res.set('content-version', '1');
    return res.redirect(303, `${base(req)}/${scope}/${name}/${v}/Package.swift`);
  }
  // the other manifests, the way the protocol lists them, so SwiftPM can pick the one for its own version
  const alternates = Object.keys(files).filter((k) => k && !want).map((k) => `<${base(req)}/${scope}/${name}/${v}/Package.swift?swift-version=${k}>; rel="alternate"; filename="Package@swift-${k}.swift"; swift-tools-version="${k}"`);
  if (alternates.length) res.set('link', alternates.join(', '));
  record(req, { package_name: r.id, version: v, action: r.pre.verdict.allowed ? 'allow' : 'audit', reason: want ? `Package@swift-${want}.swift` : 'Package.swift' });
  res.set('content-version', '1');
  res.set('content-disposition', `attachment; filename="${want ? `Package@swift-${want}.swift` : 'Package.swift'}"`);
  return res.status(200).type('text/x-swift').send(body);
}

async function archive(req, res, scope, name, v) {
  const r = await release(req, res, scope, name, v);
  if (!r) return null;
  const { got, pre, id } = r;
  const keep = db.settings.getBool('audit_log_downloads');
  const who = downloader(req, got.cacheHit);
  if (keep) {
    const finding = await audit.findingFor(id, v, 'swift').catch(() => null);
    if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
  }
  if (!got.cacheHit) cvescan.checkVersion(id, v, 'swift').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
  resolution.noteSelected(req, 'swift', id, v);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  record(req, { package_name: id, version: v, pulled_version: v, pulled_exact: 1, action: pre.verdict.allowed ? 'allow' : 'audit', bytes: got.size, cache_hit: got.cacheHit ? 1 : 0 });
  artifacts.touch(got.artifactId);
  res.set('content-version', '1');
  res.set('content-type', 'application/zip');
  res.set('content-length', String(got.size));
  res.set('digest', `sha-256=${Buffer.from(got.sha256, 'hex').toString('base64')}`);
  res.set('content-disposition', `attachment; filename="${name}-${v}.zip"`);
  res.set('cache-control', 'private, max-age=31536000, immutable');
  if (req.method === 'HEAD') return res.end();
  const stream = upstream.open(got);
  stream.on('error', (err) => {
    log.error(`could not send ${got.filename}`, err.message);
    res.destroy(err);
  });
  return stream.pipe(res);
}

// which identity a repository URL is: https://github.com/apple/swift-log(.git) or git@github.com:apple/swift-log.git
async function identifiers(req, res) {
  const url = String(req.query.url || '').trim();
  const m = /^(?:https:\/\/([^/]+)\/|git@([^:]+):)([^/]+)\/([^/]+?)(?:\.git)?\/?$/.exec(url);
  const hosts = (await upstreams.all('swift')).filter((u) => u.enabled).map((u) => { try { return new URL(u.url).host.toLowerCase(); } catch (err) { return ''; } });
  if (!m || !hosts.includes(String(m[1] || m[2]).toLowerCase()) || !swiftName.validScope(m[3]) || !swiftName.validName(m[4])) {
    record(req, { action: 'error', status: 404, reason: 'no identity for that url' });
    return problem(res, 404, 'there is no package here for that repository url');
  }
  const id = swiftName.fold(`${m[3]}.${m[4]}`);
  record(req, { package_name: id, action: 'allow', reason: 'identifiers' });
  return json(res, 200, { identifiers: [id] });
}

function login(req, res) {
  record(req, { action: 'allow', reason: `login for ${req.npmIdentity ? req.npmIdentity.username : 'nobody'}` });
  res.set('content-version', '1');
  return res.status(200).end();
}

module.exports = { listReleases, releaseInfo, manifest, archive, identifiers, login };
