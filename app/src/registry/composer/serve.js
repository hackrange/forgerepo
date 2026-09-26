// What composer asks for: packages.json, a package's metadata, and the archives.
// Author: Tim Rice
//
// a package's metadata is handed out with only the releases the rules let through, so composer only ever resolves to an
// allowed version. each release's dist points at this box and its git source is taken out, and the archive behind the
// dist address is checked again when it is asked for, fetched, kept and scanned like any package

const db = require('../../db');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const composerName = require('../../ecosystems/composer/name');
const composerVersion = require('../../ecosystems/composer/version');
const upstreams = require('../shared/upstreams');
const versionFilter = require('../shared/versions');
const gate = require('../shared/gate');
const shared = require('../shared/requests');
const access = require('../shared/access');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const log = require('../../logger');
const { record, json, text, refuse, failed, auditOnly, looksLikeComposerClient } = require('./respond');

const adapter = () => ecosystems.adapter('composer');
const base = (req) => `${access.baseUrl(req)}/composer`;

// the repository's front page: where the metadata of a package is
function root(req, res) {
  record(req, { action: 'allow', reason: 'packages.json' });
  return json(res, 200, { packages: [], 'metadata-url': `${base(req)}/p2/%package%.json` });
}

// branches are not releases, there is nothing fixed to fetch for them
function devFile(req, res) {
  record(req, { action: 'deny', status: 404, reason: 'branches are not served' });
  return text(res, 404, 'branches (dev versions) are not served by this repository');
}

// p2/<vendor>/<name>.json, only the allowed releases, each pointed at this box
async function metadata(req, res, name) {
  let got;
  try {
    got = await upstream.metadata(name);
  } catch (err) {
    return failed(req, res, err, { package_name: composerName.fold(name) });
  }
  const { doc } = got;
  const { allowed, excluded } = await versionFilter.visible({
    ecosystem: 'composer', adapter: adapter(), name: doc.name,
    versions: doc.versions.map((r) => ({ version: r.version, published: r.time || null })),
    fileOf: (v) => upstream.archiveName(doc.name, v), scope: policy.scopeOf(req), lenient: auditOnly()
  });
  if (!allowed.length) {
    const why = (excluded.find((e) => e.kind === 'rule') || excluded[0] || { reason: 'the repository lists no releases of it' }).reason;
    record(req, { package_name: doc.name, action: 'deny', status: 404, reason: why });
    if (excluded.some((e) => e.kind === 'rule')) {
      await shared.openRequest(req, doc.name, null, why, { ecosystem: 'composer', looksLikeClient: looksLikeComposerClient(req) });
    }
    // composer reads a 404 as "not in this repository" and says it could not find the package. anything else stops it
    return refuse(res, doc.name, null, why, 404, true);
  }
  const up = await upstreams.forPackage(doc.name, 'composer');
  const ok = new Set(allowed.map((v) => v.version));
  const out = [];
  let unfetchable = 0;
  for (const rel of doc.versions) {
    if (!ok.has(rel.version)) continue;
    const dist = upstream.distOf(up, rel);
    if (dist.refuse) {
      unfetchable += 1;
      continue;
    }
    const entry = { ...rel, name: doc.name };
    // no git fallback, and nobody else gets told about downloads
    delete entry.source;
    delete entry['notification-url'];
    entry.dist = {
      type: 'zip',
      url: `${base(req)}/dists/${doc.name}/${encodeURIComponent(rel.version)}/${dist.reference}.zip`,
      reference: dist.reference,
      shasum: dist.shasum || ''
    };
    out.push(entry);
  }
  out.sort((a, b) => composerVersion.compare(b.version, a.version));
  record(req, { package_name: doc.name, action: 'allow', reason: `${out.length} of ${doc.versions.length} releases${unfetchable ? `, ${unfetchable} with no archive to mirror` : ''}`, cache_hit: got.cacheHit ? 1 : 0 });
  res.set('cache-control', 'private, no-cache');
  return json(res, 200, { packages: { [doc.name]: out } });
}

// dists/<vendor>/<name>/<version>/<commit>.zip: the code, checked, fetched, kept and scanned
async function archive(req, res, name, rawVersion, file) {
  let v;
  try {
    v = decodeURIComponent(rawVersion);
  } catch (err) {
    v = '';
  }
  const folded = composerName.fold(name);
  if (!composerVersion.valid(v) || !/^[0-9a-f]{40}\.zip$/.test(file)) {
    record(req, { package_name: folded, action: 'error', status: 404, reason: 'bad archive address' });
    return text(res, 404, 'there is no such archive');
  }
  let doc;
  try {
    doc = (await upstream.metadata(folded)).doc;
  } catch (err) {
    return failed(req, res, err, { package_name: folded, version: v });
  }
  const rel = upstream.release(doc, v);
  if (!rel) {
    record(req, { package_name: folded, version: v, action: 'deny', status: 404, reason: 'not a release of the package' });
    return refuse(res, folded, v, 'the repository has no such release', 404);
  }
  // the address has to name the commit the release really points at
  const dist = upstream.distOf(await upstreams.forPackage(folded, 'composer'), rel);
  if (dist.refuse || `${dist.reference}.zip` !== file) {
    record(req, { package_name: folded, version: v, action: 'deny', status: 404, reason: dist.refuse || 'not the commit of the release' });
    return refuse(res, folded, v, dist.refuse || 'that is not the commit this release points at', 404);
  }
  const g = { ecosystem: 'composer', adapter: adapter(), name: folded, version: v, filename: upstream.archiveName(folded, v), published: rel.time || null, pin: v, looksLikeClient: looksLikeComposerClient(req) };
  const pre = await gate.before(req, g);
  if (pre.refused) {
    record(req, { package_name: folded, version: v, action: 'deny', status: pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    return refuse(res, folded, v, pre.refused.reason, pre.refused.status);
  }
  let got;
  try {
    got = await upstream.getArchive(folded, v);
  } catch (err) {
    return failed(req, res, err, { package_name: folded, version: v });
  }
  const post = await gate.after(g, got);
  if (post) {
    record(req, { package_name: folded, version: v, action: 'deny', status: post.status, reason: post.reason, blocked_by: post.by });
    return refuse(res, folded, v, post.reason, post.status === 503 ? 503 : 403);
  }
  const keep = db.settings.getBool('audit_log_downloads');
  const who = downloader(req, got.cacheHit);
  if (keep) {
    const finding = await audit.findingFor(folded, v, 'composer').catch(() => null);
    if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
  }
  if (!got.cacheHit) cvescan.checkVersion(folded, v, 'composer').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
  resolution.noteSelected(req, 'composer', folded, v);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  record(req, { package_name: folded, version: v, pulled_version: v, pulled_exact: 1, action: pre.verdict.allowed ? 'allow' : 'audit', bytes: got.size, cache_hit: got.cacheHit ? 1 : 0 });
  artifacts.touch(got.artifactId);
  res.set('content-type', 'application/zip');
  res.set('content-length', String(got.size));
  res.set('cache-control', 'private, max-age=31536000, immutable');
  if (req.method === 'HEAD') return res.end();
  const stream = upstream.open(got);
  stream.on('error', (err) => {
    log.error(`could not send ${got.filename}`, err.message);
    res.destroy(err);
  });
  return stream.pipe(res);
}

module.exports = { root, devFile, metadata, archive };
