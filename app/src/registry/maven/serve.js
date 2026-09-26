// What mvn and gradle ask for: a package's maven-metadata.xml, and the files of its versions with their checksums.
// Author: Tim Rice
//
// the version list is rebuilt from what the rules let through, so a range like [2.17,2.18) only ever resolves to an
// allowed version. every file is checked again when it is asked for, and a checksum is worked out from the bytes this
// box holds, never passed on from somewhere else

const crypto = require('crypto');
const db = require('../../db');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const mavenName = require('../../ecosystems/maven/name');
const versionFilter = require('../shared/versions');
const gate = require('../shared/gate');
const shared = require('../shared/requests');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const log = require('../../logger');
const { record, text, refuse, failed, auditOnly, looksLikeMavenClient } = require('./respond');

const adapter = () => ecosystems.adapter('maven');
const ALGORITHMS = { sha1: 'sha1', md5: 'md5', sha256: 'sha256', sha512: 'sha512' };
const TYPES = { jar: 'application/java-archive', pom: 'application/xml', xml: 'application/xml', module: 'application/json', json: 'application/json', asc: 'text/plain', txt: 'text/plain' };

const escapeXml = (s) => String(s).replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]));

// the versions of a package this caller may see, or null once a refusal has gone out
async function visible(req, res, name) {
  let got;
  try {
    got = await upstream.metadata(name);
  } catch (err) {
    failed(req, res, err, { package_name: name });
    return null;
  }
  const { doc } = got;
  const artifactId = mavenName.split(name).artifactId;
  const { allowed, excluded } = await versionFilter.visible({
    ecosystem: 'maven', adapter: adapter(), name, versions: doc.versions.map((v) => ({ version: v, published: (doc.times || {})[v] || null })),
    fileOf: (v) => `${artifactId}-${v}.jar`, scope: policy.scopeOf(req), lenient: auditOnly()
  });
  if (!allowed.length) {
    const why = (excluded.find((e) => e.kind === 'rule') || excluded[0] || { reason: 'the repository lists no versions of it' }).reason;
    record(req, { package_name: name, action: 'deny', status: 404, reason: why });
    if (excluded.some((e) => e.kind === 'rule')) {
      await shared.openRequest(req, name, null, why, { ecosystem: 'maven', looksLikeClient: looksLikeMavenClient(req) });
    }
    refuse(res, name, null, why, 404, true);
    return null;
  }
  return { doc, allowed: allowed.map((v) => v.version), cacheHit: got.cacheHit };
}

// maven-metadata.xml as the repository would write it, holding only the allowed versions. the same bytes every
// time for the same list, so the .sha1 asked for next always matches
function metadataXml(name, versions, lastUpdated) {
  const c = mavenName.split(name);
  const newest = versions[versions.length - 1];
  const release = [...versions].reverse().find((v) => !require('../../ecosystems/maven/version').isPrerelease(v)) || newest;
  return ['<?xml version="1.0" encoding="UTF-8"?>', '<metadata>', `  <groupId>${escapeXml(c.groupId)}</groupId>`,
    `  <artifactId>${escapeXml(c.artifactId)}</artifactId>`, '  <versioning>', `    <latest>${escapeXml(newest)}</latest>`,
    `    <release>${escapeXml(release)}</release>`, '    <versions>', ...versions.map((v) => `      <version>${escapeXml(v)}</version>`),
    '    </versions>', `    <lastUpdated>${escapeXml(lastUpdated || '19700101000000')}</lastUpdated>`, '  </versioning>', '</metadata>', ''].join('\n');
}

async function serveMetadata(req, res, asked) {
  const got = await visible(req, res, asked.name);
  if (!got) return null;
  const xml = metadataXml(asked.name, got.allowed, got.doc.lastUpdated);
  record(req, { package_name: asked.name, action: 'allow', reason: `${asked.checksum ? `${asked.checksum} of ` : ''}metadata, ${got.allowed.length} of ${got.doc.versions.length} versions`, cache_hit: got.cacheHit ? 1 : 0 });
  if (asked.checksum) return text(res, 200, crypto.createHash(ALGORITHMS[asked.checksum]).update(xml).digest('hex'));
  res.set('content-type', 'application/xml');
  return res.status(200).send(xml);
}

async function serveFile(req, res, asked) {
  const { name, version, filename } = asked;
  let doc;
  try {
    doc = (await upstream.metadata(name)).doc;
  } catch (err) {
    return failed(req, res, err, { package_name: name, version });
  }
  if (!doc.versions.includes(version)) {
    record(req, { package_name: name, version, action: 'deny', status: 404, reason: 'not a version of the package' });
    return refuse(res, name, version, 'the repository has no such version', 404);
  }
  const f = {
    ecosystem: 'maven', adapter: adapter(), name, version, filename,
    published: (doc.times || {})[version] || null, pin: version, looksLikeClient: looksLikeMavenClient(req)
  };
  const pre = await gate.before(req, f);
  if (pre.refused) {
    record(req, { package_name: name, version, action: 'deny', status: pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    return refuse(res, name, version, pre.refused.reason, pre.refused.status);
  }
  let got;
  try {
    got = await upstream.getFile(name, version, filename);
  } catch (err) {
    return failed(req, res, err, { package_name: name, version });
  }
  const post = await gate.after(f, got);
  if (post) {
    record(req, { package_name: name, version, action: 'deny', status: post.status, reason: post.reason, blocked_by: post.by });
    return refuse(res, name, version, post.reason, post.status === 503 ? 503 : 403);
  }

  if (asked.checksum) {
    const hex = await upstream.checksum(got, ALGORITHMS[asked.checksum]);
    record(req, { package_name: name, version, action: pre.verdict.allowed ? 'allow' : 'audit', reason: `${asked.checksum} of ${filename}`, cache_hit: 1 });
    return text(res, 200, hex);
  }
  // the pom is fetched first, for every version a range looks at. the jar is the one that says it is really used
  const real = asked.ext !== 'pom' && !asked.classifier;
  const keep = db.settings.getBool('audit_log_downloads');
  if (real) {
    const who = downloader(req, got.cacheHit);
    if (keep) {
      const finding = await audit.findingFor(name, version, 'maven').catch(() => null);
      if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
    }
    if (!got.cacheHit) cvescan.checkVersion(name, version, 'maven').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
    resolution.noteSelected(req, 'maven', name, version);
  }
  record(req, {
    package_name: name, version, pulled_version: real ? version : null, pulled_exact: real ? 1 : 0,
    action: pre.verdict.allowed ? 'allow' : 'audit', reason: real ? null : filename, bytes: got.size, cache_hit: got.cacheHit ? 1 : 0
  });
  artifacts.touch(got.artifactId);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  res.set('content-type', TYPES[asked.ext] || 'application/octet-stream');
  res.set('content-length', String(got.size));
  res.set('cache-control', 'private, max-age=31536000, immutable');
  if (req.method === 'HEAD') return res.end();
  const stream = upstream.open(got);
  stream.on('error', (err) => {
    log.error(`could not send ${filename}`, err.message);
    res.destroy(err);
  });
  return stream.pipe(res);
}

module.exports = { metadataXml, serveMetadata, serveFile };
