// What apt asks a mirror for: each suite's InRelease (or Release and Release.gpg), the index files they list (by path
// or by hash), and packages from the pool. and the box's own public key, for mirrors that hand out a filtered index.
// Author: Tim Rice
//
// by default a suite's files go out exactly as the distro signed them, and every package download is checked: the
// rules, the kill switch, holds, advisories, cooling off, then the .deb is checked against its SHA256, kept and scanned.
// a mirror set to filter hands out an index of only what the rules allow, signed by this box (see filter.js)

const fs = require('fs');
const fsp = require('fs/promises');
const db = require('../../db');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const gate = require('../shared/gate');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const filter = require('./filter');
const signing = require('./signing');
const log = require('../../logger');
const { record, text, refuse, failed, looksLikeAptClient } = require('./respond');

const adapter = () => ecosystems.adapter('apt');

async function withMirror(req, res, slug, handler) {
  const up = await upstream.mirror(slug);
  if (!up) {
    record(req, { action: 'error', status: 404, reason: `no mirror called ${slug}` });
    return text(res, 404, `there is no APT mirror called ${slug} here`);
  }
  return handler(req, res, up);
}

function sendFile(res, file, type) {
  return fsp.stat(file).then((st) => {
    res.set('content-type', type);
    res.set('content-length', String(st.size));
    if (res.req.method === 'HEAD') return res.end();
    const stream = fs.createReadStream(file);
    stream.on('error', (err) => res.destroy(err));
    return stream.pipe(res);
  });
}

// the box's public key, for signed-by= on a mirror that hands out a filtered index
async function signingKey(req, res) {
  try {
    const key = await signing.publicKey();
    record(req, { action: 'allow', reason: 'the box signing key' });
    return res.status(200).type('text/plain').send(key);
  } catch (err) {
    return failed(req, res, err, { reason: 'signing key' });
  }
}

// InRelease, Release or Release.gpg of a suite
async function releaseFile(req, res, up, suite, which) {
  try {
    if (up.options.filtered) {
      const out = await filter.suite(up, suite, policy.scopeOf(req));
      record(req, { action: 'allow', reason: `${up.name} ${suite} filtered ${which}` });
      res.set('cache-control', 'no-cache');
      const body = which === 'InRelease' ? out.inrelease : which === 'Release' ? out.release : out.releaseGpg;
      return res.status(200).type('text/plain').send(body);
    }
    const rel = await upstream.release(up, suite);
    const body = which === 'InRelease' ? rel.inrelease : which === 'Release' ? rel.release : rel.releaseGpg;
    if (!body) {
      record(req, { action: 'error', status: 404, reason: `${suite} has no ${which}` });
      return text(res, 404, `${suite} of ${up.name} has no ${which}`);
    }
    record(req, { action: 'allow', reason: `${up.name} ${suite} ${which}`, cache_hit: rel.cacheHit ? 1 : 0 });
    res.set('cache-control', 'no-cache');
    return res.status(200).type('text/plain').send(body);
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} ${suite} ${which}` });
  }
}

// a file of a suite, by path or by hash, when the suite's Release lists it
async function suiteFile(req, res, up, suite, rel) {
  let listed;
  let byHash = false;
  try {
    listed = up.options.filtered ? (await filter.suite(up, suite, policy.scopeOf(req), 10 * 60 * 1000)).files : (await upstream.release(up, suite)).parsed.files;
    byHash = !up.options.filtered && /yes/i.test((await upstream.release(up, suite)).parsed.fields['Acquire-By-Hash'] || '');
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} ${suite} ${rel}` });
  }
  const hashed = /^(.+)\/by-hash\/SHA256\/([0-9a-f]{64})$/.exec(rel);
  const entry = hashed
    ? listed.find((f) => f.sha256 === hashed[2] && f.path.startsWith(`${hashed[1]}/`))
    : listed.find((f) => f.path === rel);
  if (!entry) {
    record(req, { action: 'error', status: 404, reason: `${rel} is not in ${suite}'s index` });
    return text(res, 404, `${rel} is not a file of ${suite} on ${up.name}`);
  }
  try {
    // the box's own filtered files first, then the distro's
    const mine = up.options.filtered ? await filter.fileFor(entry.sha256) : null;
    const file = mine || await upstream.metaFile(up, suite, entry, byHash);
    record(req, { action: 'allow', reason: `${up.name} ${suite} ${entry.path}` });
    res.set('cache-control', hashed ? 'private, max-age=31536000, immutable' : 'no-cache');
    return sendFile(res, file, 'application/octet-stream');
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} ${suite} ${rel}` });
  }
}

async function pool(req, res, up, filename) {
  let hit;
  try {
    hit = await upstream.findPool(up, filename);
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} ${filename}` });
  }
  if (!hit) {
    record(req, { action: 'error', status: 404, reason: `${filename} is not in ${up.name}'s index` });
    return text(res, 404, `${filename} is not a package of ${up.name} (run apt update first if it is new)`);
  }
  const { p } = hit;
  const g = { ecosystem: 'apt', adapter: adapter(), name: p.name, version: p.version, filename: upstream.baseName(p), published: null, pin: p.version, looksLikeClient: looksLikeAptClient(req) };
  const pre = await gate.before(req, g);
  if (pre.refused) {
    record(req, { package_name: p.name, version: p.version, action: 'deny', status: pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    return refuse(res, p.name, p.version, pre.refused.reason, pre.refused.status);
  }
  let got;
  try {
    got = await upstream.getPackage(up, p);
  } catch (err) {
    return failed(req, res, err, { package_name: p.name, version: p.version });
  }
  const post = await gate.after(g, got);
  if (post) {
    record(req, { package_name: p.name, version: p.version, action: 'deny', status: post.status, reason: post.reason, blocked_by: post.by });
    return refuse(res, p.name, p.version, post.reason, post.status === 503 ? 503 : 403);
  }
  const keep = db.settings.getBool('audit_log_downloads');
  const who = downloader(req, got.cacheHit);
  if (keep) {
    const finding = await audit.findingFor(p.name, p.version, 'apt').catch(() => null);
    if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
  }
  if (!got.cacheHit) cvescan.checkVersion(p.name, p.version, 'apt').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
  resolution.noteSelected(req, 'apt', p.name, p.version);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  record(req, { package_name: p.name, version: p.version, pulled_version: p.version, pulled_exact: 1, action: pre.verdict.allowed ? 'allow' : 'audit', bytes: got.size, cache_hit: got.cacheHit ? 1 : 0 });
  artifacts.touch(got.artifactId);
  res.set('content-type', 'application/vnd.debian.binary-package');
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

module.exports = { withMirror, signingKey, releaseFile, suiteFile, pool };
