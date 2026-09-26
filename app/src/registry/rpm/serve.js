// What dnf asks a mirror for: repodata/repomd.xml (and its signature), the metadata files it lists, and packages.
// Author: Tim Rice
//
// by default the index goes out exactly as the distro signed it, and every package download is checked: the rules,
// the kill switch, holds, advisories, cooling off, then fetched, checked against its checksum, kept and scanned. a
// mirror set to filter hands out an index of only what the rules allow instead (see filter.js)

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
const log = require('../../logger');
const { record, text, refuse, failed, looksLikeRpmClient } = require('./respond');

const adapter = () => ecosystems.adapter('rpm');

// the mirror an address names, or a 404
async function withMirror(req, res, slug, handler) {
  const up = await upstream.mirror(slug);
  if (!up) {
    record(req, { action: 'error', status: 404, reason: `no mirror called ${slug}` });
    return text(res, 404, `there is no RPM mirror called ${slug} here`);
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

async function repomdXml(req, res, up) {
  let got;
  try {
    got = await upstream.repomd(up);
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} repomd.xml` });
  }
  res.set('cache-control', 'no-cache');
  if (!up.options.filtered) {
    // the package index is read now, so the first download does not wait for it
    upstream.index(up).catch((err) => log.warn(`${up.name}: its index could not be read`, err.message));
    record(req, { action: 'allow', reason: `${up.name} repomd.xml`, cache_hit: got.cacheHit ? 1 : 0 });
    return res.status(200).type('text/xml').send(got.xml);
  }
  try {
    const idx = await upstream.index(up);
    const allowed = await filter.allowedHrefs(idx, policy.scopeOf(req));
    const primary = await filter.filteredPrimary(up, idx, allowed);
    record(req, { action: 'allow', reason: `${up.name} filtered repomd.xml, ${allowed.size} of ${idx.packages.length} packages` });
    return res.status(200).type('text/xml').send(filter.rewrite(got.xml, got.entries, primary));
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} filtered repomd.xml` });
  }
}

async function repomdAsc(req, res, up) {
  if (up.options.filtered) {
    record(req, { action: 'deny', status: 404, reason: 'a filtered index has no signature' });
    return text(res, 404, `${up.name} hands out a filtered index, which the distro did not sign. Set repo_gpgcheck=0 for it (package signatures are still checked)`);
  }
  const asc = await upstream.repomdSignature(up);
  if (!asc) {
    record(req, { action: 'deny', status: 404, reason: 'the repository publishes no signature' });
    return text(res, 404, `${up.name} publishes no signature for its index`);
  }
  record(req, { action: 'allow', reason: `${up.name} repomd.xml.asc` });
  res.set('cache-control', 'no-cache');
  return res.status(200).type('text/plain').send(asc);
}

async function metadata(req, res, up, file) {
  if (up.options.filtered) {
    const mine = /^([0-9a-f]{64})-primary\.xml\.gz$/.exec(file);
    const built = mine ? await filter.fileFor(mine[1]) : null;
    if (built) {
      record(req, { action: 'allow', reason: `${up.name} filtered primary` });
      return sendFile(res, built, 'application/gzip');
    }
  }
  let entries;
  try {
    ({ entries } = await upstream.repomd(up));
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} ${file}` });
  }
  const entry = entries.find((e) => e.href === `repodata/${file}`);
  // a filtered mirror never hands out the unfiltered index, whichever copy of it is asked for
  if (!entry || (up.options.filtered && /^(primary|.*_db|.*_zck)$/.test(entry.type))) {
    record(req, { action: 'error', status: 404, reason: `${file} is not in ${up.name}'s index` });
    return text(res, 404, `${file} is not a file of ${up.name}'s current index`);
  }
  try {
    const path = await upstream.metaFile(up, entry);
    record(req, { action: 'allow', reason: `${up.name} ${entry.type}` });
    res.set('cache-control', 'private, max-age=31536000, immutable');
    return sendFile(res, path, 'application/octet-stream');
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} ${file}` });
  }
}

async function pkg(req, res, up, rel) {
  let idx;
  try {
    idx = await upstream.index(up);
  } catch (err) {
    return failed(req, res, err, { reason: `${up.name} index` });
  }
  const p = idx.byHref.get(rel);
  if (!p) {
    record(req, { action: 'error', status: 404, reason: `${rel} is not in ${up.name}'s index` });
    return text(res, 404, `${rel} is not a package of ${up.name}`);
  }
  const g = { ecosystem: 'rpm', adapter: adapter(), name: p.name, version: p.version, filename: upstream.filenameOf(p), published: p.published, pin: p.version, looksLikeClient: looksLikeRpmClient(req) };
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
    const finding = await audit.findingFor(p.name, p.version, 'rpm').catch(() => null);
    if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
  }
  if (!got.cacheHit) cvescan.checkVersion(p.name, p.version, 'rpm').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
  resolution.noteSelected(req, 'rpm', p.name, p.version);
  if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  record(req, { package_name: p.name, version: p.version, pulled_version: p.version, pulled_exact: 1, action: pre.verdict.allowed ? 'allow' : 'audit', bytes: got.size, cache_hit: got.cacheHit ? 1 : 0 });
  artifacts.touch(got.artifactId);
  res.set('content-type', 'application/x-rpm');
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

module.exports = { withMirror, repomdXml, repomdAsc, metadata, pkg };
