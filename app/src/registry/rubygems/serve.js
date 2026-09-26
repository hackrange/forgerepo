// What gem and bundler ask for: the compact index (/versions, /info/<gem>), the .gem files and their gemspecs.
// Author: Tim Rice
//
// an info file is rebuilt from the lines of the versions the rules let through, so bundler only ever resolves to an
// allowed version, and each line keeps the checksum the source gave, which bundler checks the .gem against too.
// every file is checked again when it is asked for

const crypto = require('crypto');
const db = require('../../db');
const audit = require('../../audit');
const cvescan = require('../../cvescan');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const artifacts = require('../../storage/artifacts');
const resolution = require('../../policy/resolution');
const license = require('../../policy/licenses');
const gemName = require('../../ecosystems/rubygems/name');
const versionFilter = require('../shared/versions');
const gate = require('../shared/gate');
const { downloader } = require('../shared/serving');
const upstream = require('./upstream');
const log = require('../../logger');
const { record, text, refuse, failed, auditOnly, looksLikeGemClient } = require('./respond');

const adapter = () => ecosystems.adapter('rubygems');

// the version list bundler reads first. bundler only asks /info about a name it finds here, so every name the source
// has is listed. the versions column is left at 0 and the checksum is one that never matches, so bundler always asks
// /info, which is where the rules are. names only, nothing a developer could install from
const NEVER = '0'.repeat(32);
let listing = null;
async function versions(req, res) {
  const list = await upstream.names();
  if (!listing || listing.list !== list) {
    const body = Buffer.from(`created_at: ${new Date().toISOString().replace(/\.\d+Z$/, 'Z')}\n---\n${list.map((n) => `${n} 0 ${NEVER}`).join('\n')}\n`, 'utf8');
    listing = { list, body, etag: `"${crypto.createHash('md5').update(body).digest('hex')}"`, digest: `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:` };
  }
  record(req, { action: 'allow', reason: `versions, ${list.length} names` });
  res.set('etag', listing.etag);
  res.set('repr-digest', listing.digest);
  res.set('content-type', 'text/plain; charset=utf-8');
  // bundler asks for just the end of it with a Range. the whole file is fine too, it says so itself
  if (req.get('if-none-match') === listing.etag) return res.status(304).end();
  res.set('content-length', String(listing.body.length));
  if (req.method === 'HEAD') return res.status(200).end();
  return res.status(200).send(listing.body);
}

// the versions of a gem this caller may see, or null once a refusal has gone out
async function visible(req, res, name) {
  if (!gemName.valid(name)) {
    record(req, { action: 'error', status: 404, reason: 'not a gem name' });
    text(res, 404, 'not found');
    return null;
  }
  let got;
  try {
    got = await upstream.info(name);
  } catch (err) {
    failed(req, res, err, { package_name: name });
    return null;
  }
  const { doc } = got;
  // one entry per version, pushed when its first file was
  const byVersion = new Map();
  for (const f of doc.files) {
    const had = byVersion.get(f.version);
    if (!had || (f.published && (!had.published || f.published < had.published))) byVersion.set(f.version, { version: f.version, published: f.published });
  }
  const { allowed, excluded } = await versionFilter.visible({
    ecosystem: 'rubygems', adapter: adapter(), name, versions: [...byVersion.values()],
    fileOf: (v) => upstream.fileName(name, { version: v, platform: '' }), scope: policy.scopeOf(req), lenient: auditOnly()
  });
  // nothing allowed: an info file with no versions in it. bundler's resolver reads the info of every dependency of
  // every version it weighs, old ones too (backports, mongrel...), so a refusal here would stop resolution cold and a
  // request per gem looked at would bury the approvers. with no versions the resolver picks versions that do without
  // it. a gem somebody really asks for is refused (and requested) when its .gem is downloaded
  if (!allowed.length) {
    const why = (excluded.find((e) => e.kind === 'rule') || excluded[0] || { reason: 'the gem source lists no versions of it' }).reason;
    record(req, { package_name: name, action: 'deny', status: 200, reason: `no versions offered: ${why}` });
    return { doc, files: [], versions: 0, of: byVersion.size, cacheHit: got.cacheHit, why };
  }
  const ok = new Set(allowed.map((v) => v.version));
  return { doc, files: doc.files.filter((f) => ok.has(f.version)), versions: ok.size, of: byVersion.size, cacheHit: got.cacheHit };
}

async function serveInfo(req, res, name) {
  const got = await visible(req, res, name);
  if (!got) return null;
  const body = got.files.length ? `---\n${got.files.map((f) => f.line).join('\n')}\n` : '---\n';
  const etag = `"${crypto.createHash('md5').update(body).digest('hex')}"`;
  if (got.files.length) record(req, { package_name: name, action: 'allow', reason: `info, ${got.versions} of ${got.of} versions`, cache_hit: got.cacheHit ? 1 : 0 });
  // what a person debugging with curl can read. bundler and gem do not show it
  if (got.why) res.set('x-forgerepo-refused', require('./respond').oneLine(require('./respond').refusal(name, null, got.why)));
  res.set('etag', etag);
  res.set('repr-digest', `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`);
  res.set('content-type', 'text/plain; charset=utf-8');
  if (req.get('if-none-match') === etag) return res.status(304).end();
  return res.status(200).send(req.method === 'HEAD' ? '' : body);
}

// rack-protection-4.2.1.gem is rack-protection 4.2.1. a gem name can hold dashes too, so every dash before a digit
// is tried, and a name only counts when its source lists exactly this file
async function whichFile(base) {
  const cuts = [];
  for (let i = base.indexOf('-'); i > 0; i = base.indexOf('-', i + 1)) if (/\d/.test(base[i + 1] || '')) cuts.push(i);
  for (const i of cuts.reverse()) {
    const name = base.slice(0, i);
    if (!gemName.valid(name)) continue;
    let doc;
    try {
      doc = (await upstream.info(name)).doc;
    } catch (err) {
      if (err.status === 404 || err.status === 400) continue;
      throw err;
    }
    const f = doc.files.find((x) => upstream.fileName(name, x) === `${base}.gem`);
    if (f) return { name, f };
  }
  return null;
}

// a .gem or its gemspec, spec: true for the gemspec
async function serveFile(req, res, file, spec) {
  const base = spec ? file.replace(/\.gemspec\.rz$/, '') : file.replace(/\.gem$/, '');
  if (base === file || !/^[A-Za-z0-9_.-]{3,200}$/.test(base) || base.includes('..')) {
    record(req, { action: 'error', status: 404, reason: 'bad gem address' });
    return text(res, 404, 'there is no such gem');
  }
  let hit;
  try {
    hit = await whichFile(base);
  } catch (err) {
    return failed(req, res, err, {});
  }
  if (!hit) {
    record(req, { action: 'error', status: 404, reason: `${file} is not a file any gem source lists` });
    return text(res, 404, `${file} is not a file the gem source lists`);
  }
  const { name, f } = hit;
  const filename = spec ? `${base}.gemspec.rz` : `${base}.gem`;
  const g = {
    ecosystem: 'rubygems', adapter: adapter(), name, version: f.version, filename,
    published: f.published, pin: f.version, looksLikeClient: looksLikeGemClient(req)
  };
  const pre = await gate.before(req, g);
  if (pre.refused) {
    record(req, { package_name: name, version: f.version, action: 'deny', status: pre.refused.status === 403 ? 451 : pre.refused.status, reason: pre.refused.reason, blocked_by: pre.refused.by || undefined, rule_id: pre.refused.rule ? pre.refused.rule.id : undefined });
    return refuse(res, name, f.version, pre.refused.reason, pre.refused.status);
  }
  let got;
  try {
    got = spec ? await upstream.getSpec(name, f) : await upstream.getGem(name, f);
  } catch (err) {
    return failed(req, res, err, { package_name: name, version: f.version });
  }
  const post = await gate.after(g, got);
  if (post) {
    record(req, { package_name: name, version: f.version, action: 'deny', status: post.status === 403 ? 451 : post.status, reason: post.reason, blocked_by: post.by });
    return refuse(res, name, f.version, post.reason, post.status === 503 ? 503 : 403);
  }
  if (!spec) {
    const keep = db.settings.getBool('audit_log_downloads');
    const who = downloader(req, got.cacheHit);
    if (keep) {
      const finding = await audit.findingFor(name, f.version, 'rubygems').catch(() => null);
      if (finding) audit.noteDownload(finding, who).catch((err) => log.error('could not record a download', err.message));
    }
    if (!got.cacheHit) cvescan.checkVersion(name, f.version, 'rubygems').then((found) => (found && keep ? audit.noteDownload(found, who) : null)).catch(() => {});
    resolution.noteSelected(req, 'rubygems', name, f.version);
    if (pre.lic && !pre.lic.stored) license.save(got.artifactId, pre.lic).catch(() => {});
  }
  record(req, {
    package_name: name, version: f.version, pulled_version: spec ? null : f.version, pulled_exact: spec ? 0 : 1,
    action: pre.verdict.allowed ? 'allow' : 'audit', reason: spec ? filename : null, bytes: got.size, cache_hit: got.cacheHit ? 1 : 0
  });
  artifacts.touch(got.artifactId);
  res.set('content-type', 'application/octet-stream');
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

// specs.4.8.gz and friends, for gem sources --add. a list of names, never installed from
async function serveIndex(req, res, file) {
  try {
    const body = await upstream.indexFile(file);
    record(req, { action: 'allow', reason: file, bytes: body.length });
    res.set('content-type', 'application/octet-stream');
    return res.status(200).send(req.method === 'HEAD' ? Buffer.alloc(0) : body);
  } catch (err) {
    return failed(req, res, err, {});
  }
}

module.exports = { versions, serveInfo, serveFile, serveIndex, whichFile };
