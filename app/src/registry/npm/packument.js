// The package document npm asks for first. blocked versions get trimmed out, tarball links point back here.
// Author: Tim Rice

const semver = require('semver');
const db = require('../../db');
const policy = require('../../policy');
const upstream = require('./upstream');
const audit = require('../../audit');
const quarantine = require('../../policy/quarantine');
const cooloff = require('../../policy/cooloff');
const typosquat = require('../../policy/typosquat');
const killswitch = require('../../policy/killswitch');
const waivers = require('../../policy/waivers');
const resolution = require('../../policy/resolution');
const registryMode = require('../../policy/mode');
const packages = require('../../db/repositories/packages');
const { record, baseUrl } = require('../shared/access');
const { refuse, openRequest, explicitlyAllowed, countBlocked } = require('./client');

async function servePackument(req, res, name) {
  if (!upstream.validName(name)) {
    record(req, { action: 'error', status: 400, reason: 'bad package name' });
    return res.status(400).json({ error: 'that is not a valid package name' });
  }

  // before any rule is even asked. nothing overrides a kill, audit only mode included
  const dead = await killswitch.check('npm', name, null);
  if (dead) {
    record(req, { package_name: name, action: 'deny', status: 403, reason: dead.reason, blocked_by: 'killswitch' });
    return refuse(res, req, name, null, { reason: dead.reason });
  }
  const scope = policy.scopeOf(req);
  const verdict = await policy.checkPackage(name, undefined, scope);
  const auditOnly = db.settings.getBool('audit_mode');

  if (!verdict.allowed && !auditOnly) {
    record(req, {
      package_name: name,
      action: 'deny',
      status: 403,
      reason: verdict.reason,
      rule_id: verdict.rule && verdict.rule.id
    });
    await openRequest(req, name, null, verdict.reason);
    return refuse(res, req, name, null, verdict);
  }
  if (!verdict.allowed && auditOnly) {
    record(req, { package_name: name, action: 'audit', reason: `would have blocked: ${verdict.reason}` });
  }
  // learning mode: served either way, and anything no allow rule covers lands in the approval queue
  if (auditOnly && !explicitlyAllowed(verdict)) {
    openRequest(req, name, null, verdict.reason, { source: 'learning' }).catch(() => {});
  }
  // a name imitating a well known one
  const squat = await typosquat.verdict('npm', name);
  if (squat && squat.block) {
    record(req, { package_name: name, action: 'deny', status: 403, reason: squat.reason, blocked_by: 'typosquat' });
    countBlocked(name);
    await openRequest(req, name, null, squat.reason);
    return refuse(res, req, name, null, { reason: squat.reason });
  }

  const accept = req.get('accept') || '';
  const variant = accept.includes('install-v1') ? 'abbreviated' : 'full';

  try {
    const { doc, cacheHit } = await upstream.getPackument(name, variant);
    // deep copy! the cached object is shared and we're about to mess with it
    const copy = JSON.parse(JSON.stringify(doc));
    // quarantine and safe resolution go first, so the rules pass fixes the tags after them
    const excluded = [];
    const killed = await killswitch.killedVersions('npm', name, Object.keys(copy.versions || {}));
    for (const [version, reason] of killed) {
      delete copy.versions[version];
      excluded.push({ version, kind: 'killed', reason });
    }
    // audit only skips the rules pass that normally fixes the tags, so a killed latest gets fixed here
    if (killed.size && copy['dist-tags']) {
      for (const [tag, v] of Object.entries(copy['dist-tags'])) if (killed.has(v)) delete copy['dist-tags'][tag];
      if (!copy['dist-tags'].latest) {
        const newest = Object.keys(copy.versions || {}).filter((v) => semver.valid(v) && !semver.prerelease(v)).sort(semver.rcompare)[0];
        if (newest) copy['dist-tags'].latest = newest;
      }
    }
    // lockdown: only versions already on disk, so a range settles on one that can actually be served
    if (registryMode.lockdown() && copy.versions) {
      const onDisk = new Set((await packages.tarballVersions(name)).map((r) => r.version));
      for (const version of Object.keys(copy.versions)) {
        if (onDisk.has(version)) continue;
        delete copy.versions[version];
        excluded.push({ version, kind: 'lockdown', reason: 'not cached, and the registry is in lockdown' });
      }
      if (!Object.keys(copy.versions).length) {
        const reason = `the registry is in lockdown and no version of ${name} is cached`;
        record(req, { package_name: name, action: 'deny', status: 503, reason, blocked_by: 'mode' });
        return res.status(503).json({ error: reason, reason, package: name });
      }
      const tags = copy['dist-tags'] || {};
      for (const [tag, v] of Object.entries(tags)) if (!onDisk.has(v)) delete tags[tag];
      if (!tags.latest) {
        const newest = Object.keys(copy.versions).filter((v) => semver.valid(v) && !semver.prerelease(v)).sort(semver.rcompare)[0];
        if (newest) tags.latest = newest;
      }
      copy['dist-tags'] = tags;
    }
    if (!auditOnly && copy.versions) {
      const has = (v) => Object.prototype.hasOwnProperty.call(copy.versions, v);
      for (const h of await quarantine.hiddenFor('npm', name)) {
        if (!has(h.version)) continue;
        delete copy.versions[h.version];
        excluded.push({ version: h.version, kind: 'quarantine', reason: h.status === 'rejected' ? 'rejected in quarantine' : 'held in quarantine' });
      }
      for (const [version, reason] of await resolution.securityExclusions('npm', name, scope)) {
        if (!has(version)) continue;
        delete copy.versions[version];
        excluded.push({ version, kind: 'security', reason });
      }
      // cooling off reads publish times off the full packument, the abbreviated one npm asks for has none
      if (cooloff.enabled() && !cooloff.exempt(name)) {
        const full = copy.time ? copy : await upstream.getPackument(name, 'full').then((r) => r.doc).catch(() => null);
        for (const [version, reason] of cooloff.npmExclusions(name, { versions: copy.versions, time: full && full.time })) {
          if (!has(version) || cooloff.pinned(await policy.checkVersion(name, version, undefined, scope), version)) continue;
          if (await waivers.coolingWaived('npm', name, version, scope)) continue;
          delete copy.versions[version];
          excluded.push({ version, kind: 'cooloff', reason });
        }
      }
    }
    const filtered = auditOnly
      ? { doc: copy, kept: Object.keys(copy.versions || {}).length, removed: 0, excluded: [] }
      : await policy.filterPackument(name, copy, scope);
    excluded.push(...(filtered.excluded || []));
    resolution.record(req, { ecosystem: 'npm', name, offered: filtered.kept, latest: (filtered.doc['dist-tags'] || {}).latest, excluded });

    if (!filtered.kept) {
      record(req, { package_name: name, action: 'deny', status: 403, reason: 'every version is blocked' });
      await openRequest(req, name, null, 'no version of this package is approved');
      return refuse(res, req, name, null, { reason: 'no version of this package is approved' });
    }

    // abuse `deprecated` so it shows during install, where devs actually look
    if (db.settings.getBool('audit_warn_install')) {
      const known = await audit.findingsForPackage(name);
      for (const [version, meta] of Object.entries(filtered.doc.versions)) {
        const finding = known.get(version);
        if (!finding || !meta) continue;
        const note = `SECURITY: ${audit.warningLine(finding)}`;
        meta.deprecated = meta.deprecated ? `${meta.deprecated} | ${note}` : note;
      }
    }

    const base = baseUrl(req);
    for (const [version, meta] of Object.entries(filtered.doc.versions)) {
      if (meta && meta.dist) {
        const short = name.includes('/') ? name.split('/')[1] : name;
        meta.dist.tarball = `${base}/${name}/-/${short}-${version}.tgz`;
      }
    }
    // these only point at the public registry, don't hand them out
    delete filtered.doc._attachments;

    const body = JSON.stringify(filtered.doc);
    // just a guess, the tarball fixes it
    const tags = filtered.doc['dist-tags'] || {};
    record(req, {
      package_name: name,
      action: 'allow',
      pulled_version: tags.latest || null,
      pulled_exact: 0,
      cache_hit: cacheHit ? 1 : 0,
      bytes: Buffer.byteLength(body),
      reason: filtered.removed ? `${filtered.removed} version(s) filtered out` : null
    });

    res.set('content-type', 'application/json; charset=utf-8');
    res.set('cache-control', 'no-cache');
    if (squat && squat.warn) res.set('npm-notice', `TYPOSQUAT: ${name} ${squat.reason}`.replace(/[^\x20-\x7e]/g, ' '));
    res.send(body);
  } catch (err) {
    record(req, { package_name: name, action: 'error', status: err.status || 502, reason: err.message });
    res.status(err.status || 502).json({ error: err.message });
  }
}

module.exports = { servePackument };
