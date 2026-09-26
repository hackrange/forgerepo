// Portal API, reviewing a manifest, lockfile or SBOM.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const rules = require('../../db/repositories/rules');
const policy = require('../../policy');
const upstream = require('../../registry/npm/upstream');
const license = require('../../policy/licenses');
const typosquat = require('../../policy/typosquat');
const config = require('../../config');
const { ruleEcosystem } = require('../../policy/rulecheck');
const pypiVersion = require('../../ecosystems/pypi/version');
const pypiupstream = require('../../registry/pypi/upstream');
const pypiMetadata = require('../../ecosystems/pypi/metadata');
const pypiSimple = require('../../ecosystems/pypi/simple');
const review = require('../../review');
const log = require('../../logger');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { str, required, boolFlag, oneOf } = require('../../lib/validate');
const { previewScope } = require('../shared/scope');
const { csvEscape } = require('../shared/csv');
const { toolsType } = require('../shared/tools-type');
const { actorOf } = require('../../lib/actor');

const router = express.Router();

// ---------------------------------------------------------------- file review
// package.json, lockfile, SBOM or a zip of them. all in memory, nothing on disk.
// rate limited per user not IP - a whole office behind one address shouldn't share
const REVIEW_FORMATS = ['json', 'csv', 'file'];

router.post(
  '/tools/review',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const format = oneOf(req.query.format, REVIEW_FORMATS, 'json');
    // page wants all rows, an export gets whatever filter was on screen
    const only = oneOf(req.query.only, review.VIEW_NAMES, 'all');
    const filename = str(req.body.filename, 255, 'file name') || 'uploaded';
    const encoding = oneOf(req.body.encoding, ['text', 'base64'], 'text');
    const raw = req.body.data;
    if (typeof raw !== 'string' || !raw.trim()) fail(400, 'there is nothing to review');
    if (raw.length > config.maxImportBytes) {
      fail(413, `that file is ${(raw.length / 1048576).toFixed(1)}MB and the limit is ${Math.round(config.maxImportBytes / 1048576)}MB`);
    }

    const gate = await auth.rateLimit(`review:${req.user.id}`, 20, 10 * 60000);
    if (!gate.ok) fail(429, 'slow down a moment, that is a lot of reviewing');

    let buffer;
    try {
      buffer = Buffer.from(raw, encoding === 'base64' ? 'base64' : 'utf8');
    } catch (err) {
      fail(400, 'that upload could not be decoded');
    }
    if (!buffer.length) fail(400, 'that file is empty');

    const report = await review.reviewUpload(buffer, filename);
    report.reviewed_by = req.user.username;
    await auth.auditReq(
      req, 'tools.review', filename,
      `${report.summary.total_packages} packages, ${report.summary.blocked} blocked, ` +
      `${report.summary.known_advisories} with advisories` +
      (only === 'all' ? '' : `, exported the ${only} rows only`)
    );

    const stamp = new Date().toISOString().slice(0, 10);
    const base = filename.replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 60) || 'review';
    const tag = only === 'all' ? '' : `-${only}`;
    const findings = only === 'all' ? report.findings : report.findings.filter(review.viewFilter(only));

    if (format === 'csv') {
      res.set('content-type', 'text/csv; charset=utf-8');
      res.set('content-disposition', `attachment; filename="${base}-review${tag}-${stamp}.csv"`);
      const lines = [review.CSV_COLUMNS.join(',')];
      for (const finding of findings) {
        lines.push(review.csvRow(finding).map(csvEscape).join(','));
      }
      return res.send(`${lines.join('\n')}\n`);
    }

    if (format === 'file') {
      res.set('content-type', 'application/json; charset=utf-8');
      res.set('content-disposition', `attachment; filename="${base}-review${tag}-${stamp}.json"`);
      // summary covers the whole file, filtered_to says which rows came along
      const out = Object.assign({}, report, { filtered_to: only, findings });
      return res.send(`${JSON.stringify(out, null, 2)}\n`);
    }

    res.json(report);
  })
);

// allow/deny for ticked packages from a review or tree walk.
// won't whitelist what a deny already covers - un-blacklisting is a Rules page job, on purpose
router.post(
  '/tools/decide',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const kind = oneOf(req.body.kind, ['allow', 'deny'], null);
    if (!kind) fail(400, 'kind has to be allow or deny');
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    if (!items.length) fail(400, 'nothing was ticked');
    if (items.length > 2000) fail(400, 'that is over two thousand packages, do it in batches');
    const pin = boolFlag(req.body.pin, false);
    const note = str(req.body.note, 512, 'note') ||
      (kind === 'allow' ? 'approved from a package review' : 'blocked from a package review');

    const type = toolsType(ruleEcosystem(req.body.ecosystem, { mustBeOn: true }));
    const written = [];
    const skipped = [];
    const everyVersion = [];

    for (const raw of items) {
      const typed = String((raw && raw.name) || '').trim();
      const version = str(raw && raw.version, 128, 'version');
      if (!type.validName(typed)) {
        skipped.push({ name: typed || '(blank)', error: type.badName });
        continue;
      }
      const name = type.name(typed);
      // only real versions get pinned, ^4.0.0 names no release
      const range = pin && version && type.validVersion(version) ? version : '';

      if (kind === 'allow') {
        // judge the reviewed version, not the new rule, or a blocked 4.17.20 stays blocked after a "success".
        // no version? any deny on the name refuses
        let stopper = null;
        if (version && type.validVersion(version)) {
          const verdict = await policy.checkVersion(name, version, type.adapter);
          if (!verdict.allowed && verdict.rule && verdict.rule.kind === 'deny') stopper = verdict.rule;
        } else {
          stopper = (await policy.denyRulesFor(name, type.adapter))[0] || null;
        }
        if (stopper) {
          skipped.push({
            name: version ? type.spell(name, version) : name,
            error: `blacklisted by rule ${stopper.pattern}${stopper.version_range ? ` ${stopper.version_range}` : ''}, so it cannot be whitelisted from here`
          });
          continue;
        }
      }

      await rules.upsert(
        { ecosystem: type.id, pattern: name, kind, version_range: range, note, priority: 0, enabled: 1, created_by: req.user.username },
        { note: 'values', enabled: 1 }
      );
      written.push(range ? type.spell(name, range) : name);
      if (kind === 'allow' && !range) everyVersion.push({ ecosystem: type.id, pattern: name, kind, version_range: '', enabled: 1 });
    }

    policy.invalidate();
    require('../../warm-latest').queueRules(everyVersion, actorOf(req));
    if (written.length) {
      await auth.auditReq(req, `tools.decide.${kind}`, `${written.length} packages`, written.slice(0, 50).join(','));
    }
    res.json({ ok: true, kind, written: written.length, skipped });
  })
);

// PyPI release info: JSON API, or the METADATA file (PEP 658). no version = newest
async function describePypiRelease(project, version) {
  try {
    const got = await pypiupstream.getJson(project, version || undefined);
    const info = got.doc.info || {};
    const files = (Array.isArray(got.doc.urls) ? got.doc.urls : []).map((f) => ({
      filename: f.filename,
      kind: f.packagetype === 'bdist_wheel' ? 'wheel' : (f.packagetype === 'sdist' ? 'sdist' : f.packagetype || 'file'),
      size: Number.isSafeInteger(f.size) ? f.size : null,
      uploaded: f.upload_time_iso_8601 || f.upload_time || null,
      sha256: f.digests && f.digests.sha256 ? f.digests.sha256 : null,
      yanked: !!f.yanked,
      yankedReason: f.yanked_reason || null
    }));
    return {
      source: 'JSON API',
      ...pypiMetadata.fromJsonInfo(info),
      yanked: files.length > 0 && files.every((f) => f.yanked),
      yankedReason: (files.find((f) => f.yankedReason) || {}).yankedReason || null,
      files
    };
  } catch (err) {
    if (err.status !== 404) throw err;
  }

  // no JSON API here, so index + metadata file
  const page = (await pypiupstream.getProject(project)).doc;
  const releases = new Map();
  for (const f of page.files) {
    const v = pypiSimple.releaseOf(f.filename, project);
    if (!v) continue;
    if (!releases.has(v)) releases.set(v, []);
    releases.get(v).push(f);
  }
  const chosen = version || [...releases.keys()].sort((a, b) => pypiVersion.compare(b, a))[0];
  const files = releases.get(chosen);
  if (!files) {
    const e = new Error(`${project} has no release ${version || ''} on its registry`.trim());
    e.status = 404;
    throw e;
  }
  const withMeta = files.find((f) => f.coreMetadata && f.filename.endsWith('.whl')) || files.find((f) => f.coreMetadata);
  let described = pypiMetadata.parse('');
  if (withMeta) {
    const got = await pypiupstream.getFile(project, withMeta.filename, chosen, { metadata: true });
    described = pypiMetadata.parse((await require('../../storage/artifacts').readAll(got)).toString('utf8'));
    if (got.temporary) require('fs').promises.unlink(got.file).catch(() => {});
  }
  return {
    source: withMeta ? 'core metadata file' : 'index only, no metadata file is published',
    ...described,
    version: described.version || chosen,
    yanked: files.every((f) => f.yanked),
    yankedReason: (files.find((f) => typeof f.yanked === 'string') || {}).yanked || null,
    files: files.map((f) => ({
      filename: f.filename,
      kind: f.filename.endsWith('.whl') ? 'wheel' : 'sdist',
      size: f.size,
      uploaded: f.uploadTime,
      sha256: f.hashes && f.hashes.sha256 ? f.hashes.sha256 : null,
      yanked: !!f.yanked,
      yankedReason: typeof f.yanked === 'string' ? f.yanked : null
    }))
  };
}

// quick look, touches nothing
router.get(
  '/tools/check',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const type = toolsType(ruleEcosystem(req.query.ecosystem));
    const typed = required(req.query.name, 214, 'package name');
    const version = str(req.query.version, 128, 'version');
    if (!type.validName(typed)) fail(400, type.badName);
    const name = type.name(typed);
    if (type.id === 'pypi' && version && !type.validVersion(version)) fail(400, 'that is not a version pip would understand');
    if (type.id === 'oci' && version && !type.validVersion(version)) fail(400, 'that is not an image tag or a sha256 digest');
    const preview = await previewScope(req.query);
    // an image is judged the way a pull of it is: by tag, digest, what names it, and both of its Docker Hub names
    let verdict;
    if (type.id === 'oci') {
      const images = require('../../registry/oci/upstream');
      const { name: canonical, aliases } = await images.canonicalName(name);
      verdict = await require('../../registry/oci/gate').decide(canonical, version || null, preview.scope, { aliases });
    } else {
      verdict = version
        ? await policy.checkVersion(name, version, type.adapter, preview.scope)
        : await policy.checkPackage(name, type.adapter, preview.scope);
    }

    //Python answers describe the release too. registry down? verdict still stands
    let metadata = null;
    if (type.id === 'pypi' && db.settings.getBool('pypi_enabled')) {
      try {
        metadata = await describePypiRelease(name, version);
      } catch (err) {
        metadata = { error: err.status ? err.message : 'the registry could not be asked about it' };
        if (!err.status) log.warn(`could not describe ${name}`, err.message);
      }
    }

    const lookalike = await typosquat.check(type.id, name).catch(() => null);

    // npm with no version: the latest tag is what people get
    let licenseInfo = null;
    let licenseVersion = version || (metadata && !metadata.error ? metadata.version : null);
    try {
      if (type.id === 'npm' && !licenseVersion) {
        const { doc } = await upstream.getPackument(name, 'full');
        licenseVersion = (doc['dist-tags'] || {}).latest || null;
      }
      if (licenseVersion) licenseInfo = { version: licenseVersion, ...(await license.describe(type.id, name, licenseVersion)) };
    } catch (err) {
      licenseInfo = { error: err.status === 404 ? err.message : 'the license could not be read right now' };
    }
    res.json({
      ecosystem: type.id,
      metadata,
      license: licenseInfo,
      lookalike,
      scope: preview.names,
      name,
      version: version || null,
      allowed: verdict.allowed,
      reason: verdict.reason,
      rule: verdict.rule ? { id: verdict.rule.id, pattern: verdict.rule.pattern, kind: verdict.rule.kind } : null
    });
  })
);

module.exports = router;
