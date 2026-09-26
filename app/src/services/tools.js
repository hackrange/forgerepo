// Tools: every published version of a package and whether a client would be offered it right now.
// Author: Tim Rice

const semver = require('semver');
const db = require('../db');
const policy = require('../policy');
const upstream = require('../registry/npm/upstream');
const quarantine = require('../policy/quarantine');
const resolution = require('../policy/resolution');
const cooloff = require('../policy/cooloff');
const waivers = require('../policy/waivers');
const pypiVersion = require('../ecosystems/pypi/version');
const pypiupstream = require('../registry/pypi/upstream');
const pypiSimple = require('../ecosystems/pypi/simple');
const holdsRepo = require('../db/repositories/quarantine');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const { fail } = require('../lib/errors');

// newest first, and the upstream's publish times for cooling off
async function publishedVersions(type, name) {
  let versions = [];
  let npmTimes = {};
  let pyFiles = [];
  try {
    if (type.id === 'pypi') {
      if (!db.settings.getBool('pypi_enabled')) fail(400, 'PyPI is switched off in Settings');
      const got = await pypiupstream.getProject(name);
      pyFiles = got.doc.files || [];
      const seen = new Set();
      for (const f of got.doc.files || []) {
        const v = pypiSimple.releaseOf(f.filename, name);
        if (v && pypiVersion.valid(v)) seen.add(v);
      }
      versions = [...seen].sort((a, b) => pypiVersion.compare(b, a));
    } else {
      const { doc } = await upstream.getPackument(name, 'full');
      versions = Object.keys(doc.versions || {}).filter((v) => semver.valid(v)).sort(semver.rcompare);
      npmTimes = doc.time && typeof doc.time === 'object' ? doc.time : {};
    }
  } catch (err) {
    fail(err.status || 502, err.status ? err.message : 'the registry could not be asked about it');
  }
  return { versions, npmTimes, pyFiles };
}

// type is a tools-type, preview is a checked scope
async function candidates(type, name, preview) {
  if (type.walks === false) fail(400, 'an image has no list of versions to choose from here, only the tags somebody pulled');
  const published = await publishedVersions(type, name);
  const { npmTimes, pyFiles } = published;
  const total = published.versions.length;
  const versions = published.versions.slice(0, 300);
  const holds = await holdsRepo.heldVersions(type.id, name);
  const findings = new Map((await vulnerabilities.findingsForPackage(type.id, name)).map((f) => [f.version, f]));
  const strict = quarantine.mode() === 'strict';
  const on = resolution.enabled();
  const cooling = cooloff.enabled() && !cooloff.exempt(name);
  const normPy = (v) => {
    try {
      return pypiVersion.normalize(v) || v;
    } catch (err) {
      return v;
    }
  };
  let pyTimes = new Map();
  if (cooling && type.id === 'pypi') {
    pyTimes = cooloff.pypiTimes(pyFiles, (fn) => pypiSimple.releaseOf(fn, name), normPy);
    if (versions.some((v) => !pyTimes.has(normPy(v)))) {
      try {
        cooloff.mergeJsonTimes(pyTimes, ((await pypiupstream.getJson(name)).doc || {}).releases, normPy);
      } catch (err) {
        // no JSON API, unknown times stay unknown
      }
    }
  }

  const list = [];
  for (const version of versions) {
    const reasons = [];
    let status = 'approved';
    const verdict = await policy.checkVersion(name, version, type.adapter, preview.scope);
    if (!verdict.allowed) {
      status = 'blocked';
      reasons.push(verdict.reason);
    }
    const mine = holds.filter((x) => x.version === version);
    if (mine.some((x) => x.status === 'rejected')) {
      if (status === 'approved') status = 'quarantined';
      reasons.push('rejected in quarantine');
    } else if (mine.length) {
      if (status === 'approved' && strict) status = 'quarantined';
      reasons.push(strict ? 'held in quarantine' : 'held in quarantine, still served in permissive mode');
    }
    const finding = findings.get(version) ? await resolution.withIntel(findings.get(version)) : null;
    if (finding) {
      const sev = String(finding.severity || 'unknown').toLowerCase();
      const advisoryWaiver = resolution.tooRisky(finding) && on ? await waivers.advisoryWaived(type.id, name, version, finding, preview.scope) : null;
      if (advisoryWaiver) {
        reasons.push(`${sev} advisory, waived until ${String(advisoryWaiver.expires_at).slice(0, 10)}`);
      } else if (resolution.tooRisky(finding) && on) {
        if (status === 'approved') status = 'excluded';
        reasons.push(`${sev} advisory${{ kev: ', exploited in the wild (CISA KEV)', epss: ', likely to be exploited (EPSS)' }[resolution.why(finding)] || ''}, left out by safe resolution`);
      } else {
        reasons.push(`${sev} advisory${resolution.tooRisky(finding) ? ', would be left out with safe resolution on' : ''}`);
      }
    }
    if (cooling) {
      const why = type.id === 'pypi' ? cooloff.pypiReason(pyTimes, version, normPy) : cooloff.reasonFor(npmTimes[version]);
      const coolWaiver = why && !cooloff.pinned(verdict, version) ? await waivers.coolingWaived(type.id, name, version, preview.scope) : null;
      if (why && cooloff.pinned(verdict, version)) {
        reasons.push(`${why}, but an allow rule pins this exact version`);
      } else if (coolWaiver) {
        reasons.push(`${why}, but a waiver covers it until ${String(coolWaiver.expires_at).slice(0, 10)}`);
      } else if (why) {
        if (status === 'approved') status = 'cooling';
        reasons.push(why);
      }
    }
    list.push({ version, status, offered: status === 'approved', reasons });
  }

  return {
    ecosystem: type.id, name, total, shown: list.length, safeResolution: on,
    threshold: resolution.threshold(), quarantineMode: quarantine.mode(), cooloffHours: cooloff.enabled() ? cooloff.hours() : 0,
    scope: preview.names, candidates: list
  };
}

module.exports = { candidates };
