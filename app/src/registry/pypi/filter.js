// Which files and releases of a project a client may see: kills, holds, rules, advisories, cooling off.
// Author: Tim Rice

const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const pypiVersion = require('../../ecosystems/pypi/version');
const simple = require('../../ecosystems/pypi/simple');
const pypi = require('./upstream');
const quarantine = require('../../policy/quarantine');
const cooloff = require('../../policy/cooloff');
const killswitch = require('../../policy/killswitch');
const waivers = require('../../policy/waivers');
const resolution = require('../../policy/resolution');
const registryMode = require('../../policy/mode');
const pypiFiles = require('../../db/repositories/pypi-files');
const { auditOnly, normVersion } = require('./respond');

const adapter = ecosystems.adapter('pypi');

// normalized release -> first upload time. the index page first, the JSON API for whatever it left out
async function releaseTimes(project, files) {
  const releaseOf = (fn) => (simple.validFilename(fn) ? simple.releaseOf(fn, project) : null);
  const times = cooloff.pypiTimes(files, releaseOf, normVersion);
  const gaps = (files || []).some((f) => {
    const v = releaseOf(f.filename);
    return v && !times.has(normVersion(v));
  });
  if (gaps) {
    try {
      cooloff.mergeJsonTimes(times, ((await pypi.getJson(project)).doc || {}).releases, normVersion);
    } catch (err) {
      // private indexes often have no JSON API. unknown it is
    }
  }
  return times;
}

// why this exact release is still too new, or null
async function pypiCooling(project, version, verdict, scope) {
  if (auditOnly() || !cooloff.enabled() || cooloff.exempt(project) || cooloff.pinned(verdict, version)) return null;
  if (await waivers.coolingWaived('pypi', project, version, scope)) return null;
  let files = [];
  try {
    files = (await pypi.getProject(project)).doc.files;
  } catch (err) {
    files = [];
  }
  return cooloff.pypiReason(await releaseTimes(project, files), version, normVersion);
}

// files with no readable release get dropped, no rule could apply
async function filterPage(project, page, scope) {
  const verdicts = new Map();
  const decide = async (version) => {
    if (!verdicts.has(version)) verdicts.set(version, await policy.checkVersion(project, version, adapter, scope));
    return verdicts.get(version);
  };
  const lenient = auditOnly();
  // kills apply in audit only mode too
  const pageVersions = [...new Set(page.files.map((f) => (simple.validFilename(f.filename) ? simple.releaseOf(f.filename, project) : null)).filter(Boolean))];
  const killed = await killswitch.killedVersions('pypi', project, [...pageVersions, ...(Array.isArray(page.versions) ? page.versions : [])]);
  // lockdown: only files already cached are offered, in every mode
  const onDisk = registryMode.lockdown() ? new Set((await pypiFiles.cachedFiles(project)).map((r) => r.filename)) : null;
  // held (strict) and rejected files never make it onto the page
  const hidden = new Map((lenient ? [] : await quarantine.hiddenFor('pypi', project)).map((h) => [h.filename, h.status]));
  const norm = normVersion;
  const risky = new Map();
  if (!lenient) for (const [v, reason] of await resolution.securityExclusions('pypi', project, scope)) risky.set(norm(v), reason);

  const cooling = !lenient && cooloff.enabled() && !cooloff.exempt(project);
  const times = cooling ? await releaseTimes(project, page.files) : null;
  const tooNew = async (version) => {
    if (!cooling) return null;
    const why = cooloff.pypiReason(times, version, norm);
    if (!why || cooloff.pinned(await decide(version), version)) return null;
    return (await waivers.coolingWaived('pypi', project, version, scope)) ? null : why;
  };

  const excluded = [];
  const noted = new Set();
  const exclude = (entry) => {
    const key = `${entry.kind}\n${entry.version}\n${entry.filename || ''}`;
    if (!noted.has(key)) excluded.push(entry);
    noted.add(key);
  };

  const files = [];
  let removed = 0;
  for (const f of page.files) {
    const version = simple.validFilename(f.filename) ? simple.releaseOf(f.filename, project) : null;
    if (!version) {
      removed += 1;
      continue;
    }
    if (onDisk && !onDisk.has(f.filename)) {
      removed += 1;
      exclude({ version, filename: f.filename, kind: 'lockdown', reason: 'not cached, and the registry is in lockdown' });
      continue;
    }
    if (killed.has(version)) {
      removed += 1;
      exclude({ version, kind: 'killed', reason: killed.get(version) });
      continue;
    }
    if (hidden.has(f.filename)) {
      removed += 1;
      exclude({ version, filename: f.filename, kind: 'quarantine', reason: hidden.get(f.filename) === 'rejected' ? 'rejected in quarantine' : 'held in quarantine' });
      continue;
    }
    const verdict = await decide(version);
    if (!verdict.allowed && !lenient) {
      removed += 1;
      exclude({ version, kind: 'rule', reason: verdict.reason });
      continue;
    }
    if (risky.has(norm(version))) {
      removed += 1;
      exclude({ version, kind: 'security', reason: risky.get(norm(version)) });
      continue;
    }
    const young = await tooNew(version);
    if (young) {
      removed += 1;
      exclude({ version, kind: 'cooloff', reason: young });
      continue;
    }
    files.push({ ...f, version });
  }

  let versions = null;
  if (Array.isArray(page.versions)) {
    versions = [];
    for (const v of page.versions) {
      if (!pypiVersion.valid(v)) continue;
      if (killed.has(v)) continue;
      if (onDisk && !files.some((x) => norm(x.version) === norm(v))) continue;
      if (risky.has(norm(v))) continue;
      if (await tooNew(v)) continue;
      if ((await decide(v)).allowed || lenient) versions.push(v);
    }
  }
  return { files, versions, removed, excluded, risky, norm };
}

module.exports = { adapter, releaseTimes, pypiCooling, filterPage };
