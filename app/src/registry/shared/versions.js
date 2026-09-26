// Which versions of a package a client gets to see, for the ecosystems that came after npm and PyPI.
// Author: Tim Rice
//
// the same checks, in the same order, as PyPI's page filter: lockdown, kills, quarantine, the rules, advisories too
// serious for safe resolution, and versions still cooling off. audit only mode (lenient) keeps everything the rules
// would have hidden, a kill and lockdown never soften

const policy = require('../../policy');
const killswitch = require('../../policy/killswitch');
const quarantine = require('../../policy/quarantine');
const resolution = require('../../policy/resolution');
const cooloff = require('../../policy/cooloff');
const waivers = require('../../policy/waivers');
const mode = require('../../policy/mode');
const artifactsRepo = require('../../db/repositories/artifacts');

/**
 * versions: [{ version, published }]. fileOf(version) names the file a hold would be on.
 * returns the versions let through, and why each other one was not
 */
async function visible({ ecosystem, adapter, name, versions, fileOf, scope, lenient }) {
  const list = versions.map((v) => v.version);
  const killed = await killswitch.killedVersions(ecosystem, name, list);
  const onDisk = mode.lockdown() ? new Set(await artifactsRepo.cachedVersions(ecosystem, name)) : null;
  const hidden = new Set((lenient ? [] : await quarantine.hiddenFor(ecosystem, name)).map((h) => h.filename));
  const risky = lenient ? new Map() : await resolution.securityExclusions(ecosystem, name, scope);
  const cooling = !lenient && cooloff.enabled() && !cooloff.exempt(name);

  const allowed = [];
  const excluded = [];
  for (const v of versions) {
    const out = (kind, reason) => excluded.push({ version: v.version, kind, reason });
    if (onDisk && !onDisk.has(v.version)) {
      out('lockdown', 'not cached, and the registry is in lockdown');
      continue;
    }
    if (killed.has(v.version)) {
      out('killed', killed.get(v.version));
      continue;
    }
    if (hidden.has(fileOf(v.version))) {
      out('quarantine', 'held in quarantine');
      continue;
    }
    const verdict = await policy.checkVersion(name, v.version, adapter, scope);
    if (!verdict.allowed && !lenient) {
      out('rule', verdict.reason);
      continue;
    }
    if (risky.has(v.version)) {
      out('security', risky.get(v.version));
      continue;
    }
    if (cooling && !cooloff.pinned(verdict, v.version)) {
      const young = cooloff.reasonFor(v.published);
      if (young && !(await waivers.coolingWaived(ecosystem, name, v.version, scope))) {
        out('cooloff', young);
        continue;
      }
    }
    allowed.push(v);
  }
  return { allowed, excluded };
}

module.exports = { visible };
