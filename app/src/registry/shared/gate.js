// Everything a file goes through before and after it is fetched, for the ecosystems that came after npm and PyPI.
// Author: Tim Rice
//
// the order PyPI's file handler uses: a kill (on the version or this exact file), the rules (a refusal opens a request,
// audit only mode lets it through and learns), a lookalike name, the license, quarantine, advisories too serious for
// safe resolution, cooling off. then, with the bytes in hand, a kill on their hash and scan before serve

const db = require('../../db');
const policy = require('../../policy');
const killswitch = require('../../policy/killswitch');
const quarantine = require('../../policy/quarantine');
const resolution = require('../../policy/resolution');
const cooloff = require('../../policy/cooloff');
const waivers = require('../../policy/waivers');
const typosquat = require('../../policy/typosquat');
const license = require('../../policy/licenses');
const shared = require('./requests');
const { scanBeforeServe, killedFile } = require('./serving');

const auditOnly = () => db.settings.getBool('audit_mode');
const no = (status, reason, by, extra) => ({ refused: { status, reason, by, ...(extra || {}) } });

/**
 * f: { ecosystem, adapter, name, version, filename, published, pin, looksLikeClient }. pin is how a request names the
 * version (13.0.3 for NuGet). the answer is { refused } or { verdict, lic }
 */
async function before(req, f) {
  const scope = policy.scopeOf(req);
  const dead = (await killswitch.check(f.ecosystem, f.name, f.version)) || (await killswitch.checkFile(f.ecosystem, f.name, f.filename));
  if (dead) return no(403, dead.reason, 'killswitch');
  const verdict = await policy.checkVersion(f.name, f.version, f.adapter, scope);
  if (!verdict.allowed && !auditOnly()) {
    if (!verdict.lifecycle) await shared.openRequest(req, f.name, f.pin || f.version, verdict.reason, { ecosystem: f.ecosystem, looksLikeClient: f.looksLikeClient });
    return no(403, verdict.reason, null, { rule: verdict.rule });
  }
  if (auditOnly() && !(verdict.allowed && verdict.rule && verdict.rule.kind === 'allow')) {
    shared.openRequest(req, f.name, f.pin || f.version, verdict.reason, { ecosystem: f.ecosystem, looksLikeClient: f.looksLikeClient, source: 'learning' }).catch(() => {});
  }
  const squat = await typosquat.verdict(f.ecosystem, f.name);
  if (squat && squat.block) return no(403, squat.reason, 'typosquat');
  const lic = await license.gate({ ecosystem: f.ecosystem, packageName: f.name, version: f.version, filename: f.filename });
  if (lic && lic.unavailable) return no(503, lic.reason, 'license');
  const held = await quarantine.verdict(f.ecosystem, f.name, f.version, f.filename);
  if (held && held.refuse) return no(403, held.reason, held.source === 'malware' ? 'malware' : 'quarantine');
  if (!auditOnly()) {
    const risky = await resolution.securityReason(f.ecosystem, f.name, f.version, scope);
    if (risky) return no(403, risky, 'resolution');
    if (cooloff.enabled() && !cooloff.exempt(f.name) && !cooloff.pinned(verdict, f.version)) {
      const young = cooloff.reasonFor(f.published);
      if (young && !(await waivers.coolingWaived(f.ecosystem, f.name, f.version, scope))) return no(403, young, 'cooloff');
    }
  }
  return { verdict, lic };
}

// the bytes are here: a kill on their hash, then scan before serve. null means send them
async function after(f, got) {
  const dead = await killedFile(got.artifactId);
  if (dead) return { status: 403, reason: dead.reason, by: 'killswitch' };
  return scanBeforeServe({ ecosystem: f.ecosystem, name: f.name, version: f.version, filename: f.filename, artifactId: got.artifactId });
}

module.exports = { auditOnly, before, after };
