// What an event is: the types there are, the fields that may leave the box, and who asked.
// Author: Tim Rice
// events carry context, never a secret, never a token value

const crypto = require('crypto');
const net = require('net');
const db = require('../../db');

const EVENTS = [
  'package.requested', 'package.cached', 'package.blocked', 'package.quarantined', 'package.approved', 'package.released',
  'artifact.integrity_changed', 'vulnerability.discovered', 'vulnerability.remediated', 'malware.detected',
  'policy.violation', 'waiver.created', 'waiver.expired'
];

// eslint-disable-next-line no-control-regex -- stripping control characters is the point
const clip = (v, n) => (v === undefined || v === null || v === '' ? null : String(v).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n));

// only these fields ever leave the box, whatever a caller hands in
function build(type, f = {}) {
  const num = (v) => (v === undefined || v === null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    event_type: type,
    source: 'forgerepo',
    registry: clip(db.settings.get('registry_name') || 'ForgeRepo', 128),
    severity: clip(f.severity, 16),
    ecosystem: clip(f.ecosystem, 16),
    package: clip(f.package, 214),
    version: clip(f.version, 64),
    filename: clip(f.filename, 255),
    artifact_hash: /^[0-9a-f]{64}$/i.test(String(f.artifactHash || '')) ? String(f.artifactHash).toLowerCase() : null,
    user: clip(f.user, 64),
    token: clip(f.token, 128),
    application: clip(f.application, 128),
    environment: clip(f.environment, 128),
    source_ip: net.isIP(String(f.sourceIp || '')) ? String(f.sourceIp) : null,
    policy: clip(f.policy, 255),
    reason: clip(f.reason, 1000),
    action: clip(f.action, 64),
    cve: clip(f.cve, 512),
    advisories: clip(f.advisories, 1000),
    cvss: num(f.cvss),
    epss: num(f.epss),
    cisa_kev: f.cisaKev === undefined || f.cisaKev === null ? null : !!f.cisaKev
  };
}

// who asked, straight off a registry or portal request. the token's name, never the token
function who(req) {
  if (!req) return {};
  const id = req.npmIdentity || {};
  const auth = require('../../security/auth');
  return {
    user: id.username || (req.user && req.user.username) || null,
    token: id.name || null,
    application: id.application || null,
    environment: id.environment || null,
    sourceIp: auth.clientIp(req)
  };
}

module.exports = { EVENTS, clip, build, who };
