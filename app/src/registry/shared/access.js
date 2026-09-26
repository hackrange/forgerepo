// What every registry request leaves behind: the access log row, and the address clients get sent back to.
// Author: Tim Rice

const db = require('../../db');
const config = require('../../config');
const auth = require('../../security/auth');
const accessLog = require('../../db/repositories/access-log');
const log = require('../../logger');

function baseUrl(req) {
  const configured = db.settings.get('public_url') || config.publicUrl;
  if (configured) return String(configured).replace(/\/+$/, '');
  const host = req.get('x-forwarded-host') || req.get('host') || `localhost:${config.port}`;
  const proto = req.protocol || 'http';
  return `${proto}://${host}`;
}

// one npm-session id per install, ties metadata to the tarball. no id, oh well
function sessionOf(req) {
  const id = req.get('npm-session');
  if (!id || !/^[A-Za-z0-9._-]{4,64}$/.test(id)) return null;
  return id;
}

// access_log row, fire and forget
function record(req, fields) {
  const row = {
    ip: auth.clientIp(req),
    user_id: (req.npmIdentity && req.npmIdentity.userId) || null,
    token_id: (req.npmIdentity && req.npmIdentity.id) || null,
    token_name: (req.npmIdentity && req.npmIdentity.name) || null,
    // copied, not looked up later. revoking a token shouldn't rewrite history
    application: (req.npmIdentity && req.npmIdentity.application) || null,
    environment: (req.npmIdentity && req.npmIdentity.environment) || null,
    method: req.method,
    path: String(req.originalUrl).slice(0, 512),
    package_name: null,
    version: null,
    pulled_version: null,
    pulled_exact: 0,
    action: 'allow',
    reason: null,
    blocked_by: null,
    rule_id: null,
    status: 200,
    bytes: 0,
    cache_hit: 0,
    duration_ms: req.startedAt ? Date.now() - req.startedAt : 0,
    ecosystem: 'npm',
    ...fields
  };
  const ci = require('../../policy/dryrun').ciOf(req.get('user-agent'));
  require('../../consumption').note(row, ci);
  if (row.package_name && ((row.action === 'deny' && Number(row.status) === 403) || (row.action === 'audit' && row.reason))) {
    require('../../integrations/events').emit(row.action === 'deny' ? 'package.blocked' : 'policy.violation', {
      ecosystem: row.ecosystem, package: row.package_name, version: row.version, user: (req.npmIdentity && req.npmIdentity.username) || null,
      token: row.token_name, application: row.application, environment: row.environment, sourceIp: row.ip, reason: row.reason,
      action: row.action === 'deny' ? 'refused' : 'served, audit only'
    });
  }
  accessLog.insert(row, sessionOf(req), ci).catch((err) => log.error('access log write failed', err.message));
}

// the exact version a session pulled replaces the guess its metadata row made
function notePulled(req, name, version) {
  const session = sessionOf(req);
  if (!session) return;
  accessLog.notePulled(session, name, version).catch((err) => log.error('could not note the pulled version', err.message));
}

module.exports = { baseUrl, sessionOf, record, notePulled };
