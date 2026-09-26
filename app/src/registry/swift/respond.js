// The Swift registry side helpers: every answer says Content-Version 1, and a no is problem+json, whose detail SwiftPM
// prints as it is.
// Author: Tim Rice

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/swift';
// scope/name, scope/name/version, its Package.swift and .zip, identifiers and login. /swift itself is the npm package
const OURS = /^\/(identifiers$|login$|[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9_-]{0,99}(\.json)?(\/|$))/;

function record(req, fields) {
  access.record(req, { ecosystem: 'swift', ...fields });
}

function json(res, status, body, type = 'application/json') {
  res.set('content-version', '1');
  res.status(status).type(type).send(JSON.stringify(body));
}

function problem(res, status, detail) {
  return json(res, status, { detail }, 'application/problem+json');
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\b(SwiftPackageManager|SwiftPM|swift-package)\b/i;

function looksLikeSwiftClient(req) {
  return !!req.npmIdentity || CLIENT_UA.test(req.get('user-agent') || '');
}

function auditOnly() {
  return db.settings.getBool('audit_mode');
}

function refusal(id, version, reason) {
  let message = `${id}${version ? ` ${version}` : ''} is not approved on this registry. Reason: ${reason}.`;
  const publicUrl = db.settings.get('public_url') || '';
  if (db.settings.getBool('show_help_url') && publicUrl) message += ` Ask for it at ${publicUrl}/_admin.`;
  else message += ' Ask an approver to add it.';
  return message + require('../../services/auto-approve').refusalHint('swift', reason);
}

function refuse(res, id, version, reason, status = 403, policy = status === 403) {
  return problem(res, status, policy ? refusal(id, version, reason) : `${id}${version ? ` ${version}` : ''}: ${reason}`);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the Swift side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  return problem(res, status, err.status ? err.message : 'the git host could not be reached');
}

module.exports = { MOUNT, OURS, record, json, problem, looksLikeSwiftClient, auditOnly, refusal, refuse, failed };
