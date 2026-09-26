// The NuGet side helpers: json answers, how a no is worded, and the warning header dotnet prints.
// Author: Tim Rice
//
// dotnet shows a 403 as "Response status code does not indicate success: 403" and nothing else. it does print
// X-NuGet-Warning though, so every refusal says its reason there too

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/nuget';
// under the mount. anything else, /nuget itself included, is the npm package called nuget
// /api/v2/package is where dotnet nuget push sends a package
const OURS = /^\/(v3|v3-flatcontainer)(\/|$)|^\/api\/v2\/package(\/|$)/;
const PUSH = /^\/api\/v2\/package(\/|$)/;

function record(req, fields) {
  access.record(req, { ecosystem: 'nuget', ...fields });
}

// one line of plain text for a header, nothing a proxy or the client could trip on
function warn(res, message) {
  res.set('x-nuget-warning', String(message).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 1000));
}

function json(res, status, body) {
  res.status(status).json(body);
}

// NOT a security control, user agents lie. the same hint npm, pip and docker clients get
const CLIENT_UA = /\b(NuGet|dotnet|nuget\.exe|Paket|MSBuild|NuGet\.Protocol)\b/i;

function looksLikeNugetClient(req) {
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
  return message + require('../../services/auto-approve').refusalHint('nuget', reason);
}

// policy: the answer is a no from the rules, the kill switch or the like, so it says what to ask for. otherwise (a
// scan still running, the feed down) it just says what happened
function refuse(res, id, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(id, version, reason) : `${id}${version ? ` ${version}` : ''}: ${reason}`;
  warn(res, message);
  return json(res, status, { error: message });
}

// an upstream or cache problem, said in the client's terms. a 5xx we did not mean gets logged, never shown
function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the NuGet side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the feed could not be reached';
  warn(res, message);
  return json(res, status, { error: message });
}

module.exports = { MOUNT, OURS, PUSH, record, warn, json, looksLikeNugetClient, auditOnly, refusal, refuse, failed };
