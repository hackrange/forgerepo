// The Maven side helpers: plain text answers, how a no is worded, and the status line mvn and gradle print.
// Author: Tim Rice
//
// mvn and gradle show a failed download as "status code: 403, reason phrase: ...". so a refusal puts its reason in the
// reason phrase as well as the body, one line of printable text, nothing a header could be split on

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/maven';
// group/artifact/file at least. /maven and /maven/-/... are the npm package called maven
const OURS = /^\/[A-Za-z0-9_][^/]*\/[^/]+\/[^/]+/;

function record(req, fields) {
  access.record(req, { ecosystem: 'maven', ...fields });
}

const oneLine = (text) => String(text).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 400);

function text(res, status, message, reasonPhrase) {
  if (reasonPhrase) res.statusMessage = oneLine(reasonPhrase);
  res.status(status).type('text/plain').send(`${message}\n`);
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\b(Apache-Maven|Maven|Gradle|Aether|maven-resolver|sbt|Coursier|Ivy|Leiningen|Bazel)\b/i;

function looksLikeMavenClient(req) {
  return !!req.npmIdentity || CLIENT_UA.test(req.get('user-agent') || '');
}

function auditOnly() {
  return db.settings.getBool('audit_mode');
}

function refusal(name, version, reason) {
  let message = `${name}${version ? ` ${version}` : ''} is not approved on this registry. Reason: ${reason}.`;
  const publicUrl = db.settings.get('public_url') || '';
  if (db.settings.getBool('show_help_url') && publicUrl) message += ` Ask for it at ${publicUrl}/_admin.`;
  else message += ' Ask an approver to add it.';
  return message + require('../../services/auto-approve').refusalHint('maven', reason);
}

// policy: a no from the rules, the kill switch and friends, worded to say what to ask for
function refuse(res, name, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(name, version, reason) : `${name}${version ? ` ${version}` : ''}: ${reason}`;
  return text(res, status, message, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the Maven side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the repository could not be reached';
  return text(res, status, message, message);
}

module.exports = { MOUNT, OURS, record, text, oneLine, looksLikeMavenClient, auditOnly, refusal, refuse, failed };
