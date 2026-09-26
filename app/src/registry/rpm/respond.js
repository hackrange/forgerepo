// The RPM side helpers: plain text answers, how a no is worded, and the status line dnf prints.
// Author: Tim Rice

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/rpm';
// a mirror's repodata and its packages. anything else under /rpm is the npm package called rpm
const OURS = /^\/[a-z0-9][a-z0-9-]{0,63}\/(repodata\/[A-Za-z0-9._-]+$|[A-Za-z0-9._+~^/-]+\.rpm$)/;

function record(req, fields) {
  access.record(req, { ecosystem: 'rpm', ...fields });
}

const oneLine = (t) => String(t).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 400);

function text(res, status, message, reasonPhrase) {
  if (reasonPhrase) res.statusMessage = oneLine(reasonPhrase);
  res.status(status).type('text/plain').send(`${message}\n`);
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\b(libdnf|dnf|librepo|yum|zypper|PackageKit)\b/i;

function looksLikeRpmClient(req) {
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
  return message + require('../../services/auto-approve').refusalHint('rpm', reason);
}

function refuse(res, name, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(name, version, reason) : `${name}${version ? ` ${version}` : ''}: ${reason}`;
  return text(res, status, message, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the RPM side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the mirror could not be reached';
  return text(res, status, message, message);
}

module.exports = { MOUNT, OURS, record, text, oneLine, looksLikeRpmClient, auditOnly, refusal, refuse, failed };
