// The APT side helpers: plain text answers, how a no is worded, and the status line apt prints.
// Author: Tim Rice

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/apt';
// a mirror's dists and pool, and the box's signing key. anything else under /apt is the npm package called apt
const OURS = /^\/(signing-key\.asc$|[a-z0-9][a-z0-9-]{0,63}\/(dists\/[a-z0-9][a-z0-9._-]{0,63}\/[A-Za-z0-9._+~/-]+$|pool\/[A-Za-z0-9._+~/-]+\.u?deb$))/;

function record(req, fields) {
  access.record(req, { ecosystem: 'apt', ...fields });
}

const oneLine = (t) => String(t).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 400);

function text(res, status, message, reasonPhrase) {
  if (reasonPhrase) res.statusMessage = oneLine(reasonPhrase);
  res.status(status).type('text/plain').send(`${message}\n`);
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\b(Debian APT-HTTP|APT-HTTP|apt-cacher|Acquire)\b/i;

function looksLikeAptClient(req) {
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
  return message + require('../../services/auto-approve').refusalHint('apt', reason);
}

function refuse(res, name, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(name, version, reason) : `${name}${version ? ` ${version}` : ''}: ${reason}`;
  return text(res, status, message, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the APT side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the mirror could not be reached';
  return text(res, status, message, message);
}

module.exports = { MOUNT, OURS, record, text, oneLine, looksLikeAptClient, auditOnly, refusal, refuse, failed };
