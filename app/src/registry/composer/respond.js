// The Composer side helpers: json answers, how a no is worded, and the status line composer prints.
// Author: Tim Rice
//
// composer prints the status line of a failed download, so a refusal says its reason there too, one line of text

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/composer';
// packages.json, the p2 metadata and the archives. anything else under /composer is the npm package called composer
const OURS = /^\/(packages\.json$|p2\/|dists\/)/;

function record(req, fields) {
  access.record(req, { ecosystem: 'composer', ...fields });
}

const oneLine = (t) => String(t).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 400);

function json(res, status, body) {
  res.status(status).type('application/json').send(JSON.stringify(body));
}

function text(res, status, message, reasonPhrase) {
  if (reasonPhrase) res.statusMessage = oneLine(reasonPhrase);
  res.status(status).type('text/plain').send(`${message}\n`);
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\bComposer\/\d/i;

function looksLikeComposerClient(req) {
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
  return message + require('../../services/auto-approve').refusalHint('composer', reason);
}

function refuse(res, name, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(name, version, reason) : `${name}${version ? ` ${version}` : ''}: ${reason}`;
  return text(res, status, message, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the Composer side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the Composer repository could not be reached';
  return text(res, status, message, message);
}

module.exports = { MOUNT, OURS, record, json, text, oneLine, looksLikeComposerClient, auditOnly, refusal, refuse, failed };
