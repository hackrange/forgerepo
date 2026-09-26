// The CocoaPods side helpers: plain text answers, how a no is worded, and the status line pod prints.
// Author: Tim Rice
//
// a refusal says its reason in the body and in the status line's reason phrase, one line of printable text, so it
// reaches the developer whichever of the two pod shows

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/cocoapods';
// the CDN's files, the podspecs and the source archives. anything else under /cocoapods is the npm package called cocoapods
const OURS = /^\/(CocoaPods-version\.yml$|all_pods_versions_[0-9a-f_]+\.txt$|deprecated_podspecs\.txt$|all_pods\.txt$|Specs\/|archives\/)/;

function record(req, fields) {
  access.record(req, { ecosystem: 'cocoapods', ...fields });
}

const oneLine = (t) => String(t).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 400);

function text(res, status, message, reasonPhrase) {
  if (reasonPhrase) res.statusMessage = oneLine(reasonPhrase);
  res.status(status).type('text/plain').send(`${message}\n`);
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\b(CocoaPods|cocoapods-downloader|Typhoeus|curl)\b/i;

function looksLikePodClient(req) {
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
  return message + require('../../services/auto-approve').refusalHint('cocoapods', reason);
}

function refuse(res, name, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(name, version, reason) : `${name}${version ? ` ${version}` : ''}: ${reason}`;
  return text(res, status, message, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the CocoaPods side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the CDN could not be reached';
  return text(res, status, message, message);
}

module.exports = { MOUNT, OURS, record, text, oneLine, looksLikePodClient, auditOnly, refusal, refuse, failed };
