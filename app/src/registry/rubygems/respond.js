// The RubyGems side helpers: plain text answers, how a no is worded, and the status line gem and bundler print.
// Author: Tim Rice
//
// a refusal says its reason in the body and in the status line's reason phrase, one line of printable text, so it
// reaches the developer whichever of the two their client shows

const db = require('../../db');
const log = require('../../logger');
const access = require('../shared/access');

const MOUNT = '/rubygems';
// the compact index, the gems, their gemspecs and the full index files. anything else under /rubygems is the npm
// package called rubygems
const OURS = /^\/(versions$|names$|info\/|gems\/|quick\/Marshal\.4\.8\/|specs\.4\.8\.gz$|latest_specs\.4\.8\.gz$|prerelease_specs\.4\.8\.gz$|api\/v1\/(dependencies|gems))/;

function record(req, fields) {
  access.record(req, { ecosystem: 'rubygems', ...fields });
}

const oneLine = (t) => String(t).replace(/[^\x20-\x7e]+/g, ' ').slice(0, 400);

function text(res, status, message, reasonPhrase) {
  if (reasonPhrase) res.statusMessage = oneLine(reasonPhrase);
  res.status(status).type('text/plain').send(`${message}\n`);
}

// NOT a security control, user agents lie. the same hint the other clients get
const CLIENT_UA = /\b(RubyGems|bundler|Ruby)\b/i;

function looksLikeGemClient(req) {
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
  return message + require('../../services/auto-approve').refusalHint('rubygems', reason);
}

// bundler turns a 403 into "Access token could not be authenticated" and a 404 into a quiet fall back to the old
// indexes, so neither says why. a no from the rules goes out as 451, which bundler prints with its body, the reason
function refuse(res, name, version, reason, status = 403, policy = status === 403) {
  const message = policy ? refusal(name, version, reason) : `${name}${version ? ` ${version}` : ''}: ${reason}`;
  return text(res, policy ? 451 : status, message, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the RubyGems side failed', err.message);
  record(req, { ...fields, action: status === 404 ? 'deny' : 'error', status, reason: err.message });
  const message = err.status ? err.message : 'the gem source could not be reached';
  return text(res, status, message, message);
}

module.exports = { MOUNT, OURS, record, text, oneLine, looksLikeGemClient, auditOnly, refusal, refuse, failed };
