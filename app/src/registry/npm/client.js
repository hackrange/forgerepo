// npm side helpers: is this an npm client, how a no is worded, and the package counters.
// Author: Tim Rice

const db = require('../../db');
const packages = require('../../db/repositories/packages');
const shared = require('../shared/requests');

// NOT a security control (headers lie), just keeps scanner junk out of the approval queue
const CLIENT_UA = /\b(npm|yarn|pnpm|bun|node|corepack)\b/i;

function looksLikeNpmClient(req) {
  if (req.npmIdentity) return true;
  if (req.get('npm-command') || req.get('npm-session')) return true;
  if (String(req.get('accept') || '').includes('install-v1')) return true;
  return CLIENT_UA.test(req.get('user-agent') || '');
}

// an allow rule said yes, as opposed to blacklist mode shrugging
function explicitlyAllowed(verdict) {
  return !!(verdict && verdict.allowed && verdict.rule && verdict.rule.kind === 'allow');
}

// npm prints `error`. portal link only with show_help_url, maybe don't advertise it
function refuse(res, req, name, version, verdict) {
  const publicUrl = db.settings.get('public_url') || '';
  let msg = `${name}${version ? `@${version}` : ''} is not approved on this registry. Reason: ${verdict.reason}.`;
  if (db.settings.getBool('show_help_url')) {
    msg += publicUrl ? ` Ask for it at ${publicUrl}/_admin.` : ' Ask an approver to add it.';
  } else {
    msg += ' Ask an approver to add it.';
  }
  if (!verdict.rule) msg += require('../../services/auto-approve').refusalHint('npm', verdict.reason);
  res.status(403).json({ error: msg, reason: verdict.reason, package: name, version: version || null });
}

function openRequest(req, name, version, reason, options = {}) {
  const looksLikeClient = options.looksLikeClient !== undefined ? options.looksLikeClient : looksLikeNpmClient(req);
  return shared.openRequest(req, name, version, reason, { ...options, looksLikeClient });
}

// Only tarballs count. a scanner asking for /index.php looks like a real package request
// (some of those names exist on npm), but none gets a valid tarball. the tell
function countServed(name) {
  packages.countServed(name).catch(() => {});
}

function countBlocked(name) {
  packages.countBlocked(name).catch(() => {});
}

module.exports = { looksLikeNpmClient, explicitlyAllowed, refuse, openRequest, countServed, countBlocked };
