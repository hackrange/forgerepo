// PyPI side helpers: plain text answers, how a no is worded, and addresses pointing back here.
// Author: Tim Rice

const db = require('../../db');
const log = require('../../logger');
const pypiName = require('../../ecosystems/pypi/name');
const pypiVersion = require('../../ecosystems/pypi/version');
const access = require('../shared/access');
const shared = require('../shared/requests');

const MOUNT = '/pypi';

// anything else under /pypi is still npm's
const OURS = /^\/(simple|files|pypi|legacy)(\/|$)/;

function record(req, fields) {
  access.record(req, { ecosystem: 'pypi', ...fields });
}

function text(res, status, message) {
  res.status(status).type('text/plain').send(`${message}\n`);
}

// keeps the query string, that's where ?format= lives
function redirect(req, res, to) {
  const at = req.originalUrl.indexOf('?');
  res.redirect(301, at >= 0 ? to + req.originalUrl.slice(at) : to);
}

// NOT a security control, user agents lie. see looksLikeNpmClient
const CLIENT_UA = /\b(pip|uv|poetry|pdm|pipenv|hatch|twine|pex|rye|conda|devpi|pip-audit|setuptools|python-requests|CPython|PyPy)\b/i;

function looksLikePythonClient(req) {
  return !!req.npmIdentity || CLIENT_UA.test(req.get('user-agent') || '');
}

function auditOnly() {
  return db.settings.getBool('audit_mode');
}

function askFor(req, project, version, reason, source) {
  return shared.openRequest(req, project, version, reason, {
    ecosystem: 'pypi',
    looksLikeClient: looksLikePythonClient(req),
    source
  });
}

function refuse(req, res, project, version, reason) {
  let message = `${project}${version ? ` ${version}` : ''} is not approved on this registry. Reason: ${reason}.`;
  const publicUrl = db.settings.get('public_url') || '';
  if (db.settings.getBool('show_help_url') && publicUrl) message += ` Ask for it at ${publicUrl}/_admin.`;
  else message += ' Ask an approver to add it.';
  message += require('../../services/auto-approve').refusalHint('pypi', reason);
  return text(res, 403, message);
}

function failed(req, res, err, fields) {
  const status = err.status || 502;
  if (!err.status) log.error('the PyPI side failed', err.message);
  record(req, { action: 'error', status, reason: err.message, ...fields });
  return text(res, status, err.status ? err.message : 'something went wrong fetching that from the upstream registry');
}

// keyed on the normalized version so 2.0 and 2.0.0 are the same release
function normVersion(v) {
  try {
    return pypiVersion.normalize(v) || v;
  } catch (err) {
    return v;
  }
}

function fileUrl(req, project, filename) {
  return `${access.baseUrl(req)}${MOUNT}/files/${project}/${encodeURIComponent(filename)}`;
}

function projectFrom(raw) {
  return typeof raw === 'string' && pypiName.valid(raw) ? pypiName.normalize(raw) : null;
}

module.exports = {
  MOUNT, OURS, record, text, redirect, looksLikePythonClient, auditOnly, askFor, refuse, failed, normVersion, fileUrl, projectFrom
};
