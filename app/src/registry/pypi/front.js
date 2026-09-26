// The PyPI front door: is this ours, who is asking, and nothing but reads.
// Author: Tim Rice
// PyPI off = falls through to npm ("pypi" is a valid npm name too)

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, text, looksLikePythonClient } = require('./respond');

function ours(req, res, next) {
  // writes to the root are uploads. reads of it are the npm package called pypi
  const write = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  if (!OURS.test(req.path) && !(write && req.path === '/')) return next('router');
  if (!db.settings.getBool('pypi_enabled')) return next('router');
  return next();
}

// pip sends the token as the basic auth password. the 401 challenge makes it go check keyring/.netrc
const identify = wrap(async (req, res, next) => {
  req.startedAt = Date.now();
  const challenge = (message, reason) => {
    record(req, { action: 'deny', status: 401, reason });
    res.set('www-authenticate', 'Basic realm="ForgeRepo", charset="UTF-8"');
    return text(res, 401, message);
  };

  const raw = auth.registryCredential(req);
  if (raw) {
    const token = req.npmIdentity || (await auth.lookupToken(raw));
    if (token) {
      req.npmIdentity = token;
      auth.touchToken(token.id, auth.clientIp(req)).catch(() => {});
    } else if (db.settings.getBool('require_auth')) {
      return challenge('that token is not valid on this registry', 'bad token');
    }
  } else if (db.settings.getBool('require_auth')) {
    return challenge('this registry needs a token. Put it in the index address, as https://__token__:<token>@<host>/pypi/simple/', 'no token');
  }

  if (db.settings.getBool('npm_clients_only') && !looksLikePythonClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return text(res, 404, 'not found');
  }
  return next();
});

function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  // twine uploads to the root, the upload handler decides whether it is allowed
  if (req.method === 'POST' && req.path === '/') return next();
  if (req.method === 'OPTIONS') {
    res.set('allow', 'GET, HEAD, POST, OPTIONS');
    return res.status(204).end();
  }
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD, POST, OPTIONS');
  return text(res, 405, 'an uploaded file is never changed or removed here, and uploads go to the index root');
}

module.exports = { ours, identify, readOnly };
