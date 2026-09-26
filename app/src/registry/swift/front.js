// The Swift registry front door: switched on, who is asking, and reads only.
// Author: Tim Rice
// swift package-registry login stores the token for the registry (in ~/.netrc on Linux), and SwiftPM sends it every time

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, problem, looksLikeSwiftClient } = require('./respond');

// SwiftPM 6 checks a login by POSTing to the url it was given, so a POST to /swift/ itself is a login too
const isLogin = (req) => req.path === '/login' || (req.method === 'POST' && req.path === '/');

// only the registry's own paths. /swift itself is the npm package called swift, and so is all of it with Swift off
function ours(req, res, next) {
  if (!(OURS.test(req.path) || isLogin(req)) || !db.settings.getBool('swift_enabled')) return next('router');
  return next();
}

const identify = wrap(async (req, res, next) => {
  req.startedAt = Date.now();
  const challenge = (message, reason) => {
    record(req, { action: 'deny', status: 401, reason });
    // no WWW-Authenticate: SwiftPM sends its login up front, and on Linux a Basic challenge it has nothing for hangs it
    return problem(res, 401, message);
  };
  const raw = auth.registryCredential(req);
  if (raw) {
    const token = req.npmIdentity || (await auth.lookupToken(raw));
    if (token) {
      req.npmIdentity = token;
      auth.touchToken(token.id, auth.clientIp(req)).catch(() => {});
    } else if (db.settings.getBool('require_auth') || isLogin(req)) {
      return challenge('that token is not valid on this registry', 'bad token');
    }
  } else if (db.settings.getBool('require_auth') || isLogin(req)) {
    return challenge('this registry needs a token: swift package-registry login with your user name and the token as the password', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeSwiftClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return problem(res, 404, 'not found');
  }
  return next();
});

// POST /login (or /) is how SwiftPM checks a login. publishing is not taken
function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || (req.method === 'POST' && isLogin(req))) return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD');
  return problem(res, 405, 'this registry mirrors packages, it does not take swift package-registry publish');
}

module.exports = { ours, identify, readOnly };
