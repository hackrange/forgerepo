// The CocoaPods front door: switched on, who is asking, and reads only.
// Author: Tim Rice
// pod reads its login for the CDN and for downloads from ~/.netrc, and sends it once the 401 challenge asks

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, text, looksLikePodClient } = require('./respond');

// only the CDN's own paths. /cocoapods itself is the npm package called cocoapods, and so is all of it with CocoaPods off
function ours(req, res, next) {
  if (!OURS.test(req.path) || !db.settings.getBool('cocoapods_enabled')) return next('router');
  return next();
}

const identify = wrap(async (req, res, next) => {
  req.startedAt = Date.now();
  const challenge = (message, reason) => {
    record(req, { action: 'deny', status: 401, reason });
    res.set('www-authenticate', 'Basic realm="ForgeRepo", charset="UTF-8"');
    return text(res, 401, message, message);
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
    return challenge('this CDN needs a token: put a machine line for this host in ~/.netrc with your user name and the token as the password', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikePodClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return text(res, 404, 'not found');
  }
  return next();
});

function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD');
  return text(res, 405, 'this CDN mirrors pods, it does not take pod trunk push', 'pod trunk push is not taken here');
}

module.exports = { ours, identify, readOnly };
