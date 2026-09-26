// The RPM front door: switched on, who is asking, and reads only.
// Author: Tim Rice
// dnf sends the username and password of the .repo file once the 401 challenge asks for them

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, text, looksLikeRpmClient } = require('./respond');

// only a mirror's own paths. /rpm itself is the npm package called rpm, and so is all of it with RPM off
// a client may write + ~ and ^ of a file name as %2b %7e and %5e. only those are read back, only on a mirror's own paths
const plain = (p) => p.replace(/%2b/gi, '+').replace(/%7e/gi, '~').replace(/%5e/gi, '^');

function ours(req, res, next) {
  if (!OURS.test(plain(req.path)) || !db.settings.getBool('rpm_enabled')) return next('router');
  req.url = plain(req.url);
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
    return challenge('this mirror needs a token: put username= and password= (the token) in the .repo file', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeRpmClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return text(res, 404, 'not found');
  }
  return next();
});

function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD');
  return text(res, 405, 'this mirror hands out packages, it does not take uploads', 'uploads are not taken here');
}

module.exports = { ours, identify, readOnly };
