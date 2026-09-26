// The Composer front door: switched on, who is asking, and reads only.
// Author: Tim Rice
// composer sends the http-basic login from auth.json for this host, the user name and the token as the password

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, text, looksLikeComposerClient } = require('./respond');

// only the repository's own paths. /composer itself is the npm package called composer, and so is all of it with Composer off
function ours(req, res, next) {
  if (!OURS.test(req.path) || !db.settings.getBool('composer_enabled')) return next('router');
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
    return challenge('this repository needs a token: composer config http-basic.<this host> <your user name> <your token>', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeComposerClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return text(res, 404, 'not found');
  }
  return next();
});

function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD');
  return text(res, 405, 'this repository mirrors packages, it does not take uploads', 'uploads are not taken here');
}

module.exports = { ours, identify, readOnly };
