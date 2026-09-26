// The Maven front door: switched on, who is asking, and reads only.
// Author: Tim Rice
// mvn and gradle send the token as the password of their server credentials, once the 401 challenge asks for it

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, text, looksLikeMavenClient } = require('./respond');

// only group/artifact/file paths are Maven's. /maven itself is the npm package called maven, and so is all of it
// with Maven off
function ours(req, res, next) {
  if (!OURS.test(req.path) || !db.settings.getBool('maven_enabled')) return next('router');
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
    return challenge('this repository needs a token: put your user name and the token as the password in a <server> of settings.xml', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeMavenClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return text(res, 404, 'not found');
  }
  return next();
});

// mvn deploy sends every file of a release as its own PUT
function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'PUT') return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD, PUT');
  return text(res, 405, 'a deployed file is never changed or deleted here. Deploy a new version', 'that is not something this repository takes');
}

module.exports = { ours, identify, readOnly };
