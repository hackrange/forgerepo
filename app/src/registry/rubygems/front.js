// The RubyGems front door: switched on, who is asking, and reads only.
// Author: Tim Rice
// gem and bundler send the token as the password in the source address (https://user:token@host/rubygems/)

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, record, text, looksLikeGemClient } = require('./respond');

// only the gem source's own paths. /rubygems itself is the npm package called rubygems, and so is all of it with
// RubyGems off
function ours(req, res, next) {
  if (!OURS.test(req.path) || !db.settings.getBool('rubygems_enabled')) return next('router');
  return next();
}

const identify = wrap(async (req, res, next) => {
  req.startedAt = Date.now();
  const challenge = (message, reason) => {
    record(req, { action: 'deny', status: 401, reason });
    res.set('www-authenticate', 'Basic realm="ForgeRepo", charset="UTF-8"');
    return text(res, 401, message, message);
  };
  // gem push sends the token in Authorization as it is, with no scheme in front of it
  const bare = String(req.get('authorization') || '').trim();
  const raw = auth.registryCredential(req) || (/^nrt_[A-Za-z0-9_-]+$/.test(bare) ? bare : '');
  if (raw) {
    const token = req.npmIdentity || (await auth.lookupToken(raw));
    if (token) {
      req.npmIdentity = token;
      auth.touchToken(token.id, auth.clientIp(req)).catch(() => {});
    } else if (db.settings.getBool('require_auth')) {
      return challenge('that token is not valid on this registry', 'bad token');
    }
  } else if (db.settings.getBool('require_auth')) {
    return challenge('this gem source needs a token: put your user name and the token in its address, like https://you:<token>@host/rubygems/', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeGemClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return text(res, 404, 'not found');
  }
  return next();
});

// gem push and gem yank, the only writes this source takes. the router is mounted at /rubygems, so paths here
// have no prefix on them
const WRITES = /^\/api\/v1\/gems(\/yank)?$/;

function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  if (WRITES.test(req.path)) return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD');
  return text(res, 405, 'this gem source mirrors gems, it does not take gem push yet', 'gem push is not taken here yet');
}

module.exports = { ours, identify, readOnly };
