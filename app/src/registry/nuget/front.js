// The NuGet front door: switched on, who is asking, and reads only for now.
// Author: Tim Rice
// dotnet sends the token as the password of its packageSourceCredentials. the 401 challenge is what makes it send it.
// a push carries it as X-NuGet-ApiKey too, which is only read on the push path

const db = require('../../db');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { OURS, PUSH, record, json, warn, looksLikeNugetClient } = require('./respond');

// only /nuget/v3... is ours. /nuget itself is the npm package called nuget, and so is everything with NuGet off
function ours(req, res, next) {
  if (!OURS.test(req.path) || !db.settings.getBool('nuget_enabled')) return next('router');
  return next();
}

const identify = wrap(async (req, res, next) => {
  req.startedAt = Date.now();
  const challenge = (message, reason) => {
    record(req, { action: 'deny', status: 401, reason });
    res.set('www-authenticate', 'Basic realm="ForgeRepo", charset="UTF-8"');
    warn(res, message);
    return json(res, 401, { error: message });
  };
  const raw = auth.registryCredential(req) || (PUSH.test(req.path) ? String(req.get('x-nuget-apikey') || '').trim() || null : null);
  if (raw) {
    const token = req.npmIdentity || (await auth.lookupToken(raw));
    if (token) {
      req.npmIdentity = token;
      auth.touchToken(token.id, auth.clientIp(req)).catch(() => {});
    } else if (db.settings.getBool('require_auth')) {
      return challenge('that token is not valid on this registry', 'bad token');
    }
  } else if (db.settings.getBool('require_auth') && !(req.method === 'GET' && req.path === '/v3/index.json')) {
    // the service index only says where this feed's own endpoints are, and dotnet nuget push reads it before it sends
    // the API key. every list and every package behind it still needs a token
    return challenge('this feed needs a token: add packageSourceCredentials to nuget.config with your user name and the token as the password', 'no token');
  }
  if (db.settings.getBool('npm_clients_only') && !looksLikeNugetClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not a package manager' });
    return json(res, 404, { error: 'not found' });
  }
  return next();
});

// reads, and on the push path a push or a delete (which is refused there, with the reason)
function readOnly(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  if (PUSH.test(req.path) && (req.method === 'PUT' || req.method === 'DELETE')) return next();
  record(req, { action: 'deny', status: 405, reason: 'write attempt' });
  res.set('allow', 'GET, HEAD');
  return json(res, 405, { error: 'this feed takes pushes at /nuget/api/v2/package, nothing else is written' });
}

module.exports = { ours, identify, readOnly };
