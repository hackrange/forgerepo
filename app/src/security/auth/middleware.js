// Express middleware for the portal: attach the session, then insist on login, a current password, a permission and csrf.
// Author: Tim Rice
// ownership checks live in the query that loads the row, and a row you can't see is a 404 not a 403

const crypto = require('crypto');
const log = require('../../logger');
const { can } = require('./permissions');
const { loadSession } = require('./sessions');
const { auditReq } = require('./audit-log');

// the same person hitting the same wall is one row every few minutes, not one a click
const deniedSeen = new Map();
const DENIED_EVERY_MS = 5 * 60000;

function noteDenied(req, perm) {
  try {
    const where = `${req.method} ${log.safeUrl(req.originalUrl)}`.slice(0, 255);
    const key = `${req.user.id}|${perm}|${where}`;
    const now = Date.now();
    if (deniedSeen.get(key) > now - DENIED_EVERY_MS) return;
    if (deniedSeen.size > 5000) deniedSeen.clear();
    deniedSeen.set(key, now);
    Promise.resolve(auditReq(req, 'access.denied', where, `needs ${perm}, ${req.user.role} does not have it`)).catch(() => {});
  } catch (err) {
    // a refusal still refuses whether or not it got written down
  }
}

// never rejects, that's someone else's job
async function attachSession(req, res, next) {
  try {
    const sess = await loadSession(req);
    if (sess) {
      req.session = sess;
      req.user = sess.user;
    }
    next();
  } catch (err) {
    next(err);
  }
}

function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'you need to log in' });
  next();
}

function requirePasswordCurrent(req, res, next) {
  if (req.user && req.user.mustChangePassword) {
    const allowed = req.path === '/me/password' || req.path === '/me' || req.path === '/logout';
    if (!allowed) {
      return res.status(403).json({ error: 'change your password before you do anything else', mustChangePassword: true });
    }
  }
  next();
}

function requirePerm(perm) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'you need to log in' });
    if (!can(req.user, perm)) {
      log.warn(`denied ${req.user.username} (${req.user.role}) on ${perm} at ${req.method} ${log.safeUrl(req.originalUrl)}`);
      noteDenied(req, perm);
      return res.status(403).json({ error: 'your role does not allow that' });
    }
    next();
  };
}

// CSRF: token echoed back in a header, which a cross site form can't set
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = req.get('x-csrf-token');
  const want = req.session && req.session.csrf;
  if (!sent || !want || sent.length !== want.length) {
    return res.status(403).json({ error: 'csrf check failed, reload the page' });
  }
  if (!crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(want))) {
    return res.status(403).json({ error: 'csrf check failed, reload the page' });
  }
  next();
}

module.exports = { attachSession, requireLogin, requirePasswordCurrent, requirePerm, requireCsrf };
