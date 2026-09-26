// An admin acting as someone else for a while, then getting their own session back.
// Author: Tim Rice

const sessions = require('../../db/repositories/sessions');
const { COOKIE, COOKIE_PREV, sessionKey, randomId, parseCookies, cookieOptions, prevCookieOptions } = require('./cookies');
const { clientIp } = require('./client-ip');
const { userAgentOf, loadSessionRaw } = require('./sessions');

const IMPERSONATE_MINUTES = 30;

// a fresh session as the target. the admin's own is left alone and handed back on stop
async function startImpersonation(req, res, target) {
  const current = parseCookies(req.headers.cookie)[COOKIE];
  if (!current || !req.session || req.user.impersonator) throw new Error('there is no session of your own to come back to');
  const id = randomId(32);
  const csrf = randomId(32);
  await sessions.createImpersonation({
    key: sessionKey(id), userId: target.id, csrf, ip: clientIp(req), userAgent: userAgentOf(req),
    minutes: IMPERSONATE_MINUTES, impersonatorId: req.user.id
  });
  res.cookie(COOKIE_PREV, current, prevCookieOptions());
  res.cookie(COOKIE, id, cookieOptions());
  return { csrf, minutes: IMPERSONATE_MINUTES };
}

// back to the admin's own session if it is still a good admin one. null when there is none to go back to.
// the impersonation cookie alone never gets anyone an admin session
async function returnFromImpersonation(req, res, impersonatorId) {
  const prev = parseCookies(req.headers.cookie)[COOKIE_PREV];
  if (!prev) return null;
  res.clearCookie(COOKIE_PREV, { path: '/_api' });
  const sess = await loadSessionRaw(prev);
  if (!sess || sess.user.impersonator || sess.user.role !== 'admin' || (impersonatorId && sess.user.id !== impersonatorId)) {
    res.clearCookie(COOKIE, { path: '/' });
    return null;
  }
  res.cookie(COOKIE, prev, cookieOptions());
  return sess;
}

async function stopImpersonation(req, res) {
  await sessions.removeImpersonation(req.session.sessionId);
  const back = await returnFromImpersonation(req, res, req.user.impersonator.id);
  if (!back) res.clearCookie(COOKIE, { path: '/' });
  return back;
}

module.exports = { IMPERSONATE_MINUTES, startImpersonation, returnFromImpersonation, stopImpersonation };
