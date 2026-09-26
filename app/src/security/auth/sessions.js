// Portal sessions: making one, loading it on every request, and ending it.
// Author: Tim Rice
// a session dies when it expires, sits idle too long, its user is disabled, or its impersonation is over

const db = require('../../db');
const config = require('../../config');
const sessions = require('../../db/repositories/sessions');
const { COOKIE, COOKIE_PREV, sessionKey, randomId, parseCookies, cookieOptions } = require('./cookies');
const { clientIp } = require('./client-ip');

const userAgentOf = (req) => String(req.headers['user-agent'] || '').slice(0, 255);

async function createSession(res, user, req) {
  const id = randomId(32);
  const csrf = randomId(32);
  await sessions.create({ key: sessionKey(id), userId: user.id, csrf, ip: clientIp(req), userAgent: userAgentOf(req), hours: config.sessionHours });
  res.cookie(COOKIE, id, cookieOptions());
  return { id: sessionKey(id), csrf };
}

async function destroySession(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies[COOKIE];
  if (sid) await sessions.remove(sessionKey(sid));
  // signing out while acting as someone signs the admin out as well
  const prev = cookies[COOKIE_PREV];
  if (prev && /^[a-f0-9]{64}$/.test(prev) && req.user && req.user.impersonator) {
    await sessions.removeOwnedBy(sessionKey(prev), req.user.impersonator.id);
  }
  res.clearCookie(COOKIE, { path: '/' });
  if (prev) res.clearCookie(COOKIE_PREV, { path: '/_api' });
}

// keepSessionId is the stored key, not the cookie
function dropUserSessions(userId, keepSessionId) {
  return sessions.removeForUser(userId, keepSessionId || null);
}

async function loadSession(req) {
  return loadSessionRaw(parseCookies(req.headers.cookie)[COOKIE]);
}

async function loadSessionRaw(sid) {
  if (!sid || !/^[a-f0-9]{64}$/.test(sid)) return null;
  const key = sessionKey(sid);

  const row = await sessions.load(key);
  if (!row) return null;

  if (row.disabled) {
    await sessions.remove(key);
    return null;
  }

  // acting as someone is over when time is up, the admin stops being one, or the target becomes one
  if (row.impersonator_id) {
    const over = row.imp_left === null || Number(row.imp_left) <= 0 || !row.imp_username
      || row.imp_disabled || row.imp_role !== 'admin' || row.role === 'admin';
    if (over) {
      await sessions.remove(key);
      return null;
    }
  }

  const idleMin = db.settings.getInt('session_idle_minutes', 60);
  const lastSeen = new Date(row.last_seen_at).getTime();
  if (idleMin > 0 && Date.now() - lastSeen > idleMin * 60000) {
    await sessions.remove(key);
    return null;
  }

  // once a minute is plenty
  if (Date.now() - lastSeen > 60000) {
    await sessions.touch(key);
  }

  const impersonator = row.impersonator_id ? { id: row.impersonator_id, username: row.imp_username } : null;
  return {
    sessionId: row.id,
    csrf: row.csrf,
    impersonation: impersonator ? { endsAt: new Date(Date.now() + Number(row.imp_left) * 1000).toISOString() } : null,
    user: {
      id: row.user_id,
      username: row.username,
      role: row.role,
      fullName: row.full_name,
      email: row.email,
      // their password prompt is theirs to answer, not the admin's
      mustChangePassword: impersonator ? false : !!row.must_change_password,
      impersonator
    }
  };
}

function sweepSessions() {
  return sessions.sweep();
}

module.exports = { userAgentOf, createSession, destroySession, dropUserSessions, loadSession, loadSessionRaw, sweepSessions };
