// The session cookies: names, options, reading them, and the hash a session is stored under.
// Author: Tim Rice

const crypto = require('crypto');
const config = require('../../config');

const COOKIE = 'nr_sid';
// an admin's own session waits here while they act as someone else. only ever read by /_api
const COOKIE_PREV = 'nr_sid_prev';

// stored under a hash of the id. the cookie holds the only real copy, so a leaked
// table or backup doesn't hand out sessions
function sessionKey(sid) {
  return crypto.createHash('sha256').update(String(sid)).digest('hex');
}

function randomId(bytes) {
  return crypto.randomBytes(bytes || 32).toString('hex');
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    // a broken % escape threw here on every request that carried it. kept raw, it just never matches anything
    try {
      out[k] = decodeURIComponent(v);
    } catch (err) {
      out[k] = v;
    }
  }
  return out;
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.secureCookies,
    path: '/',
    maxAge: config.sessionHours * 3600 * 1000
  };
}

const prevCookieOptions = () => ({ ...cookieOptions(), path: '/_api' });

module.exports = { COOKIE, COOKIE_PREV, sessionKey, randomId, parseCookies, cookieOptions, prevCookieOptions };
