// Username and password logins, with lockout and no way to tell which usernames exist.
// Author: Tim Rice

const db = require('../../db');
const users = require('../../db/repositories/users');
const { verifyPassword, burnTime } = require('./passwords');
const { rateLimit, refundRateLimit } = require('./rate-limit');
const { audit } = require('./audit-log');
const { clientIp } = require('./client-ip');

const UNAVAILABLE = { ok: false, error: 'sign in is unavailable for a moment, try again shortly', status: 503 };

async function login(username, password, req) {
  const ip = clientIp(req);
  const name = String(username || '').slice(0, 64);
  const maxAttempts = db.settings.getInt('max_login_attempts', 5);
  const lockMinutes = db.settings.getInt('lockout_minutes', 15);

  //ip first, so nobody grinds through a list of usernames. and if it can't count, nobody gets checked
  const ipGate = await rateLimit(`login:ip:${ip}`, maxAttempts * 4, 15 * 60000, { failClosed: true });
  if (ipGate.unavailable) {
    await audit(null, name || null, ip, 'login.throttled', name || null, 'the attempt counter could not be written, no password was checked');
    return UNAVAILABLE;
  }
  if (!ipGate.ok) {
    await audit(null, name || null, ip, 'login.throttled', name || null, 'too many attempts from this address');
    return { ok: false, error: 'too many attempts from this address, wait a bit', status: 429 };
  }

  const user = await users.forLogin(name);

  // same message, same work. no user enumeration for you
  const generic = { ok: false, error: 'wrong username or password', status: 401 };
  const locked = { ok: false, error: 'account is locked, try again later', status: 429 };

  // a name nobody can sign in as (none, or disabled) locks after as many tries as a real one, with the same words and
  // as quickly. otherwise "locked" after five guesses is a very polite way of saying the account exists
  if (!user || user.disabled) {
    const nameGate = await rateLimit(`login:name:${name.toLowerCase()}`, maxAttempts, lockMinutes * 60000, { failClosed: true });
    if (nameGate.unavailable) return UNAVAILABLE;
    const why = user ? 'account is disabled' : 'no such user';
    if (!nameGate.ok) {
      await audit(user ? user.id : null, name, ip, user ? 'login.blocked' : 'login.failed', name, `${why}, and out of tries`);
      return locked;
    }
    await burnTime(password);
    await audit(user ? user.id : null, name, ip, user ? 'login.blocked' : 'login.failed', name, why);
    return generic;
  }

  if (!(await users.reserveAttempt(user.id, maxAttempts))) {
    // out of attempts with no lock set means a sign in died between the two. lock it properly, it'll come back
    if (!user.locked_until && user.failed_logins >= maxAttempts) await users.lockIfSpent(user.id, maxAttempts, lockMinutes);
    await audit(user.id, user.username, ip, 'login.blocked', user.username, 'account is locked');
    return locked;
  }

  const good = await verifyPassword(String(password || ''), user.password_hash);
  if (!good) {
    if (await users.lockIfSpent(user.id, maxAttempts, lockMinutes)) {
      await audit(user.id, user.username, ip, 'login.locked', user.username, `${maxAttempts} bad passwords in a row`);
    } else {
      await audit(user.id, user.username, ip, 'login.failed', user.username, 'bad password');
    }
    return generic;
  }

  await users.recordLogin(user.id);
  // only this attempt comes off the address, the misses before it stay until the window runs out.
  // wiping it here let anyone with one account guess, sign in as themselves, and guess again
  await refundRateLimit(`login:ip:${ip}`);
  await audit(user.id, user.username, ip, 'login.ok', user.username, null);

  return { ok: true, user };
}

module.exports = { login };
