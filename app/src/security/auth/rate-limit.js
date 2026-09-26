// Throttling logins, tests and anything else that shouldn't be hammered.
// Author: Tim Rice

const counters = require('../../db/repositories/rate-limits');
const log = require('../../logger');

const keyOf = (key) => String(key).slice(0, 190);

// options.failClosed: for the gates in front of a password or a break glass key. a throttle that quietly stops
// counting is how a guessing run goes unnoticed, so those refuse instead (after one retry, deadlocks happen)
async function rateLimit(key, limit, windowMs, options = {}) {
  const seconds = Math.max(1, Math.ceil(windowMs / 1000));
  const count = async () => {
    await counters.hit(keyOf(key), seconds);
    return counters.read(keyOf(key));
  };
  let row;
  try {
    row = await count();
  } catch (err) {
    if (!options.failClosed) {
      // fail open, everything behind these gates needs the db anyway
      log.error('rate limit check failed, letting this one through', err.message);
      return { ok: true, remaining: limit, retryAfter: 0 };
    }
    try {
      row = await count();
    } catch (again) {
      log.error('rate limit check failed, refusing this one', again.message);
      return { ok: false, remaining: 0, retryAfter: 30, unavailable: true };
    }
  }
  if (!row) return { ok: true, remaining: limit - 1, retryAfter: 0 };

  const retryAfter = Math.max(0, Number(row.reset_epoch) - Math.floor(Date.now() / 1000));
  if (row.hits > limit) return { ok: false, remaining: 0, retryAfter };
  return { ok: true, remaining: Math.max(0, limit - row.hits), retryAfter: 0 };
}

async function clearRateLimit(key) {
  try {
    await counters.clear(keyOf(key));
  } catch (err) {
    log.error('could not clear a rate limit counter', err.message);
  }
}

// gives one hit back. for a counter that should only remember what went wrong
async function refundRateLimit(key) {
  try {
    await counters.refund(keyOf(key));
  } catch (err) {
    log.error('could not refund a rate limit counter', err.message);
  }
}

function sweepRateLimits() {
  return counters.sweep();
}

module.exports = { rateLimit, clearRateLimit, refundRateLimit, sweepRateLimits };
