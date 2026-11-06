// How long an API rule lasts. days (7, "7", "7d") or a date (2026-12-01, good until the end of that day UTC), or a full
// ISO time. an allow always runs out: one day when nothing is said, a year at most. a deny lasts until removed unless told
// Author: Tim Rice

const { fail } = require('../../lib/errors');

const DAY = 86400;
const MAX_ALLOW_DAYS = 365;
const MAX_DENY_DAYS = 5 * 366;

function parse(value, kind, now = Math.floor(Date.now() / 1000)) {
  const most = kind === 'allow' ? MAX_ALLOW_DAYS : MAX_DENY_DAYS;
  if (value === undefined || value === null || String(value).trim() === '') return kind === 'allow' ? now + DAY : null;
  const text = String(value).trim().toLowerCase();
  if (text === 'never') {
    if (kind === 'allow') fail(400, 'an allow made through the API always expires, give it days or a date');
    return null;
  }
  let at;
  const days = text.match(/^(\d{1,4})\s*d?(?:ays?)?$/);
  if (days) {
    const n = Number(days[1]);
    if (n < 1) fail(400, 'expires needs at least 1 day');
    at = now + n * DAY;
  } else if (/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    const ms = Date.parse(`${text}T23:59:59Z`);
    // Date.parse quietly rolls 2026-02-31 into March, so make sure it read back the same
    if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 10) !== text) fail(400, `${text} is not a real date`);
    at = Math.floor(ms / 1000);
  } else if (/^\d{4}-\d{2}-\d{2}t/.test(text)) {
    const ms = Date.parse(String(value).trim());
    if (!Number.isFinite(ms)) fail(400, 'expires is not a time this understands');
    at = Math.floor(ms / 1000);
  } else {
    fail(400, 'expires is a number of days (7 or "7d") or a date (yyyy-mm-dd)');
  }
  if (at <= now) fail(400, 'that expiry is already in the past');
  if (at > now + most * DAY) fail(400, `an ${kind} from the API can run ${most} days at most`);
  return at;
}

module.exports = { parse, MAX_ALLOW_DAYS, MAX_DENY_DAYS };
