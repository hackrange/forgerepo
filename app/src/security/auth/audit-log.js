// Writing the audit trail. a failed write is logged, never thrown at whoever did the thing.
// Author: Tim Rice
// a row can say what the thing looked like before and after, and whether it worked. secrets never go in, whatever a caller passes

const trail = require('../../db/repositories/audit');
const log = require('../../logger');
const { clientIp } = require('./client-ip');

const RESULTS = ['success', 'failure', 'denied'];
const MASK = '********';
const MAX_STATE = 4000;

// by key name: a password, secret, token, key or hash is never written, only whether there was one
const SECRET_KEY = /^(password|secret|token|api_key)$|(_password|_secret|_token|_key|_hash)$/i;

// refusals that are the system saying no, as opposed to something going wrong
const DENIED = new Set(['login.blocked', 'login.locked', 'login.throttled', 'breakglass.throttled', 'access.denied']);

function resultOf(action, detail, given) {
  if (RESULTS.includes(given)) return given;
  if (DENIED.has(action)) return 'denied';
  if (/\.failed$/.test(action) || /^failed\b/i.test(String(detail || ''))) return 'failure';
  return 'success';
}

function redact(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return depth > 3 ? '[...]' : value.map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    if (value instanceof Date) return value.toISOString();
    if (depth > 3) return '{...}';
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY.test(k) ? (v === null || v === undefined || v === '' ? v : MASK) : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

// json, cut to fit. a cut one says so rather than pretending to be whole
function stateText(state) {
  if (state === null || state === undefined) return null;
  const text = JSON.stringify(redact(state));
  if (text === undefined) return null;
  return text.length > MAX_STATE ? `${text.slice(0, MAX_STATE - 16)} ...(cut short)` : text;
}

// extra: { before, after, result }. all optional
async function audit(userId, username, ip, action, target, detail, extra) {
  const e = extra || {};
  try {
    await trail.insert({
      userId: userId || null,
      username: username ? String(username).slice(0, 64) : null,
      ip: ip ? String(ip).slice(0, 45) : null,
      action: String(action).slice(0, 64),
      target: target ? String(target).slice(0, 255) : null,
      detail: detail ? String(detail).slice(0, 4000) : null,
      before: stateText(e.before),
      after: stateText(e.after),
      result: resultOf(String(action), detail, e.result)
    });
  } catch (err) {
    log.error('could not write the audit log', err.message);
  }
}

function auditReq(req, action, target, detail, extra) {
  const u = req.user || {};
  // acting as someone: the record names both of them
  const who = u.impersonator ? `${u.impersonator.username} as ${u.username}` : u.username;
  return audit(u.id || null, who || null, clientIp(req), action, target, detail, extra);
}

// the fields of a row a change touched, for the before side
function pick(row, keys) {
  const out = {};
  for (const k of keys) out[k] = row ? row[k] : undefined;
  return out;
}

module.exports = { RESULTS, MASK, audit, auditReq, redact, stateText, resultOf, pick };
