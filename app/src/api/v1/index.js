// The REST API at /_api/v1, for another product filing temporary exceptions. API keys only, no sessions, no cookies.
// Author: Tim Rice
//
// the portal allow list doesn't apply here (see portal.isRestApi), every key carries its own instead.
// a key sees and changes the rules it made and nothing else, a rule that isn't yours is a 404 same as a missing one

const express = require('express');
const auth = require('../../security/auth');
const apiKeys = require('../../services/api-keys');
const policy = require('../../policy');
const rulesRepo = require('../../db/repositories/rules');
const transfer = require('../../db/repositories/transfer');
const ecosystems = require('../../ecosystems');
const db = require('../../db');
const log = require('../../logger');
const { ruleEcosystem, checkPattern, checkRange } = require('../../policy/rulecheck');
const { audit } = require('../../lib/actor');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { str, intIn, boolFlag } = require('../../lib/validate');
const expiry = require('./expiry');

const router = express.Router();
const PER_MINUTE = 300;

const KINDS = { allow: 'allow', whitelist: 'allow', deny: 'deny', blacklist: 'deny' };

// ---------------------------------------------------------------- the door

router.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const type = String(req.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') return res.status(415).json({ error: 'send application/json' });
  }
  return next();
});
router.use(express.json({ limit: '32kb', type: ['application/json'] }));

router.use(wrap(async (req, res, next) => {
  const ip = auth.clientIp(req);
  // somebody guessing keys gets slowed down, and a throttle that can't count says no
  const header = String(req.get('authorization') || '');
  const raw = /^bearer\s+/i.test(header) ? header.slice(7).trim() : '';
  if (!raw) {
    res.set('www-authenticate', 'Bearer realm="forgerepo-api"');
    return res.status(401).json({ error: 'send an API key as Authorization: Bearer frk_...' });
  }
  const got = await apiKeys.authenticate(raw, ip);
  if (!got.ok) {
    const tries = await auth.rateLimit(`apikey:bad:${ip}`, 20, 15 * 60000, { failClosed: true });
    if (!tries.ok) {
      res.set('retry-after', String(tries.retryAfter || 60));
      return res.status(429).json({ error: 'too many bad keys from this address, wait a bit' });
    }
    if (got.status === 403) {
      log.warn(`api key ${got.name} used from ${ip}, which is not on its list`);
      await auth.audit(null, `api:${got.name}`, ip, 'apikey.refused', got.name, `not allowed from ${ip}`);
      return res.status(403).json({ error: `this key is not allowed from ${ip}` });
    }
    res.set('www-authenticate', 'Bearer realm="forgerepo-api", error="invalid_token"');
    return res.status(401).json({ error: 'that API key is not valid, or it was revoked or expired' });
  }
  const limit = await auth.rateLimit(`apikey:${got.key.id}`, PER_MINUTE, 60000);
  res.set('ratelimit-limit', String(PER_MINUTE));
  res.set('ratelimit-remaining', String(limit.remaining));
  if (!limit.ok) {
    res.set('retry-after', String(limit.retryAfter || 60));
    return res.status(429).json({ error: `slow down, ${PER_MINUTE} requests a minute per key` });
  }
  req.apiKey = got.key;
  req.apiActor = { id: null, name: `api:${got.key.name}`.slice(0, 64), username: `api:${got.key.name}`, ip, user: null };
  return next();
}));

function scope(name) {
  return (req, res, next) => {
    if (!req.apiKey.scopes.includes(name)) return res.status(403).json({ error: `this key does not have the ${name} scope` });
    return next();
  };
}

// ---------------------------------------------------------------- shapes

function iso(ts) {
  return ts === null || ts === undefined ? null : new Date(Number(ts) * 1000).toISOString();
}

function shape(r) {
  return {
    id: Number(r.id),
    ecosystem: r.ecosystem,
    pattern: r.pattern,
    kind: r.kind,
    list: r.kind === 'allow' ? 'whitelist' : 'blacklist',
    version_range: r.version_range || '',
    application: r.application_id ? (r.application_name || null) : null,
    environment: r.environment_id ? (r.environment_name || null) : null,
    note: r.note || null,
    priority: Number(r.priority),
    enabled: !!Number(r.enabled),
    expires_at: iso(r.expires_ts),
    expired: !!Number(r.expired),
    created_at: r.created_at,
    updated_at: r.updated_at
  };
}

const ruleId = (raw) => {
  const text = String(raw || '');
  if (!/^[1-9]\d{0,9}$/.test(text)) fail(404, 'no such rule');
  return Number(text);
};

async function owned(req) {
  const row = await rulesRepo.ownedBy(req.apiKey.id, ruleId(req.params.id));
  if (!row) fail(404, 'no such rule');
  return row;
}

// names, not ids. ids mean nothing to the product on the other end
async function scopeIds(body) {
  const find = async (value, key, label) => {
    const text = str(value, 128, label);
    if (!text) return 0;
    const id = (await transfer.labelIds(key)).get(text.toLowerCase());
    if (!id) fail(400, `there is no ${label} called ${text.slice(0, 60)}`);
    return id;
  };
  return { app: await find(body.application, 'applications', 'application'), env: await find(body.environment, 'environments', 'environment') };
}

function priorityFor(req, value, fallback) {
  const p = intIn(value, -1000, 1000, fallback);
  if (p > req.apiKey.maxPriority) fail(400, `this key can file rules up to priority ${req.apiKey.maxPriority}`);
  return p;
}

// ---------------------------------------------------------------- routes

router.get('/me', (req, res) => {
  res.json({ id: req.apiKey.id, name: req.apiKey.name, prefix: req.apiKey.prefix, scopes: req.apiKey.scopes, max_priority: req.apiKey.maxPriority });
});

router.get('/ecosystems', (req, res) => {
  const on = ecosystems.enabled((k) => db.settings.getBool(k));
  res.json({ ecosystems: on.map((e) => ({ id: e.id, name: e.name })) });
});

router.get('/rules', scope('rules:read'), wrap(async (req, res) => {
  const q = req.query;
  const limit = intIn(q.limit, 1, 500, 50);
  const page = intIn(q.page, 1, 100000, 1);
  const kind = q.kind ? KINDS[String(q.kind).toLowerCase()] : null;
  if (q.kind && !kind) fail(400, 'kind is allow, deny, whitelist or blacklist');
  const state = q.state ? String(q.state).toLowerCase() : null;
  if (state && !['active', 'expired'].includes(state)) fail(400, 'state is active or expired');
  const ecosystem = q.ecosystem ? ruleEcosystem(q.ecosystem) : null;
  const pattern = q.pattern ? checkPattern(q.pattern, ecosystem || 'npm') : null;
  const { rows, total } = await rulesRepo.pageOwnedBy(req.apiKey.id, { ecosystem, kind, pattern, state }, { limit, offset: (page - 1) * limit });
  res.json({ rules: rows.map(shape), total, page, limit });
}));

router.get('/rules/:id', scope('rules:read'), wrap(async (req, res) => {
  res.json(shape(await owned(req)));
}));

// a new rule is 201. the same rule this key already filed gets the new expiry and note and is 200.
// the same rule filed by a person is 409, an API key never rewrites what a person decided
router.post('/rules', scope('rules:write'), wrap(async (req, res) => {
  const b = req.body || {};
  const kind = KINDS[String(b.kind || '').toLowerCase()];
  if (!kind) fail(400, 'kind is allow (or whitelist) or deny (or blacklist)');
  const ecosystem = ruleEcosystem(b.ecosystem, { mustBeOn: true });
  const pattern = checkPattern(b.pattern, ecosystem);
  const versionRange = checkRange(b.version_range, ecosystem);
  const note = str(b.note, 512, 'note');
  const priority = priorityFor(req, b.priority, Math.min(0, req.apiKey.maxPriority));
  const expiresTs = expiry.parse(b.expires, kind);
  const sc = await scopeIds(b);
  const key = { ecosystem, pattern, kind, version_range: versionRange, application_id: sc.app, environment_id: sc.env };

  const target = `${ecosystem}:${kind}:${pattern}`;
  const there = await rulesRepo.ownerOfKey(key);
  let id;
  let status = 201;
  if (there) {
    if (Number(there.api_key_id) !== req.apiKey.id) {
      fail(409, `a ${kind} rule for ${pattern} with that version range and scope already exists and was not made by this key`);
    }
    id = Number(there.id);
    // filing it again is "keep it going": what wasn't sent stays as it was
    const had = await rulesRepo.ownedBy(req.apiKey.id, id);
    await rulesRepo.updateForKey(req.apiKey.id, id, {
      note: b.note !== undefined ? note : had.note,
      priority: b.priority !== undefined ? priority : Number(had.priority),
      enabled: 1,
      expires_ts: expiresTs
    });
    status = 200;
  } else {
    try {
      id = await rulesRepo.insertForKey({ ...key, note, priority, enabled: 1, expires_at: expiresTs, api_key_id: req.apiKey.id, created_by: req.apiActor.name });
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') fail(409, `a ${kind} rule for ${pattern} with that version range and scope already exists`);
      throw err;
    }
  }
  policy.invalidate();
  await audit(req.apiActor, status === 201 ? 'rule.save' : 'rule.update', target,
    JSON.stringify({ via: 'api', key_id: req.apiKey.id, range: versionRange, priority, expires: iso(expiresTs), application_id: sc.app, environment_id: sc.env }));
  const saved = await rulesRepo.ownedBy(req.apiKey.id, id);
  if (status === 201 && kind === 'allow') {
    // same as a rule saved by hand: an allow for any version gets its current release pulled in
    require('../../warm-latest').queueRules([{ ...saved, api_key_id: req.apiKey.id }], req.apiActor);
  }
  res.status(status).location(`${req.baseUrl}/rules/${id}`).json(shape(saved));
}));

// only the parts that make sense to change. pattern, kind and scope are the rule's identity, delete and file a new one
router.patch('/rules/:id', scope('rules:write'), wrap(async (req, res) => {
  const row = await owned(req);
  const b = req.body || {};
  const patch = {
    note: b.note !== undefined ? str(b.note, 512, 'note') : row.note,
    priority: b.priority !== undefined ? priorityFor(req, b.priority, Number(row.priority)) : Number(row.priority),
    enabled: b.enabled !== undefined ? (boolFlag(b.enabled, true) ? 1 : 0) : Number(row.enabled),
    expires_ts: b.expires !== undefined ? expiry.parse(b.expires, row.kind) : (row.expires_ts === null ? null : Number(row.expires_ts))
  };
  for (const k of Object.keys(b)) {
    if (!['note', 'priority', 'enabled', 'expires'].includes(k)) fail(400, `${k.slice(0, 40)} can't be changed, delete the rule and file a new one`);
  }
  await rulesRepo.updateForKey(req.apiKey.id, row.id, patch);
  policy.invalidate();
  await audit(req.apiActor, 'rule.update', `${row.ecosystem}:${row.kind}:${row.pattern}`,
    JSON.stringify({ via: 'api', key_id: req.apiKey.id, note: patch.note, priority: patch.priority, enabled: patch.enabled, expires: iso(patch.expires_ts) }));
  res.json(shape(await rulesRepo.ownedBy(req.apiKey.id, row.id)));
}));

router.delete('/rules/:id', scope('rules:write'), wrap(async (req, res) => {
  const row = await owned(req);
  await rulesRepo.removeForKey(req.apiKey.id, row.id);
  policy.invalidate();
  await audit(req.apiActor, 'rule.delete', `${row.ecosystem}:${row.kind}:${row.pattern}`, JSON.stringify({ via: 'api', key_id: req.apiKey.id }));
  res.status(204).end();
}));

router.use((req, res) => res.status(404).json({ error: 'no such endpoint' }));

module.exports = router;
