// API keys: making, editing, revoking and deleting them (admins), and checking one on a request (everyone else).
// Author: Tim Rice
// a key is only good from its own networks. no list, no key - there's no "from anywhere" option on purpose

const crypto = require('crypto');
const keys = require('../db/repositories/api-keys');
const ipacl = require('../security/network/ipacl');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { str, intIn } = require('../lib/validate');

const PREFIX = 'frk_';
const SCOPES = ['rules:read', 'rules:write'];
const MAX_CIDRS = 50;
// wider than this is "the internet, more or less", which is what the list is there to stop
const WIDEST = { 4: 8, 6: 32 };

const hashKey = (raw) => crypto.createHash('sha256').update(raw).digest('hex');

// newline, comma or space separated, or an array. a bare address is that one address (/32, /128 for v6)
function checkCidrs(value) {
  const parts = (Array.isArray(value) ? value : String(value || '').split(/[\s,]+/))
    .map((s) => String(s).trim()).filter(Boolean);
  if (!parts.length) fail(400, 'a key needs at least one address or network it may be used from, like 203.0.113.7 or 10.20.0.0/16');
  if (parts.length > MAX_CIDRS) fail(400, `that is more than ${MAX_CIDRS} networks for one key`);
  const out = [];
  for (const p of parts) {
    const c = ipacl.parseCidr(p);
    if (!c) fail(400, `${p.slice(0, 60)} is not an address or a network in cidr form`);
    if (c.prefix < WIDEST[c.version]) fail(400, `${p.slice(0, 60)} is too wide, keep IPv4 to /${WIDEST[4]} or narrower and IPv6 to /${WIDEST[6]} or narrower`);
    const norm = ipacl.normalizeCidr(p);
    if (!out.includes(norm)) out.push(norm);
  }
  return out;
}

function checkScopes(value) {
  const list = (Array.isArray(value) ? value : String(value || '').split(','))
    .map((s) => String(s).trim()).filter(Boolean);
  const bad = list.find((s) => !SCOPES.includes(s));
  if (bad) fail(400, `${String(bad).slice(0, 40)} is not a scope, pick from ${SCOPES.join(', ')}`);
  if (!list.length) fail(400, 'a key needs at least one scope');
  return [...new Set(list)];
}

// key lifetime in days, blank = until revoked
function checkKeyDays(value) {
  if (value === undefined || value === null || String(value).trim() === '') return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 1825) fail(400, 'a key lasts 1 to 1825 days, or leave it blank for until revoked');
  return Math.floor(Date.now() / 1000) + n * 86400;
}

function shape(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    scopes: String(row.scopes || '').split(',').filter(Boolean),
    allowed_cidrs: String(row.allowed_cidrs || '').split('\n').filter(Boolean),
    max_priority: Number(row.max_priority),
    expires_ts: row.expires_ts === null || row.expires_ts === undefined ? null : Number(row.expires_ts),
    revoked_at: row.revoked_at || null,
    revoked_by: row.revoked_by || null,
    created_by: row.created_by || null,
    created_at: row.created_at,
    last_used_at: row.last_used_at || null,
    last_used_ip: row.last_used_ip || null,
    rule_count: Number(row.rule_count || 0)
  };
}

function readBody(body, existing) {
  return {
    name: existing && body.name === undefined ? existing.name : (str(body.name, 128, 'name') || fail(400, 'give the key a name, like the product that will use it')),
    scopes: existing && body.scopes === undefined ? existing.scopes : checkScopes(body.scopes === undefined ? SCOPES : body.scopes),
    cidrs: existing && body.allowed_cidrs === undefined ? existing.allowed_cidrs : checkCidrs(body.allowed_cidrs),
    maxPriority: existing && body.max_priority === undefined ? existing.max_priority : intIn(body.max_priority, -1000, 1000, 0),
    expiresTs: existing && body.expires_in_days === undefined ? existing.expires_ts : checkKeyDays(body.expires_in_days)
  };
}

async function list() {
  return (await keys.list()).map(shape);
}

async function get(id) {
  const row = shape(await keys.byId(id));
  if (!row) fail(404, 'no such key');
  return row;
}

// the only time the key exists outside the caller's hands
async function create(actor, body) {
  const k = readBody(body || {}, null);
  const raw = `${PREFIX}${crypto.randomBytes(32).toString('base64url')}`;
  const id = await keys.insert({
    name: k.name, prefix: raw.slice(0, 12), hash: hashKey(raw), scopes: k.scopes.join(','), cidrs: k.cidrs.join('\n'),
    maxPriority: k.maxPriority, expiresTs: k.expiresTs, createdBy: actor.name
  });
  await audit(actor, 'apikey.create', k.name, JSON.stringify({ id, scopes: k.scopes, allowed_cidrs: k.cidrs, max_priority: k.maxPriority }));
  return { key: raw, apiKey: await get(id) };
}

async function update(actor, id, body) {
  const existing = await get(id);
  if (existing.revoked_at) fail(409, 'that key is revoked, make a new one instead');
  const k = readBody(body || {}, existing);
  await keys.update(id, { name: k.name, scopes: k.scopes.join(','), cidrs: k.cidrs.join('\n'), maxPriority: k.maxPriority, expiresTs: k.expiresTs });
  const after = await get(id);
  await audit(actor, 'apikey.update', existing.name, null, {
    before: { name: existing.name, scopes: existing.scopes, allowed_cidrs: existing.allowed_cidrs, max_priority: existing.max_priority },
    after: { name: after.name, scopes: after.scopes, allowed_cidrs: after.allowed_cidrs, max_priority: after.max_priority }
  });
  return after;
}

async function revoke(actor, id) {
  const existing = await get(id);
  if (existing.revoked_at) fail(409, 'that key is already revoked');
  await keys.revoke(id, actor.name);
  await audit(actor, 'apikey.revoke', existing.name, `id ${id}`);
  return get(id);
}

async function remove(actor, id) {
  const existing = await get(id);
  if (!existing.revoked_at) fail(409, 'revoke the key first, then it can be deleted');
  await keys.remove(id);
  await audit(actor, 'apikey.delete', existing.name, `id ${id}, ${existing.rule_count} rules it made stay`);
}

// ---------------------------------------------------------------- on a request

// null = no usable key. reason is for the log and the caller's 401/403, never says which part of a bad key was wrong
async function authenticate(raw, ipText) {
  if (!raw || typeof raw !== 'string' || !raw.startsWith(PREFIX) || raw.length > 120) return { ok: false, status: 401 };
  const hash = hashKey(raw);
  const row = await keys.byHash(hash);
  if (!row) return { ok: false, status: 401 };
  const a = Buffer.from(row.key_hash, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, status: 401 };
  if (row.revoked_at || Number(row.expired)) return { ok: false, status: 401, keyId: row.id, why: row.revoked_at ? 'revoked' : 'expired' };

  const ip = ipacl.parseIp(ipText);
  const nets = String(row.allowed_cidrs || '').split('\n').filter(Boolean).map((c) => ipacl.parseCidr(c)).filter(Boolean);
  if (!ip || !nets.some((n) => ipacl.cidrContains(n, ip))) return { ok: false, status: 403, keyId: row.id, name: row.name, why: 'address' };

  keys.touch(row.id, ipText).catch(() => {});
  return {
    ok: true,
    key: {
      id: row.id, name: row.name, prefix: row.prefix,
      scopes: String(row.scopes || '').split(',').filter(Boolean),
      maxPriority: Number(row.max_priority)
    }
  };
}

module.exports = { PREFIX, SCOPES, checkCidrs, checkScopes, list, get, create, update, revoke, remove, authenticate, hashKey };
