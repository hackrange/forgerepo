// Registry tokens: making one, reading it off a request, and checking it.
// Author: Tim Rice

const crypto = require('crypto');
const tokens = require('../../db/repositories/tokens');

// what /v2/token hands docker. short lived, and never the token it logged in with
const BEARER_PREFIX = 'nrb_';
const BEARER_SECONDS = 300;

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function newToken() {
  const secret = crypto.randomBytes(32).toString('base64url');
  const token = `nrt_${secret}`;
  return { token, prefix: token.slice(0, 12), hash: hashToken(token) };
}

function identity(row) {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    username: row.username,
    role: row.role,
    application: row.application || null,
    environment: row.environment || null,
    // the ids rules are scoped by. only set while the label still exists
    applicationId: row.application ? Number(row.application_id) : 0,
    environmentId: row.environment ? Number(row.environment_id) : 0
  };
}

const usable = (row) => !!row && !row.disabled && !(row.expires_at && new Date(row.expires_at) < new Date());

async function lookupToken(raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 200) return null;
  const hash = hashToken(raw);
  // a bearer is looked up by its own hash and is only as good as the token it stands for right now
  if (raw.startsWith(BEARER_PREFIX)) {
    const held = await tokens.forBearer(hash);
    return usable(held) ? identity(held) : null;
  }
  const row = await tokens.forRegistry(hash);
  if (!row) return null;
  if (row.disabled) return null;
  if (row.expires_at && new Date(row.expires_at) < new Date()) return null;

  // belt and suspenders, constant time compare anyway
  const a = Buffer.from(row.token_hash, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  return identity(row);
}

// a bearer for a token docker just logged in with. the caller has already checked the token
async function issueBearer(token) {
  const raw = `${BEARER_PREFIX}${crypto.randomBytes(32).toString('base64url')}`;
  const bearers = require('../../db/repositories/oci-bearers');
  await bearers.put(hashToken(raw), token.id, BEARER_SECONDS);
  bearers.sweep().catch(() => {});
  return { token: raw, expiresIn: BEARER_SECONDS };
}

// bearer or basic. one copy of this parsing, a second would definitely drift
function registryCredential(req) {
  const header = (req && req.get && req.get('authorization')) || '';
  if (/^bearer\s+/i.test(header)) return header.slice(7).trim() || null;
  if (/^basic\s+/i.test(header)) {
    try {
      const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
      return decoded.slice(decoded.indexOf(':') + 1) || null;
    } catch (err) {
      return null;
    }
  }
  return null;
}

async function touchToken(id, ip) {
  await tokens.touch(id, ip);
}

module.exports = { BEARER_SECONDS, hashToken, newToken, lookupToken, issueBearer, registryCredential, touchToken };
