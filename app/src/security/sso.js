// Single sign on, over OpenID Connect.
// Author: Tim Rice
//
// code flow + PKCE, token swapped over our own connection, signature checked against the provider's keys.
// nothing trusted just because a browser handed it over. no SAML, xml sigs are cursed

const https = require('https');
const crypto = require('crypto');
const db = require('../db');
const appConfig = require('../config');
const { parseCookies } = require('./auth/cookies');
const log = require('../logger');
const users = require('../db/repositories/users');
const ssoStates = require('../db/repositories/sso-states');

const HTTP_TIMEOUT_MS = 15000;
const DISCOVERY_TTL_MS = 60 * 60000;
const JWKS_TTL_MS = 60 * 60000;
// a login someone started and wandered off from is garbage after this
const STATE_TTL_MINUTES = 15;
//tokens are short lived and clocks are liars
const CLOCK_SKEW_SECONDS = 120;

let discovery = null;
let keys = null;

// ---------------------------------------------------------------- settings

function config() {
  return {
    enabled: db.settings.getBool('sso_enabled'),
    // sso_only refuses passwords, even right ones
    mode: db.settings.get('sso_mode') === 'sso_only' ? 'sso_only' : 'both',
    issuer: String(db.settings.get('oidc_issuer') || '').replace(/\/+$/, ''),
    clientId: db.settings.get('oidc_client_id') || '',
    clientSecret: db.settings.get('oidc_client_secret') || '',
    scopes: db.settings.get('oidc_scopes') || 'openid profile email',
    label: db.settings.get('sso_button_label') || 'Sign in with SSO',
    autoCreate: db.settings.getBool('sso_auto_create'),
    defaultRole: db.settings.get('sso_default_role') || 'developer',
    redirect: db.settings.get('oidc_redirect_url') || '',
    // empty = no group roles (default)
    roleGroups: db.settings.get('sso_role_groups') || '',
    roleSync: db.settings.getBool('sso_role_sync'),
    requireRoleGroup: db.settings.getBool('sso_require_role_group'),
    groupsClaim: db.settings.get('oidc_groups_claim') || 'groups'
  };
}

// has to match the provider exactly, so it can be set by hand
function redirectUri(settings = config()) {
  if (settings.redirect) return settings.redirect;
  const base = db.settings.get('public_url');
  return base ? `${String(base).replace(/\/+$/, '')}/_api/sso/callback` : '';
}

// why sso can't be used right now, or null if it's good to go
function unusable(settings = config()) {
  if (!settings.issuer) return 'no identity provider address is set';
  if (!/^https:\/\//i.test(settings.issuer)) return 'the identity provider address has to be https';
  if (!settings.clientId) return 'no client id is set';
  if (!settings.clientSecret) return 'no client secret is set';
  if (!redirectUri(settings)) return 'set the public url, or a redirect address, so the provider knows where to send people back to';
  return null;
}

// pre-login state. nothing about the provider, no free recon
function publicState() {
  const settings = config();
  const usable = settings.enabled && !unusable(settings);
  return {
    enabled: !!usable,
    // half configured sso_only = locked door, no key
    passwordAllowed: !usable || settings.mode === 'both',
    label: settings.label
  };
}

// re-read every time so the break glass script works without a restart
function passwordLoginAllowed() {
  return publicState().passwordAllowed;
}

// ---------------------------------------------------------------- http

function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== 'https:') return reject(new Error('the identity provider has to be https'));
    const payload = options.body || null;
    const headers = { accept: 'application/json', ...(options.headers || {}) };
    if (payload) headers['content-length'] = Buffer.byteLength(payload);

    const req = https.request(
      {
        // not host, it includes the port and dns gets weird
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        method: options.method || 'GET',
        headers
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          if (text.length < 512000) text += c;
        });
        res.on('end', () => resolve({ status: res.statusCode, text }));
      }
    );
    req.on('error', (err) => reject(new Error(`could not reach ${target.hostname}: ${err.message}`)));
    req.setTimeout(HTTP_TIMEOUT_MS, () => req.destroy(new Error(`${target.hostname} did not answer in time`)));
    req.end(payload);
  });
}

async function getJson(url, headers) {
  const res = await request(url, { headers });
  if (res.status !== 200) throw new Error(`${url} answered ${res.status}`);
  try {
    return JSON.parse(res.text);
  } catch (err) {
    throw new Error(`${url} did not answer with json`);
  }
}

// ---------------------------------------------------------------- discovery and keys

async function metadata(force = false) {
  const settings = config();
  const problem = unusable(settings);
  if (problem) throw new Error(problem);

  if (!force && discovery && discovery.issuer === settings.issuer && discovery.at > Date.now() - DISCOVERY_TTL_MS) {
    return discovery.doc;
  }
  // some providers put it at the root instead of off the issuer
  const candidates = [
    `${settings.issuer}/.well-known/openid-configuration`,
    `${new URL(settings.issuer).origin}/.well-known/openid-configuration`
  ];
  let last = null;
  for (const url of [...new Set(candidates)]) {
    try {
      const doc = await getJson(url);
      if (!doc.authorization_endpoint || !doc.token_endpoint) throw new Error('that is not an openid configuration');
      discovery = { issuer: settings.issuer, doc, at: Date.now() };
      return doc;
    } catch (err) {
      last = err;
    }
  }
  throw new Error(`could not read the provider's configuration: ${last ? last.message : 'no answer'}`);
}

async function signingKeys(force = false) {
  const doc = await metadata();
  if (!force && keys && keys.uri === doc.jwks_uri && keys.at > Date.now() - JWKS_TTL_MS) return keys.list;
  const jwks = await getJson(doc.jwks_uri);
  const list = Array.isArray(jwks.keys) ? jwks.keys : [];
  keys = { uri: doc.jwks_uri, list, at: Date.now() };
  return list;
}

// ---------------------------------------------------------------- the token

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(text) {
  return Buffer.from(String(text).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

const DIGESTS = { 256: 'sha256', 384: 'sha384', 512: 'sha512' };

function verifyOptions(alg, key) {
  const bits = alg.slice(2);
  const digest = DIGESTS[bits];
  if (!digest) throw new Error(`the token is signed with ${alg}, which this does not know`);
  if (alg.startsWith('RS')) return { digest, options: key };
  if (alg.startsWith('PS')) {
    return { digest, options: { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } };
  }
  if (alg.startsWith('ES')) return { digest, options: { key, dsaEncoding: 'ieee-p1363' } };
  throw new Error(`the token is signed with ${alg}, which this does not know`);
}

// signature first, then claims, and only THEN do we believe a word of it.
async function verifyIdToken(token, nonce) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('the id token is not a jwt');

  let header;
  let claims;
  try {
    header = JSON.parse(fromB64url(parts[0]).toString('utf8'));
    claims = JSON.parse(fromB64url(parts[1]).toString('utf8'));
  } catch (err) {
    throw new Error('the id token is not readable');
  }
  if (!header.alg || header.alg === 'none') throw new Error('the id token is not signed');

  const settings = config();
  const doc = await metadata();
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
  const signature = fromB64url(parts[2]);

  const matching = (list) => list.filter((k) => (!header.kid || k.kid === header.kid) && (!k.use || k.use === 'sig'));
  const checks = (list) => list.some((jwk) => {
    try {
      const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const { digest, options } = verifyOptions(header.alg, key);
      return crypto.verify(digest, signed, options, signature);
    } catch (err) {
      // a broken key is not a passing key. the next one might be fine though
      return false;
    }
  });

  // keys may be a rotation behind, so ONE refetch. more and anyone could make us hammer the provider
  let verified = checks(matching(await signingKeys()));
  if (!verified) verified = checks(matching(await signingKeys(true)));
  if (!verified) throw new Error('the signature on the id token does not check out');

  const now = Math.floor(Date.now() / 1000);
  const issuer = String(claims.iss || '').replace(/\/+$/, '');
  if (issuer !== String(doc.issuer || settings.issuer).replace(/\/+$/, '')) {
    throw new Error('the id token came from a different issuer');
  }
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(settings.clientId)) throw new Error('the id token was not issued for this application');
  if (claims.azp && claims.azp !== settings.clientId) throw new Error('the id token was issued to a different application');
  if (!claims.exp || claims.exp + CLOCK_SKEW_SECONDS < now) throw new Error('the id token has expired');
  if (claims.iat && claims.iat - CLOCK_SKEW_SECONDS > now) throw new Error('the id token is dated in the future');
  if (nonce && claims.nonce !== nonce) throw new Error('the id token does not match the login it answers');
  if (!claims.sub) throw new Error('the id token names nobody');

  return claims;
}

// ---------------------------------------------------------------- starting a login

async function begin(req) {
  const settings = config();
  if (!settings.enabled) throw new Error('single sign on is switched off');
  const problem = unusable(settings);
  if (problem) throw new Error(problem);

  const doc = await metadata();
  const state = crypto.randomBytes(32).toString('hex');
  const nonce = crypto.randomBytes(32).toString('hex');
  // PKCE, a nicked code is worthless without the verifier
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());

  await ssoStates.add({ state, nonce, verifier, ip: String(req.ip || '').slice(0, 45) });

  const url = new URL(doc.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', settings.clientId);
  url.searchParams.set('redirect_uri', redirectUri(settings));
  url.searchParams.set('scope', settings.scopes);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

// ---------------------------------------------------------------- finishing one

// ---------------------------------------------------------------- which browser a login belongs to

// the state rides in a cookie as well, so a callback only finishes in the browser that asked for it. without this a
// callback link started in one browser signs a DIFFERENT browser in as whoever started it (login CSRF).
// Lax, not Strict: the provider sends people back with a top level GET from its own site, Strict never arrives
const BROWSER_COOKIE = 'nr_sso';
const browserCookie = () => ({ httpOnly: true, sameSite: 'lax', secure: !!appConfig.secureCookies, path: '/_api/sso' });

function bindBrowser(res, url) {
  res.cookie(BROWSER_COOKIE, new URL(url).searchParams.get('state'), { ...browserCookie(), maxAge: STATE_TTL_MINUTES * 60000 });
}

function sameBrowser(req, state) {
  const held = String(parseCookies(req.headers.cookie)[BROWSER_COOKIE] || '');
  const said = String(state || '');
  if (!/^[a-f0-9]{64}$/.test(held) || said.length !== held.length) return false;
  return crypto.timingSafeEqual(Buffer.from(held), Buffer.from(said));
}

function forgetBrowser(res) {
  res.clearCookie(BROWSER_COOKIE, browserCookie());
}

// A state is single use. replay the callback and there's nothing waiting for you.
async function takeState(state) {
  if (!/^[a-f0-9]{64}$/.test(String(state || ''))) return null;
  const row = await ssoStates.live(state, STATE_TTL_MINUTES);
  await ssoStates.remove(state);
  return row;
}

async function exchange(code, verifier) {
  const settings = config();
  const doc = await metadata();
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(settings),
    code_verifier: verifier
  });

  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  // client id in ONE place, never both. Okta rejects "multiple client credentials"
  const methods = doc.token_endpoint_auth_methods_supported || ['client_secret_basic'];
  if (methods.includes('client_secret_basic')) {
    const pair = Buffer.from(`${encodeURIComponent(settings.clientId)}:${encodeURIComponent(settings.clientSecret)}`).toString('base64');
    headers.authorization = `Basic ${pair}`;
  } else {
    //nothing in the header, so the id has to go here to say who's asking
    body.set('client_id', settings.clientId);
    body.set('client_secret', settings.clientSecret);
  }

  const res = await request(doc.token_endpoint, { method: 'POST', body: body.toString(), headers });
  let parsed;
  try {
    parsed = JSON.parse(res.text);
  } catch (err) {
    throw new Error('the provider did not answer the code exchange with json');
  }
  if (res.status !== 200 || !parsed.id_token) {
    throw new Error(`the provider would not exchange the code: ${parsed.error_description || parsed.error || res.status}`);
  }
  return parsed;
}

// userinfo fills in when email isn't in the token
async function profileFrom(tokens, claims) {
  if (claims.email || !tokens.access_token) return claims;
  try {
    const doc = await metadata();
    if (!doc.userinfo_endpoint) return claims;
    const extra = await getJson(doc.userinfo_endpoint, { authorization: `Bearer ${tokens.access_token}` });
    if (extra && extra.sub === claims.sub) return { ...claims, ...extra };
  } catch (err) {
    log.warn('could not read the userinfo endpoint', err.message);
  }
  return claims;
}

function usernameFrom(claims) {
  const raw = claims.preferred_username || claims.email || claims.sub;
  //just a db column, not an identity
  return String(raw).trim().slice(0, 64);
}

// ---------------------------------------------------------------- roles from groups

// weakest first, order decides who wins
const ROLES = ['viewer', 'developer', 'publisher', 'approver', 'admin'];

// one per line, like `approver = okta_npm_approvers, okta_npm_leads`. case-insensitive
function parseRoleGroups(text) {
  const rules = [];
  for (const raw of String(text || '').split(/[\r\n]+/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const at = line.indexOf('=');
    if (at < 0) continue;
    const role = line.slice(0, at).trim().toLowerCase();
    if (!ROLES.includes(role)) continue;
    for (const name of line.slice(at + 1).split(',')) {
      const group = name.trim().toLowerCase();
      if (group) rules.push({ role, group });
    }
  }
  return rules;
}

// bad lines, so a typo doesn't silently hand someone the wrong role
function roleGroupProblems(text) {
  const bad = [];
  for (const raw of String(text || '').split(/[\r\n]+/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const at = line.indexOf('=');
    const role = at < 0 ? '' : line.slice(0, at).trim().toLowerCase();
    if (!ROLES.includes(role) || !line.slice(at + 1).trim()) bad.push(line);
  }
  return bad;
}

// most providers send a list, a few send one string. we take both
function groupsFrom(claims, settings) {
  const raw = claims[settings.groupsClaim];
  const list = Array.isArray(raw)
    ? raw
    : (typeof raw === 'string' && raw ? raw.split(/[,\s]+/) : []);
  return list.map((g) => String(g).trim().toLowerCase()).filter(Boolean);
}

function roleFromGroups(claims, settings = config()) {
  const rules = parseRoleGroups(settings.roleGroups);
  if (!rules.length) return null;
  const mine = new Set(groupsFrom(claims, settings));
  let best = null;
  for (const rule of rules) {
    if (!mine.has(rule.group)) continue;
    if (best === null || ROLES.indexOf(rule.role) > ROLES.indexOf(best)) best = rule.role;
  }
  return best;
}

// demoting the last admin = door locks behind you. refused
async function anotherAdminExists(exceptId) {
  return (await users.otherActiveAdmins(exceptId)) > 0;
}

// email first, it survives a login name change
async function resolveUser(claims) {
  const settings = config();
  const email = String(claims.email || '').trim().toLowerCase();
  const username = usernameFrom(claims);

  let user = null;
  if (email) {
    // emails aren't unique here. picking whichever row came first = logged in as someone else
    const matches = await users.byEmailForSso(email);
    if (matches.length > 1) {
      throw new Error(`more than one account here has the email address ${email}, so it is not clear which is yours. Ask an admin to fix it.`);
    }
    user = matches[0] || null;
  }
  if (!user) {
    user = await users.byUsernameForSso(username);
  }

  const mapping = parseRoleGroups(settings.roleGroups);
  const mapped = mapping.length ? roleFromGroups(claims, settings) : null;
  if (mapping.length && !mapped && settings.requireRoleGroup) {
    // mapping doubles as the bouncer here, because that setting asked for it
    throw new Error('your account is not in a group that grants access to this registry. Ask an admin.');
  }

  if (user) {
    if (user.disabled) throw new Error(`the ${user.username} account is disabled on this box`);

    // with a mapping the provider owns roles. hand edits get undone, that's the point
    let role = user.role;
    let changed = null;
    if (mapped && settings.roleSync && mapped !== user.role) {
      if (user.role === 'admin' && !(await anotherAdminExists(user.id))) {
        log.warn(`left ${user.username} as admin: the groups say ${mapped}, but this is the only admin left`);
      } else {
        changed = { from: user.role, to: mapped };
        role = mapped;
      }
    }

    // keep name and email in sync with the provider, that's where they live now
    await users.recordSsoLogin(user.id, { email, fullName: String(claims.name || '').slice(0, 128), role });
    if (changed) log.info(`${user.username} is now ${changed.to} rather than ${changed.from}, from the provider's groups`);
    return { ...user, role, roleChanged: changed };
  }

  if (!settings.autoCreate) {
    throw new Error('there is no account here for you, and this box does not make one on the way in. Ask an admin.');
  }
  // group wins, default is the consolation prize
  const role = mapped || (ROLES.includes(settings.defaultRole)
    ? settings.defaultRole
    : 'developer');

  // random junk nothing hashes to, so SSO only until an admin sets a password
  const unusablePassword = crypto.randomBytes(48).toString('base64');
  const result = await users.createFromSso({
    username, email: email || null, fullName: String(claims.name || '').slice(0, 128) || null, passwordHash: unusablePassword, role
  });
  log.info(`made an account for ${username} from single sign on, as ${role}${mapped ? " from the provider's groups" : ''}`);
  return { id: result.insertId, username, role, disabled: 0, created: true };
}

async function complete(query) {
  const row = await takeState(query.state);
  if (!row) throw new Error('that login has expired or was already used, start again');
  const code = String(query.code || '');
  if (!code) throw new Error('the provider sent no code back');

  const tokens = await exchange(code, row.verifier);
  const claims = await verifyIdToken(tokens.id_token, row.nonce);
  const profile = await profileFrom(tokens, claims);
  return resolveUser(profile);
}

async function sweepStates() {
  await ssoStates.sweep(STATE_TTL_MINUTES);
}

// settings changed, cached doc + keys are stale
function invalidate() {
  discovery = null;
  keys = null;
}

module.exports = {
  resolveUser,
  config,
  publicState,
  parseRoleGroups,
  roleGroupProblems,
  roleFromGroups,
  passwordLoginAllowed,
  unusable,
  redirectUri,
  metadata,
  begin,
  complete,
  bindBrowser,
  sameBrowser,
  forgetBrowser,
  sweepStates,
  invalidate
};
