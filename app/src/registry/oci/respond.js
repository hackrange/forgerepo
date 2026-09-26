// The /v2 side helpers: what belongs to us, how a no is worded, and the traffic line every answer leaves behind.
// Author: Tim Rice
//
// docker reads errors as {"errors":[{code, message}]}, and decides what to do next from the code, so they are spelled
// the way the registry spec spells them rather than in our own words

const db = require('../../db');
const access = require('../shared/access');

const MOUNT = '/v2';

// anything not under /v2 is still npm's, including an npm package called v2
const OURS = /^\/v2(\/|$)/;

const CODES = {
  BLOB_UNKNOWN: 404,
  BLOB_UPLOAD_UNKNOWN: 404,
  BLOB_UPLOAD_INVALID: 400,
  MANIFEST_UNKNOWN: 404,
  MANIFEST_BLOB_UNKNOWN: 400,
  SIZE_INVALID: 400,
  NAME_UNKNOWN: 404,
  NAME_INVALID: 400,
  TAG_INVALID: 400,
  DIGEST_INVALID: 400,
  MANIFEST_INVALID: 400,
  UNSUPPORTED: 405,
  UNAUTHORIZED: 401,
  DENIED: 403,
  TOOMANYREQUESTS: 429
};

function record(req, fields) {
  access.record(req, { ecosystem: 'oci', ...fields });
}

// the registry spec's error envelope. detail is for a person reading the traffic log, not for the client to parse
function fail(res, code, message, detail) {
  const status = CODES[code] || 500;
  res.status(status).json({ errors: [{ code, message, detail: detail || null }] });
  return status;
}

// docker asks anonymously first and expects to be told how to authenticate
function challenge(req, res, message) {
  res.set('www-authenticate', `Basic realm="ForgeRepo",service="${(db.settings.get('registry_name') || 'ForgeRepo')}"`);
  return fail(res, 'UNAUTHORIZED', message);
}

// the token flow Docker Hub uses: a client with a login trades it at /v2/token, one without gets an anonymous token and
// keeps pulling. a Basic challenge would stop that second one cold ("no basic auth credentials")
function bearerChallenge(req, res, message) {
  const realm = `${access.baseUrl(req)}/v2/token`;
  res.set('www-authenticate', `Bearer realm="${realm}",service="${(db.settings.get('registry_name') || 'ForgeRepo')}"`);
  return fail(res, 'UNAUTHORIZED', message);
}

// Basic where every client has to log in anyway, the token flow where logging in is only needed to push
function askLogin(req, res, message) {
  return db.settings.getBool('require_auth') ? challenge(req, res, message) : bearerChallenge(req, res, message);
}

// NOT a security control, user agents lie. the same hint npm and pip clients get
const CLIENT_UA = /\b(docker|containerd|skopeo|podman|buildkit|buildah|crane|regctl|oras|kaniko|img|nerdctl)\b/i;

function looksLikeOciClient(req) {
  return !!req.npmIdentity || CLIENT_UA.test(req.get('user-agent') || '');
}

function auditOnly() {
  return db.settings.getBool('audit_mode');
}

module.exports = { MOUNT, OURS, CODES, record, fail, challenge, bearerChallenge, askLogin, looksLikeOciClient, auditOnly };
