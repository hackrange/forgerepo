// A small S3 client for the blob store: put, head, get, delete and list. Signed with SigV4, sent through safefetch.
// Author: Tim Rice
//
// only what the store needs. object keys are ours (sha256 paths), never something a client sent,
// and every upload carries its sha256 so the bucket itself refuses bytes that don't match

const safefetch = require('../security/safefetch');
const { sign, EMPTY_SHA256, encode } = require('./sigv4');

const KEY = /^[A-Za-z0-9/_.-]{1,900}$/;
const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const HEX64 = /^[0-9a-f]{64}$/;
const UPLOAD_TIMEOUT_MS = 15 * 60 * 1000;

function storeError(message, status, code) {
  const e = new Error(message);
  e.status = status;
  e.code = code || null;
  return e;
}

// cfg: { endpoint, region, bucket, accessKeyId, secretAccessKey, pathStyle }
function objectUrl(cfg, key, query) {
  if (!BUCKET.test(String(cfg.bucket || ''))) throw storeError('the bucket name is not valid', 400);
  if (key !== '' && (!KEY.test(key) || key.split('/').includes('..'))) throw storeError('that is not an object key this store makes', 400);
  const base = new URL(cfg.endpoint);
  const path = key.split('/').map(encode).join('/');
  const url = cfg.pathStyle
    ? new URL(`${base.origin}/${cfg.bucket}/${path}`)
    : new URL(`${base.protocol}//${cfg.bucket}.${base.host}/${path}`);
  for (const [k, v] of Object.entries(query || {})) if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
  return url.toString();
}

function signed(cfg, method, url, headers, payloadHash) {
  return sign({
    method, url, region: cfg.region || 'us-east-1', accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey,
    headers, payloadHash
  });
}

// S3 errors are a small xml document. the code is what matters, the message is for people
async function failure(res, what) {
  let text = '';
  try {
    text = (await res.text()).slice(0, 2000);
  } catch (err) {
    text = '';
  }
  const code = (/<Code>([^<]{1,64})<\/Code>/.exec(text) || [])[1] || null;
  const message = (/<Message>([^<]{1,300})<\/Message>/.exec(text) || [])[1] || `the bucket said ${res.status}`;
  return storeError(`${what}: ${code ? `${code}, ` : ''}${message}`, res.status, code);
}

const checksumOf = (sha256) => Buffer.from(sha256, 'hex').toString('base64');

// stream is read once and never replayed, so no redirects
async function put(cfg, key, { stream, size, sha256 }) {
  if (!HEX64.test(String(sha256 || ''))) throw storeError('an upload needs its sha256', 400);
  if (!(Number.isSafeInteger(size) && size >= 0)) throw storeError('an upload needs its size', 400);
  const url = objectUrl(cfg, key);
  const headers = signed(cfg, 'PUT', url, {
    'content-length': size,
    'content-type': 'application/octet-stream',
    'x-amz-checksum-sha256': checksumOf(sha256)
  });
  const res = await safefetch.request(url, {
    method: 'PUT', headers, bodyStream: stream, bodyLength: size, noRedirects: true, timeoutMs: UPLOAD_TIMEOUT_MS, maxBytes: 64 * 1024
  });
  if (res.status !== 200) throw await failure(res, `uploading ${key}`);
}

// null when it isn't there. sha256 comes back when the bucket kept the checksum
async function head(cfg, key) {
  const url = objectUrl(cfg, key);
  const headers = signed(cfg, 'HEAD', url, { 'x-amz-checksum-mode': 'ENABLED' }, EMPTY_SHA256);
  const res = await safefetch.request(url, { method: 'HEAD', headers, noRedirects: true, timeoutMs: 30000, maxBytes: 64 * 1024 });
  if (res.status === 404) return null;
  if (res.status !== 200) throw storeError(`checking ${key}: the bucket said ${res.status}`, res.status);
  const sum = res.headers.get('x-amz-checksum-sha256');
  const hex = sum ? Buffer.from(sum, 'base64').toString('hex') : null;
  return { size: Number(res.headers.get('content-length')), sha256: HEX64.test(String(hex)) ? hex : null };
}

// a readable stream of the object, or null when it isn't there
async function get(cfg, key, { maxBytes } = {}) {
  const url = objectUrl(cfg, key);
  const headers = signed(cfg, 'GET', url, {}, EMPTY_SHA256);
  const res = await safefetch.request(url, { method: 'GET', headers, noRedirects: true, stream: true, timeoutMs: UPLOAD_TIMEOUT_MS, maxBytes });
  if (res.status === 404) {
    if (res.stream) res.stream.resume();
    return null;
  }
  if (res.status !== 200) {
    if (res.stream) res.stream.resume();
    throw storeError(`reading ${key}: the bucket said ${res.status}`, res.status);
  }
  return res.stream;
}

async function remove(cfg, key) {
  const url = objectUrl(cfg, key);
  const headers = signed(cfg, 'DELETE', url, {}, EMPTY_SHA256);
  const res = await safefetch.request(url, { method: 'DELETE', headers, noRedirects: true, timeoutMs: 30000, maxBytes: 64 * 1024 });
  if (res.status !== 204 && res.status !== 200 && res.status !== 404) throw await failure(res, `deleting ${key}`);
}

const unxml = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

// one page of keys under a prefix. next is the token for the page after, or null
async function list(cfg, prefix, next) {
  const url = objectUrl(cfg, '', { 'list-type': 2, prefix, 'max-keys': 1000, 'continuation-token': next });
  const headers = signed(cfg, 'GET', url, {}, EMPTY_SHA256);
  const res = await safefetch.request(url, { method: 'GET', headers, noRedirects: true, timeoutMs: 60000, maxBytes: 8 * 1024 * 1024 });
  if (res.status !== 200) throw await failure(res, 'listing the bucket');
  const text = await res.text();
  const keys = [...text.matchAll(/<Key>([^<]*)<\/Key>/g)].map((m) => unxml(m[1]));
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(text);
  const token = (/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/.exec(text) || [])[1];
  return { keys, next: truncated && token ? unxml(token) : null };
}

// for a test stack. the app never makes buckets on its own
async function createBucket(cfg) {
  const url = objectUrl(cfg, '');
  const headers = signed(cfg, 'PUT', url, { 'content-length': 0 }, EMPTY_SHA256);
  const res = await safefetch.request(url, { method: 'PUT', headers, noRedirects: true, timeoutMs: 30000, maxBytes: 64 * 1024 });
  if (res.status !== 200 && res.status !== 409) throw await failure(res, 'creating the bucket');
}

module.exports = { put, head, get, remove, list, createBucket, objectUrl, BUCKET };
