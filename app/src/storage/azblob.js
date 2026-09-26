// A small Azure Blob client for the blob store: put, head, get, delete and list. Shared Key signing, sent through safefetch.
// Author: Tim Rice
//
// the same shape as s3.js so the bucket driver doesn't care which it has. object keys are ours (sha256 paths),
// and every upload carries its Content-MD5, which Azure checks and refuses the bytes if they don't match

const crypto = require('crypto');
const safefetch = require('../security/safefetch');

const VERSION = '2021-08-06';
const KEY = /^[A-Za-z0-9/_.-]{1,900}$/;
const CONTAINER = /^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$/;
const ACCOUNT = /^[a-z0-9]{3,24}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const UPLOAD_TIMEOUT_MS = 15 * 60 * 1000;

function storeError(message, status, code) {
  const e = new Error(message);
  e.status = status;
  e.code = code || null;
  return e;
}

// cfg: { endpoint, account, accountKey, container }. endpoint is https://<account>.blob.core.windows.net,
// or an emulator's http://host:10000/<account>
function blobUrl(cfg, key, query) {
  if (!ACCOUNT.test(String(cfg.account || ''))) throw storeError('the storage account name is not valid', 400);
  if (!CONTAINER.test(String(cfg.container || ''))) throw storeError('the container name is not valid', 400);
  if (key !== '' && (!KEY.test(key) || key.split('/').includes('..'))) throw storeError('that is not an object key this store makes', 400);
  const base = String(cfg.endpoint).replace(/\/+$/, '');
  const url = new URL(`${base}/${cfg.container}${key ? `/${key.split('/').map(encodeURIComponent).join('/')}` : ''}`);
  for (const [k, v] of Object.entries(query || {})) if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
  return url.toString();
}

// the Shared Key string to sign, as the Blob service documents it
function sign(cfg, method, url, headers) {
  const u = new URL(url);
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[k.toLowerCase()] = String(v);
  h['x-ms-date'] = new Date().toUTCString();
  h['x-ms-version'] = VERSION;

  const canonicalHeaders = Object.keys(h)
    .filter((k) => k.startsWith('x-ms-'))
    .sort()
    .map((k) => `${k}:${h[k].trim().replace(/\s+/g, ' ')}\n`)
    .join('');

  const params = new Map();
  for (const [k, v] of u.searchParams.entries()) {
    const name = k.toLowerCase();
    params.set(name, [...(params.get(name) || []), v]);
  }
  let resource = `/${cfg.account}${u.pathname}`;
  for (const name of [...params.keys()].sort()) resource += `\n${name}:${params.get(name).sort().join(',')}`;

  const length = h['content-length'] && h['content-length'] !== '0' ? h['content-length'] : '';
  const toSign = [
    method.toUpperCase(), h['content-encoding'] || '', h['content-language'] || '', length, h['content-md5'] || '',
    h['content-type'] || '', '', h['if-modified-since'] || '', h['if-match'] || '', h['if-none-match'] || '',
    h['if-unmodified-since'] || '', h.range || '', canonicalHeaders + resource
  ].join('\n');
  const signature = crypto.createHmac('sha256', Buffer.from(String(cfg.accountKey || ''), 'base64')).update(toSign, 'utf8').digest('base64');
  h.authorization = `SharedKey ${cfg.account}:${signature}`;
  return h;
}

async function failure(res, what) {
  let text = '';
  try {
    text = (await res.text()).slice(0, 2000);
  } catch (err) {
    text = '';
  }
  const code = (/<Code>([^<]{1,64})<\/Code>/.exec(text) || [])[1] || null;
  const message = ((/<Message>([^<]{1,300})/.exec(text) || [])[1] || `the storage account said ${res.status}`).split('\n')[0];
  return storeError(`${what}: ${code ? `${code}, ` : ''}${message}`, res.status, code);
}

// md5 is hex here, base64 on the wire
async function put(cfg, key, { stream, size, md5 }) {
  if (!HEX32.test(String(md5 || ''))) throw storeError('an upload needs its md5', 400);
  if (!(Number.isSafeInteger(size) && size >= 0)) throw storeError('an upload needs its size', 400);
  const url = blobUrl(cfg, key);
  const headers = sign(cfg, 'PUT', url, {
    'content-length': size,
    'content-type': 'application/octet-stream',
    'content-md5': Buffer.from(md5, 'hex').toString('base64'),
    'x-ms-blob-type': 'BlockBlob'
  });
  const res = await safefetch.request(url, {
    method: 'PUT', headers, bodyStream: stream, bodyLength: size, noRedirects: true, timeoutMs: UPLOAD_TIMEOUT_MS, maxBytes: 64 * 1024
  });
  if (res.status !== 201) throw await failure(res, `uploading ${key}`);
}

async function head(cfg, key) {
  const url = blobUrl(cfg, key);
  const res = await safefetch.request(url, { method: 'HEAD', headers: sign(cfg, 'HEAD', url, {}), noRedirects: true, timeoutMs: 30000, maxBytes: 64 * 1024 });
  if (res.status === 404) return null;
  if (res.status !== 200) throw storeError(`checking ${key}: the storage account said ${res.status}`, res.status);
  const sum = res.headers.get('content-md5');
  const hex = sum ? Buffer.from(sum, 'base64').toString('hex') : null;
  return { size: Number(res.headers.get('content-length')), md5: HEX32.test(String(hex)) ? hex : null };
}

async function get(cfg, key, { maxBytes } = {}) {
  const url = blobUrl(cfg, key);
  const res = await safefetch.request(url, { method: 'GET', headers: sign(cfg, 'GET', url, {}), noRedirects: true, stream: true, timeoutMs: UPLOAD_TIMEOUT_MS, maxBytes });
  if (res.status === 404) {
    if (res.stream) res.stream.resume();
    return null;
  }
  if (res.status !== 200) {
    if (res.stream) res.stream.resume();
    throw storeError(`reading ${key}: the storage account said ${res.status}`, res.status);
  }
  return res.stream;
}

async function remove(cfg, key) {
  const url = blobUrl(cfg, key);
  const res = await safefetch.request(url, { method: 'DELETE', headers: sign(cfg, 'DELETE', url, {}), noRedirects: true, timeoutMs: 30000, maxBytes: 64 * 1024 });
  if (res.status !== 202 && res.status !== 200 && res.status !== 404) throw await failure(res, `deleting ${key}`);
}

const unxml = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

async function list(cfg, prefix, next) {
  const url = blobUrl(cfg, '', { restype: 'container', comp: 'list', prefix, maxresults: 1000, marker: next });
  const res = await safefetch.request(url, { method: 'GET', headers: sign(cfg, 'GET', url, {}), noRedirects: true, timeoutMs: 60000, maxBytes: 8 * 1024 * 1024 });
  if (res.status !== 200) throw await failure(res, 'listing the container');
  const text = await res.text();
  const keys = [...text.matchAll(/<Blob>\s*<Name>([^<]*)<\/Name>/g)].map((m) => unxml(m[1]));
  const marker = (/<NextMarker>([^<]+)<\/NextMarker>/.exec(text) || [])[1];
  return { keys, next: marker ? unxml(marker) : null };
}

// for a test stack. the app never makes containers on its own
async function createContainer(cfg) {
  const url = blobUrl(cfg, '', { restype: 'container' });
  const res = await safefetch.request(url, { method: 'PUT', headers: sign(cfg, 'PUT', url, { 'content-length': 0 }), noRedirects: true, timeoutMs: 30000, maxBytes: 64 * 1024 });
  if (res.status !== 201 && res.status !== 409) throw await failure(res, 'creating the container');
}

module.exports = { put, head, get, remove, list, createContainer, blobUrl, sign, CONTAINER, ACCOUNT };
