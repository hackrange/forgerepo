// @ts-check
// AWS Signature Version 4, for S3 and everything that speaks it (MinIO, R2, Wasabi and friends).
// Author: Tim Rice
//
// node crypto and nothing else. the secret key only ever goes into the HMAC, never into a header

const crypto = require('crypto');

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
// streamed bodies can't be hashed up front. fine over https, the bucket checks x-amz-checksum-sha256 instead
const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

/** @param {crypto.BinaryLike} key @param {string} data */
function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

/** @param {string} data */
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

// RFC 3986, which is stricter than encodeURIComponent about !'()*
/** @param {string} value */
function encode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** @param {Date} date */
function amzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

/** @param {URL} u */
function canonicalPath(u) {
  return u.pathname.split('/').map((part) => encode(decodeURIComponent(part))).join('/') || '/';
}

/** @param {URL} u */
function canonicalQuery(u) {
  return [...u.searchParams.entries()]
    .map(([k, v]) => [encode(k), encode(v)])
    .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
}

/**
 * The headers to send, authorization included.
 * @param {{ method: string, url: string, region: string, service?: string, accessKeyId: string, secretAccessKey: string,
 *   headers?: Record<string, string | number>, payloadHash?: string, date?: Date }} req
 * @returns {Record<string, string>}
 */
function sign(req) {
  const u = new URL(req.url);
  const stamp = amzDate(req.date || new Date());
  const day = stamp.slice(0, 8);
  const service = req.service || 's3';
  const payloadHash = req.payloadHash || UNSIGNED_PAYLOAD;

  /** @type {Record<string, string>} */
  const all = {};
  for (const [k, v] of Object.entries(req.headers || {})) all[k.toLowerCase()] = String(v);
  all.host = u.host;
  all['x-amz-date'] = stamp;
  all['x-amz-content-sha256'] = payloadHash;

  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map((n) => `${n}:${all[n].trim().replace(/\s+/g, ' ')}\n`).join('');
  const signedHeaders = names.join(';');
  const canonical = [req.method.toUpperCase(), canonicalPath(u), canonicalQuery(u), canonicalHeaders, signedHeaders, payloadHash].join('\n');

  const scope = `${day}/${req.region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', stamp, scope, sha256Hex(canonical)].join('\n');
  const key = hmac(hmac(hmac(hmac(`AWS4${req.secretAccessKey}`, day), req.region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', key).update(toSign, 'utf8').digest('hex');

  // host is set by the http client from the url, sending it twice upsets some proxies
  const { host, ...out } = all;
  out.authorization = `AWS4-HMAC-SHA256 Credential=${req.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return out;
}

module.exports = { sign, EMPTY_SHA256, UNSIGNED_PAYLOAD, encode };
