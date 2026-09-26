// What the storage settings may be: a bucket address that is safe to talk to, and nothing moving under files already up.
// Author: Tim Rice

const db = require('../db');
const ipacl = require('../security/network/ipacl');
const blobs = require('../db/repositories/blobs');
const { fail } = require('../lib/errors');
const { boolFlag, intIn, oneOf } = require('../lib/validate');

// the secret keys are checked with the other secrets, stars back mean keep them. the switch goes last, see settings.js
const KEYS = [
  's3_endpoint', 's3_region', 's3_bucket', 's3_prefix', 's3_path_style', 's3_access_key_id', 's3_secret_access_key',
  'az_endpoint', 'az_account', 'az_container', 'az_prefix', 'az_account_key',
  'storage_cache_mb', 'storage_backend'
];
const CLOUDS = ['s3', 'azure'];

// plain http to a bucket is only fine on your own network
function privateHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!host.includes('.') && !host.includes(':')) return true;
  if (/\.(internal|local|lan|home\.arpa)$/.test(host)) return true;
  const ip = ipacl.parseIp(host);
  if (!ip) return false;
  return ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'].some((range) => {
    const cidr = ipacl.parseCidr(range);
    return cidr && ipacl.cidrContains(cidr, ip);
  });
}

// once files are in the bucket in use, where it is can't change under them. the other cloud's fields are free
async function guardBucketMove(key, value) {
  if (value === (db.settings.get(key) || '')) return;
  const inUse = db.settings.get('storage_backend');
  if (key.startsWith('s3_') && inUse !== 's3') return;
  if (key.startsWith('az_') && inUse !== 'azure') return;
  if (await blobs.anyInBucket()) {
    fail(409, 'files are already in the bucket, so where it is cannot change. Empty the cache first if it really has to move');
  }
}

// an address, https unless it is on your own network. withPath lets an emulator keep its /account part
function endpoint(value, withPath) {
  value = String(value || '').trim().replace(/\/+$/, '');
  if (!value) return '';
  let u = null;
  try {
    u = new URL(value);
  } catch (err) {
    u = null;
  }
  if (!u || !['http:', 'https:'].includes(u.protocol)) fail(400, 'the storage endpoint has to be an http or https url');
  if (u.username || u.password) fail(400, 'put the keys in their own fields, not in the endpoint');
  if (u.search || u.hash || (!withPath && u.pathname && u.pathname !== '/')) {
    fail(400, 'the endpoint is only the address, like https://s3.eu-west-1.amazonaws.com');
  }
  // signed requests and every file would cross the wire readable
  if (u.protocol === 'http:' && !privateHost(u.hostname)) fail(400, 'use https for storage that is not on your own network');
  return withPath ? `${u.origin}${u.pathname.replace(/\/+$/, '')}` : u.origin;
}

function prefix(value) {
  value = String(value || '').trim().replace(/^\/+/, '');
  if (value && (value.length > 200 || !/^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*\/?$/.test(value) || value.split('/').includes('..'))) {
    fail(400, 'the folder is letters, digits, dots, dashes and underscores, split by /');
  }
  return value && !value.endsWith('/') ? `${value}/` : value;
}

async function check(key, rawValue) {
  let value = rawValue;
  switch (key) {
    case 'storage_backend': {
      value = oneOf(value, ['local', ...CLOUDS], null);
      if (!value) fail(400, 'cached files are kept on local disk, in s3 or in azure');
      const now = db.settings.get('storage_backend') || 'local';
      if (value === now) break;
      if (now !== 'local' && (await blobs.anyInBucket())) {
        fail(409, value === 'local'
          ? 'files are already in the bucket and some may only be there, so this box cannot go back to local disk on its own'
          : 'files are already in the bucket, so this box cannot move to another kind of storage on its own');
      }
      if (CLOUDS.includes(value)) {
        // the bucket fields were saved just before this in the same request, the switch always goes last
        const bucket = require('../storage/bucket');
        const cfg = bucket.settings(value);
        const missing = bucket.missing(cfg);
        if (missing) fail(400, `${missing} before switching to ${value}`);
        try {
          await bucket.check(cfg);
        } catch (err) {
          fail(400, `the bucket did not work, so nothing was switched: ${String(err.message).slice(0, 300)}`);
        }
      }
      break;
    }
    case 's3_endpoint':
      value = endpoint(value, false);
      await guardBucketMove(key, value);
      break;
    case 'az_endpoint':
      value = endpoint(value, true);
      await guardBucketMove(key, value);
      break;
    case 's3_region':
      value = String(value || '').trim() || 'us-east-1';
      if (!/^[a-z0-9-]{1,32}$/.test(value)) fail(400, 'the region looks like us-east-1 or eu-west-2');
      break;
    case 's3_bucket':
      value = String(value || '').trim();
      if (value && !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value)) fail(400, 'a bucket name is 3 to 63 lowercase letters, digits, dots and dashes');
      await guardBucketMove(key, value);
      break;
    case 'az_account':
      value = String(value || '').trim();
      if (value && !/^[a-z0-9]{3,24}$/.test(value)) fail(400, 'a storage account name is 3 to 24 lowercase letters and digits');
      await guardBucketMove(key, value);
      break;
    case 'az_container':
      value = String(value || '').trim();
      if (value && !/^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$/.test(value)) fail(400, 'a container name is 3 to 63 lowercase letters, digits and single dashes');
      await guardBucketMove(key, value);
      break;
    case 's3_prefix':
    case 'az_prefix':
      value = prefix(value);
      await guardBucketMove(key, value);
      break;
    case 's3_path_style':
      value = boolFlag(value, false) ? '1' : '0';
      break;
    case 's3_access_key_id':
      value = String(value || '').trim();
      if (value.length > 128 || /[^!-~]/.test(value)) fail(400, 'the access key id is one word of plain characters');
      break;
    case 'storage_cache_mb':
      value = String(intIn(value, 0, 10000000, 20480));
      break;
    default:
      fail(400, `${String(key).slice(0, 40)} is not a storage setting`);
  }
  return value;
}

module.exports = { KEYS, CLOUDS, check, privateHost };
