// The blob store with a bucket behind it (S3 or Azure Blob). Local disk is the way in and the cache, the bucket is the copy that counts.
// Author: Tim Rice
//
// a new file lands on disk exactly like before, and the uploader sends it up with a checksum the bucket itself checks
// (sha256 for S3, md5 for Azure). only then is the local copy just a cache, and only then can eviction take it.
// a file that isn't on disk comes back down and is hashed against its sha256 before a single byte of it is served

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { PassThrough, Transform, Readable } = require('stream');
const { pipeline } = require('stream/promises');
const config = require('../config');
const db = require('../db');
const log = require('../logger');
const local = require('./local');
const s3 = require('./s3');
const azblob = require('./azblob');
const rows = require('../db/repositories/blobs');

const HEX64 = /^[0-9a-f]{64}$/;
const KINDS = ['s3', 'azure'];

function folder(value) {
  const prefix = String(value || '').replace(/^\/+/, '');
  return prefix && !prefix.endsWith('/') ? `${prefix}/` : prefix;
}

// settings for one kind of bucket, with the environment winning for the credentials
function settings(kind) {
  const which = kind || db.settings.get('storage_backend');
  if (which === 'azure') {
    const account = db.settings.get('az_account') || '';
    return {
      kind: 'azure',
      endpoint: db.settings.get('az_endpoint') || (account ? `https://${account}.blob.core.windows.net` : ''),
      account,
      container: db.settings.get('az_container') || '',
      prefix: folder(db.settings.get('az_prefix')),
      accountKey: config.storage.azureAccountKey || db.settings.get('az_account_key') || ''
    };
  }
  return {
    kind: 's3',
    endpoint: db.settings.get('s3_endpoint') || '',
    region: db.settings.get('s3_region') || 'us-east-1',
    bucket: db.settings.get('s3_bucket') || '',
    prefix: folder(db.settings.get('s3_prefix')),
    pathStyle: db.settings.getBool('s3_path_style'),
    accessKeyId: config.storage.s3AccessKeyId || db.settings.get('s3_access_key_id') || '',
    secretAccessKey: config.storage.s3SecretAccessKey || db.settings.get('s3_secret_access_key') || ''
  };
}

// what is still missing before this bucket can be used, or null
function missing(cfg) {
  if (cfg.kind === 'azure') {
    return cfg.endpoint && cfg.account && cfg.container && cfg.accountKey ? null : 'fill in the storage account, the container and the account key first';
  }
  return cfg.endpoint && cfg.bucket && cfg.accessKeyId && cfg.secretAccessKey ? null : 'fill in the endpoint, the bucket and both keys first';
}

const client = (cfg) => (cfg.kind === 'azure' ? azblob : s3);
const nameOf = (cfg) => (cfg.kind === 'azure' ? cfg.container : cfg.bucket);

function keyFor(cfg, sha256) {
  if (!HEX64.test(String(sha256 || ''))) throw new Error('that is not a sha256 digest');
  return `${cfg.prefix}blobs/sha256/${sha256.slice(0, 2)}/${sha256.slice(2, 4)}/${sha256}`;
}

async function md5OfFile(file) {
  const hash = crypto.createHash('md5');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

// the bucket's copy is whole: right size, and its checksum agrees when the bucket kept one
function whole(cfg, found, size, sums) {
  if (!found || found.size !== size) return false;
  if (cfg.kind === 'azure') return found.md5 === null || found.md5 === sums.md5;
  return found.sha256 === null || found.sha256 === sums.sha256;
}

// files someone is reading right now. eviction walks past them
const inUse = new Map();
function hold(sha256) {
  inUse.set(sha256, (inUse.get(sha256) || 0) + 1);
}
function letGo(sha256) {
  const n = (inUse.get(sha256) || 1) - 1;
  if (n > 0) inUse.set(sha256, n);
  else inUse.delete(sha256);
}

// ---------------------------------------------------------------- bringing a file back down

const fetching = new Map();

// the bucket's copy onto this disk, refused unless it hashes to its own name
function fetchToDisk(sha256) {
  if (fetching.has(sha256)) return fetching.get(sha256);
  const run = (async () => {
    if (await local.has(sha256)) return;
    const cfg = settings();
    const stream = await client(cfg).get(cfg, keyFor(cfg, sha256));
    if (!stream) {
      const e = new Error(`${sha256} is neither on this disk nor in the bucket`);
      e.code = 'ENOENT';
      throw e;
    }
    await local.init();
    const tmp = local.tmpFile();
    const hash = crypto.createHash('sha256');
    const hashing = new Transform({
      transform(chunk, enc, done) {
        hash.update(chunk);
        done(null, chunk);
      }
    });
    try {
      await pipeline(stream, hashing, fs.createWriteStream(tmp, { mode: 0o640 }));
      const got = hash.digest('hex');
      if (got !== sha256) {
        const e = new Error(`the bucket's copy of ${sha256} hashes to ${got}, not serving it`);
        e.code = 'EDIGEST';
        throw e;
      }
      await local.adoptTmp(tmp, sha256);
    } finally {
      await fsp.unlink(tmp).catch(() => {});
    }
  })();
  fetching.set(sha256, run);
  run.catch(() => {}).finally(() => fetching.delete(sha256));
  return run;
}

// ---------------------------------------------------------------- the store's usual calls

async function has(sha256, size) {
  if (await local.has(sha256, size)) return true;
  const row = await rows.location(sha256);
  return !!(row && Number(row.in_bucket) === 1 && (size === undefined || size === null || Number(row.size) === size));
}

async function stat(sha256) {
  const s = await local.stat(sha256);
  if (s) return s;
  const row = await rows.location(sha256);
  return row && Number(row.in_bucket) === 1 ? { size: Number(row.size), links: 0 } : null;
}

// straight off the disk when it is here, otherwise fetched, checked and then served from the disk
function open(sha256) {
  const file = local.blobPath(sha256);
  if (fs.existsSync(file)) {
    const now = new Date();
    // mtime is when it was last wanted, that's what eviction goes by
    fsp.utimes(file, now, now).catch(() => {});
    return local.open(sha256);
  }
  const out = new PassThrough();
  hold(sha256);
  fetchToDisk(sha256)
    .then(() => {
      const from = local.open(sha256);
      from.on('error', (err) => out.destroy(err));
      from.on('close', () => letGo(sha256));
      from.pipe(out);
    })
    .catch((err) => {
      letGo(sha256);
      log.error(`could not bring ${sha256} back from the bucket`, err.message);
      out.destroy(err);
    });
  return out;
}

async function verify(sha256) {
  if (await local.has(sha256)) return local.verify(sha256);
  try {
    const cfg = settings();
    const stream = await client(cfg).get(cfg, keyFor(cfg, sha256));
    if (!stream) return false;
    const hash = crypto.createHash('sha256');
    for await (const chunk of stream) hash.update(chunk);
    return hash.digest('hex') === sha256;
  } catch (err) {
    log.warn(`could not read ${sha256} back from the bucket to check it`, err.message);
    return false;
  }
}

// both copies. a bucket that can't be reached leaves an orphan, which costs space and nothing else
async function remove(sha256) {
  await local.remove(sha256);
  try {
    const cfg = settings();
    await client(cfg).remove(cfg, keyFor(cfg, sha256));
  } catch (err) {
    log.warn(`could not delete ${sha256} from the bucket, it stays there unused`, err.message);
  }
}

async function purgeAll() {
  await local.purgeAll();
  const cfg = settings();
  let next = null;
  let removed = 0;
  do {
    const page = await client(cfg).list(cfg, `${cfg.prefix}blobs/sha256/`, next);
    for (const key of page.keys) {
      await client(cfg).remove(cfg, key);
      removed += 1;
    }
    next = page.next;
  } while (next);
  if (removed) log.info(`emptied the bucket too, ${removed} file(s) deleted`);
}

async function withLocalCopy(sha256, fn) {
  hold(sha256);
  try {
    await fetchToDisk(sha256);
    return await fn(local.blobPath(sha256));
  } finally {
    letGo(sha256);
  }
}

// old cache folders stay as they are, a bucket has no hard links
async function keepLegacyCopy() {}

// ---------------------------------------------------------------- the uploader

// sends one blob up and makes sure the bucket has it whole. 'absent' = not on this node's disk, another node's job
async function upload(sha256) {
  const cfg = settings();
  const s = await local.stat(sha256);
  if (!s) return 'absent';
  const key = keyFor(cfg, sha256);
  const c = client(cfg);
  const sums = { sha256, md5: cfg.kind === 'azure' ? await md5OfFile(local.blobPath(sha256)) : null };
  if (!whole(cfg, await c.head(cfg, key), s.size, sums)) {
    await c.put(cfg, key, { stream: fs.createReadStream(local.blobPath(sha256)), size: s.size, sha256: sums.sha256, md5: sums.md5 });
    if (!whole(cfg, await c.head(cfg, key), s.size, sums)) throw new Error('the bucket does not hold the file it just accepted');
  }
  await rows.markUploaded(sha256);
  return 'uploaded';
}

let pass = null;

function uploaderStatus() {
  return pass ? { ...pass } : { running: false, uploaded: 0, failed: 0, absent: 0, startedAt: null, finishedAt: null, lastError: null };
}

// a batch at a time. a failure is noted on the blob and it goes to the back of the line
async function uploadWaiting({ batch = 200, maxBatches = 50 } = {}) {
  if (pass && pass.running) return uploaderStatus();
  pass = { running: true, uploaded: 0, failed: 0, absent: 0, startedAt: new Date().toISOString(), finishedAt: null, lastError: null };
  const seen = new Set();
  try {
    for (let b = 0; b < maxBatches; b += 1) {
      const waiting = (await rows.waitingForUpload(batch)).filter((r) => !seen.has(r.sha256));
      if (!waiting.length) break;
      for (const r of waiting) {
        seen.add(r.sha256);
        try {
          const how = await upload(r.sha256);
          if (how === 'uploaded') pass.uploaded += 1;
          else pass.absent += 1;
        } catch (err) {
          pass.failed += 1;
          pass.lastError = err.message;
          await rows.markUploadFailed(r.sha256, err.message).catch(() => {});
        }
      }
    }
  } finally {
    pass.running = false;
    pass.finishedAt = new Date().toISOString();
  }
  if (pass.uploaded || pass.failed) {
    log.info(`bucket upload: ${pass.uploaded} sent, ${pass.failed} failed${pass.lastError ? `, last error: ${pass.lastError}` : ''}`);
  }
  return uploaderStatus();
}

// ---------------------------------------------------------------- keeping the disk inside its limit

async function localBlobs() {
  const root = path.dirname(path.dirname(path.dirname(local.blobPath('0'.repeat(64)))));
  const out = [];
  let firsts = [];
  try {
    firsts = await fsp.readdir(root);
  } catch (err) {
    return out;
  }
  for (const a of firsts) {
    if (!/^[0-9a-f]{2}$/.test(a)) continue;
    let seconds = [];
    try {
      seconds = await fsp.readdir(path.join(root, a));
    } catch (err) {
      continue;
    }
    for (const b of seconds) {
      let names = [];
      try {
        names = await fsp.readdir(path.join(root, a, b));
      } catch (err) {
        continue;
      }
      for (const name of names) {
        if (!HEX64.test(name)) continue;
        try {
          const s = await fsp.stat(path.join(root, a, b, name));
          if (s.isFile()) out.push({ sha256: name, size: s.size, used: s.mtimeMs });
        } catch (err) {
          // gone meanwhile
        }
      }
    }
  }
  return out;
}

// oldest used first, and only copies the bucket already holds. a copy's old cache links go with it
async function evict(capBytes) {
  const files = await localBlobs();
  let total = files.reduce((n, f) => n + f.size, 0);
  const result = { before: total, after: total, removed: 0, freed: 0 };
  if (total <= capBytes) return result;
  files.sort((a, b) => a.used - b.used);
  const safe = await rows.inBucketOf(files.map((f) => f.sha256));
  const cacheRoot = path.resolve(config.cacheDir) + path.sep;
  for (const f of files) {
    if (total <= capBytes) break;
    if (!safe.has(f.sha256) || inUse.has(f.sha256)) continue;
    for (const { path: p } of await rows.legacyPaths(f.sha256)) {
      // only ever inside the cache directory
      if (p && path.resolve(p).startsWith(cacheRoot)) await fsp.unlink(p).catch(() => {});
    }
    await local.remove(f.sha256);
    total -= f.size;
    result.removed += 1;
    result.freed += f.size;
  }
  result.after = total;
  if (result.removed) log.info(`storage cache: dropped ${result.removed} local copy(ies) the bucket holds, ${Math.round(result.freed / 1048576)}MB freed`);
  return result;
}

// ---------------------------------------------------------------- is the bucket usable

// a small file up, read back, and removed again. every step has to work
async function check(cfg) {
  const started = Date.now();
  const body = Buffer.from(`forgerepo storage check ${crypto.randomBytes(12).toString('hex')}`);
  const sha256 = crypto.createHash('sha256').update(body).digest('hex');
  const md5 = crypto.createHash('md5').update(body).digest('hex');
  const key = `${cfg.prefix}forgerepo-check/${sha256}`;
  const c = client(cfg);
  await c.put(cfg, key, { stream: Readable.from([body]), size: body.length, sha256, md5 });
  const back = await c.get(cfg, key);
  const parts = [];
  if (back) for await (const chunk of back) parts.push(chunk);
  await c.remove(cfg, key);
  if (!Buffer.concat(parts).equals(body)) throw new Error('the bucket gave back different bytes from the ones sent');
  return { ok: true, ms: Date.now() - started };
}

module.exports = {
  kind: 'bucket', KINDS, settings, missing, nameOf, keyFor, has, stat, open, verify, remove, purgeAll, withLocalCopy, keepLegacyCopy,
  upload, uploadWaiting, uploaderStatus, evict, check, fetchToDisk
};
