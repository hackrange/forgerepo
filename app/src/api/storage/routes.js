// Portal API, where cached files are kept: what the bucket holds, a test, and running the uploader now.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const db = require('../../db');
const blobs = require('../../db/repositories/blobs');
const { wrap } = require('../../lib/http');
const { actorOf, audit } = require('../../lib/actor');
const { fail } = require('../../lib/errors');

const router = express.Router();

const CLOUDS = ['s3', 'azure'];
const backend = () => db.settings.get('storage_backend') || 'local';
const inBucketMode = () => CLOUDS.includes(backend());
const cacheBytes = () => db.settings.getInt('storage_cache_mb', 20480) * 1048576;

router.get(
  '/storage',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    const bucket = require('../../storage/bucket');
    // upload errors can name the endpoint, so only for people who could change it
    const failing = auth.can(req.user, 'settings:write')
      ? (await blobs.uploadErrors(5)).map((r) => ({ sha256: r.sha256, size: Number(r.size), attempts: Number(r.upload_attempts), error: r.upload_error }))
      : [];
    res.json({ backend: backend(), counts: await blobs.counts(), uploader: bucket.uploaderStatus(), failing });
  })
);

// the saved settings for one kind of bucket, put through a small file up, back and away again.
// kind lets azure be tested before switching to it
router.post(
  '/storage/test',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const limited = await auth.rateLimit(`storage-test:${req.user.id}`, 10, 60000);
    if (!limited.ok) fail(429, 'that is a lot of bucket tests, give it a minute');
    const asked = req.body && req.body.kind;
    if (asked !== undefined && !CLOUDS.includes(asked)) fail(400, 'the kind of bucket is s3 or azure');
    const kind = asked || (inBucketMode() ? backend() : 's3');
    const bucket = require('../../storage/bucket');
    const cfg = bucket.settings(kind);
    const missing = bucket.missing(cfg);
    if (missing) fail(400, missing);
    const name = bucket.nameOf(cfg);
    let result;
    try {
      result = await bucket.check(cfg);
    } catch (err) {
      await audit(actorOf(req), 'storage.test', `${kind}:${name}`, `failed: ${err.message}`.slice(0, 1000));
      // the settings are what's wrong, not this box. a 5xx would hide the reason behind "something went wrong"
      fail(400, `the bucket did not work: ${String(err.message).slice(0, 300)}`);
    }
    await audit(actorOf(req), 'storage.test', `${kind}:${name}`, `ok in ${result.ms}ms`);
    res.json({ ok: true, ms: result.ms, bucket: name, kind });
  })
);

// uploads and eviction now, instead of waiting for the timer
router.post(
  '/storage/sync',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    if (!inBucketMode()) fail(409, 'there is no bucket in use');
    const bucket = require('../../storage/bucket');
    const uploaded = await bucket.uploadWaiting();
    const cache = await bucket.evict(cacheBytes());
    await audit(actorOf(req), 'storage.sync', 'bucket', `${uploaded.uploaded} uploaded, ${uploaded.failed} failed, ${cache.removed} local copies dropped`);
    res.json({ uploaded, cache });
  })
);

module.exports = router;
