// Portal API, cache housekeeping.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const cachekeep = require('../../cachekeep');
const { wrap } = require('../../lib/http');

const router = express.Router();

// ---------------------------------------------------------------- cache housekeeping (the chores)

// read only drift report, run whenever
router.post(
  '/cache/audit',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const started = cachekeep.startAudit(req.user.username);
    await auth.auditReq(req, 'cache.audit', null, null);
    res.status(202).json({ ok: true, job: started });
  })
);

// restores missing tarballs, clears orphans. no longer allowed = dropped, not refetched
router.post(
  '/cache/recache-missing',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const started = cachekeep.startRecacheMissing(req.user.username);
    await auth.auditReq(req, 'cache.recache', null, null);
    res.status(202).json({ ok: true, job: started });
  })
);

// removes cached tarballs the rules now block. dead weight, can never be served
router.post(
  '/cache/purge-blocked',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const started = cachekeep.startPurgeBlocked(req.user.username);
    await auth.auditReq(req, 'cache.purge.blocked', null, null);
    res.status(202).json({ ok: true, job: started });
  })
);

router.get(
  '/cache/maintenance',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    res.json({ ok: true, job: cachekeep.status() });
  })
);

router.post(
  '/cache/maintenance/cancel',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const job = cachekeep.cancel();
    await auth.auditReq(req, 'cache.maintenance.cancel', null, null);
    res.json({ ok: true, job });
  })
);

module.exports = router;
