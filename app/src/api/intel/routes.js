// Portal API, vulnerability intel: how the CISA KEV and FIRST EPSS feeds last went, and fetching them now.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const intel = require('../../integrations/intel');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');

const router = express.Router();

router.get(
  '/intel',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    res.json(await intel.status());
  })
);

// an admin can ask for it now. it waits for both feeds, which takes a minute on a box with many CVEs
router.post(
  '/intel/sync',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const gate = await auth.rateLimit(`intel:${req.user.id}`, 6, 60 * 60000);
    if (!gate.ok) fail(429, 'those feeds were fetched a lot just now, give them a while');
    await auth.auditReq(req, 'intel.sync', null, null);
    const result = await intel.sync(req.user.username);
    res.json({ ok: true, ...result, status: await intel.status() });
  })
);

module.exports = router;
