// Portal API, licenses.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const license = require('../../policy/licenses');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');

const router = express.Router();

// ---------------------------------------------------------------- licenses

router.get(
  '/licenses',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json(await license.summary());
  })
);

router.post(
  '/licenses/recheck',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    if (license.mode() === 'off') fail(409, 'license checks are switched off in Settings');
    await license.recheck();
    await auth.auditReq(req, 'license.recheck', 'everything', null);
    res.status(202).json({ ok: true, job: license.status() });
  })
);

module.exports = router;
