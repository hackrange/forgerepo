// Portal API, server utilization.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const utilization = require('../../utilization');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { intIn } = require('../../lib/validate');

const router = express.Router();

// ---------------------------------------------------------------- utilization

router.get(
  '/utilization/live',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.set('cache-control', 'no-store');
    res.json(utilization.current(intIn(req.query.since, 0, Number.MAX_SAFE_INTEGER, 0)));
  })
);

router.get(
  '/utilization/history',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    const now = Date.now();
    const to = intIn(req.query.to, 0, now + 60000, now);
    const from = intIn(req.query.from, 0, now, to - 86400000);
    if (!(to > from)) fail(400, 'the end of the range has to be after the start');
    if (to - from > utilization.MAX_SPAN_MS) fail(400, 'that range is longer than the history kept, a year at most');
    res.json(await utilization.history(from, to));
  })
);

module.exports = router;
