// Portal API, email.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const mail = require('../../integrations/mail');
const email = require('../../services/email');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { paging } = require('../../lib/validate');

const router = express.Router();

// works with the switch off on purpose, test BEFORE turning it on
router.post(
  '/email/test',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const to = String(req.body.to || req.user.email || '').trim();
    if (!to) fail(400, 'nowhere to send it, put an address in or set one on your account');
    if (!mail.validAddress(to)) fail(400, `"${to}" is not an email address`);
    await email.sendTest(actorOf(req), to);
    res.json({ ok: true, to });
  })
);

// digest now. same marks as the hourly run, so button mashing won't double send
router.post(
  '/email/digest/run',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const result = await email.runDigest(actorOf(req));
    res.json({ ok: !result.error, ...result });
  })
);

// what got sent and what didn't. half the 'it never arrived' answer
router.get(
  '/email/log',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const { rows, total } = await email.log({ limit, offset });
    res.json({ entries: rows, total, page, limit });
  })
);

module.exports = router;
