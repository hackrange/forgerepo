// Portal API, acting as another user.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');

const router = express.Router();

// ---------------------------------------------------------------- impersonation

// anyone acting as someone can stop, whatever that someone's role
router.post(
  '/impersonate/stop',
  wrap(async (req, res) => {
    if (!req.user.impersonator) fail(400, 'you are not acting as anyone');
    const admin = req.user.impersonator;
    const target = req.user.username;
    const back = await auth.stopImpersonation(req, res);
    await auth.audit(admin.id, admin.username, auth.clientIp(req), 'impersonate.end', target,
      back ? 'stopped' : 'stopped, and their own session had already ended');
    res.json({ ok: true, restored: !!back });
  })
);

module.exports = router;
