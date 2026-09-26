// Portal API, users.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const users = require('../../services/users');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/users',
  auth.requirePerm('users:read'),
  wrap(async (req, res) => {
    res.json({ users: await users.list(), roles: auth.ROLES });
  })
);

router.post(
  '/users',
  auth.requirePerm('users:write'),
  wrap(async (req, res) => {
    const user = await users.create(actorOf(req), req.body);
    res.status(201).json({ ok: true, user });
  })
);

router.patch(
  '/users/:id',
  auth.requirePerm('users:write'),
  wrap(async (req, res) => {
    const user = await users.update(actorOf(req), idParam(req.params.id), req.body);
    res.json({ ok: true, user });
  })
);

router.delete(
  '/users/:id',
  auth.requirePerm('users:write'),
  wrap(async (req, res) => {
    await users.remove(actorOf(req), idParam(req.params.id));
    res.json({ ok: true });
  })
);

// act as someone for a while. never an admin, never yourself, never from inside another one
router.post(
  '/users/:id/impersonate',
  auth.requirePerm('users:write'),
  wrap(async (req, res) => {
    if (req.user.impersonator) fail(403, 'stop acting as someone before starting again');
    const target = await users.impersonationTarget(actorOf(req), idParam(req.params.id));
    await auth.auditReq(req, 'impersonate.start', target.username, `role ${target.role}, for ${auth.IMPERSONATE_MINUTES} minutes at most`);
    const started = await auth.startImpersonation(req, res, target);
    res.json({ ok: true, user: target.username, role: target.role, minutes: started.minutes });
  })
);

module.exports = router;
