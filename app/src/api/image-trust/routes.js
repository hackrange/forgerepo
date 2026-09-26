// Portal API, trust policies for image signatures.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const trust = require('../../services/image-trust');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/image-trust',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({ policies: await trust.list(), canChange: auth.can(req.user, 'settings:write') });
  })
);

router.post(
  '/image-trust',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    res.status(201).json({ ok: true, policy: await trust.add(actorOf(req), body) });
  })
);

router.delete(
  '/image-trust/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await trust.remove(actorOf(req), idParam(req.params.id));
    res.json({ ok: true });
  })
);

module.exports = router;
