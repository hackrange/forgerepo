// Portal API, webhooks, Splunk and syslog.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const events = require('../../integrations/events');
const integrations = require('../../services/integrations');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam } = require('../../lib/validate');

const router = express.Router();

const load = (req) => integrations.get(idParam(req.params.id));

router.get(
  '/integrations',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({ entries: await integrations.list(), events: events.EVENTS, writable: auth.can(req.user, 'settings:write') });
  })
);

router.post(
  '/integrations',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const id = await integrations.create(actorOf(req), req.body);
    res.status(201).json({ ok: true, id });
  })
);

router.patch(
  '/integrations/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await integrations.update(actorOf(req), await load(req), req.body);
    res.json({ ok: true });
  })
);

router.delete(
  '/integrations/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await integrations.remove(actorOf(req), await load(req));
    res.json({ ok: true });
  })
);

router.post(
  '/integrations/:id/test',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    res.json(await integrations.sendTest(actorOf(req), req.params.id));
  })
);

router.get(
  '/integrations/:id/deliveries',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({ entries: await integrations.deliveries(await load(req)) });
  })
);

router.post(
  '/integrations/:id/retry',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const retried = await integrations.retry(actorOf(req), await load(req));
    res.json({ ok: true, retried });
  })
);

module.exports = router;
