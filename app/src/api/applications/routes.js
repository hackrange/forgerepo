// Portal API, applications and environments.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const labels = require('../../services/labels');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam } = require('../../lib/validate');

const router = express.Router();

// readable down to viewer on purpose (dropdowns, traffic filter). changing them is settings:write
for (const key of ['applications', 'environments']) {
  router.get(
    `/${key}`,
    auth.requirePerm('rules:read'),
    wrap(async (req, res) => {
      res.json({ entries: await labels.list(key), writable: auth.can(req.user, 'settings:write') });
    })
  );

  router.post(
    `/${key}`,
    auth.requirePerm('settings:write'),
    wrap(async (req, res) => {
      const id = await labels.create(actorOf(req), key, req.body);
      res.status(201).json({ ok: true, id });
    })
  );

  router.patch(
    `/${key}/:id`,
    auth.requirePerm('settings:write'),
    wrap(async (req, res) => {
      await labels.update(actorOf(req), key, idParam(req.params.id), req.body);
      res.json({ ok: true });
    })
  );

  router.delete(
    `/${key}/:id`,
    auth.requirePerm('settings:write'),
    wrap(async (req, res) => {
      await labels.remove(actorOf(req), key, idParam(req.params.id));
      res.json({ ok: true });
    })
  );
}

module.exports = router;
