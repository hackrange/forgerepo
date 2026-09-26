// Portal API, break glass keys.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const breakglass = require('../../services/breakglass');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam, required, intIn } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/acl/keys',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({ keys: await breakglass.keys(), enabled: db.settings.getBool('breakglass_enabled') });
  })
);

router.post(
  '/acl/keys',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const label = required(req.body.label, 128, 'label');
    const maxUses = intIn(req.body.max_uses, 0, 1000, 1);
    const grantMinutes = intIn(req.body.grant_minutes, 5, 1440, db.settings.getInt('breakglass_grant_minutes', 60));
    const days = intIn(req.body.expires_days, 0, 3650, 90);
    const made = await breakglass.create(actorOf(req), { label, maxUses, grantMinutes, days });
    // only time the uuid is ever visible. no pressure
    res.status(201).json({
      ok: true,
      id: made.id,
      uuid: made.uuid,
      note: 'write this down somewhere safe, it cannot be shown again'
    });
  })
);

router.delete(
  '/acl/keys/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const ended = await breakglass.remove(actorOf(req), idParam(req.params.id));
    res.json({ ok: true, grantsEnded: ended });
  })
);

router.get(
  '/acl/grants',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({ grants: await breakglass.grants() });
  })
);

router.post(
  '/acl/grants/revoke-all',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    res.json({ ok: true, revoked: await breakglass.revokeAll(actorOf(req)) });
  })
);

module.exports = router;
