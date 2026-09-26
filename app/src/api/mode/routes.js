// Portal API, registry mode: normal, degraded, lockdown.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const mode = require('../../policy/mode');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');

const router = express.Router();

router.get(
  '/mode',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    res.json({ ...mode.describe(), canRaise: auth.can(req.user, 'rules:write'), canLower: auth.can(req.user, 'settings:write') });
  })
);

// approvers can raise it the moment an incident lands, like the kill switch. only admins bring it back down
router.put(
  '/mode',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const actor = actorOf(req);
    const now = await mode.set(String((req.body && req.body.mode) || ''), {
      reason: req.body && req.body.reason,
      user: actor.name,
      userId: actor.id,
      ip: actor.ip,
      canLower: auth.can(req.user, 'settings:write')
    });
    res.json({ ok: true, ...now });
  })
);

// auto approve takes a person out of the loop, so only an admin switches it, either way
router.put(
  '/auto-approve',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const actor = actorOf(req);
    const body = req.body || {};
    if (typeof body.on !== 'boolean') return res.status(400).json({ error: 'on is true or false' });
    try {
      const now = await require('../../services/auto-approve').set(body.on, { reason: body.reason, user: actor.name, userId: actor.id, ip: actor.ip });
      return res.json({ ok: true, ...now });
    } catch (err) {
      if (err.status) return res.status(err.status).json({ error: err.message });
      throw err;
    }
  })
);

module.exports = router;
