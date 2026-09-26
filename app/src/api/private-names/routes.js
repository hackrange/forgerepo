// Portal API, reserved names for private packages.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const privateNames = require('../../services/private-names');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam, str } = require('../../lib/validate');

const router = express.Router();

// anyone signed in, so a developer can see which names they could publish under
router.get(
  '/private-names',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json({ names: await privateNames.list(), canChange: auth.can(req.user, 'settings:write') });
  })
);

// what is kept away from upstreams is an admin decision
router.post(
  '/private-names',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const row = await privateNames.add(actorOf(req), {
      ecosystem: String(body.ecosystem || ''),
      pattern: str(body.pattern, 214, 'reserved name'),
      note: str(body.note, 1000, 'note')
    });
    res.status(201).json({ ok: true, name: row });
  })
);

router.delete(
  '/private-names/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await privateNames.remove(actorOf(req), idParam(req.params.id));
    res.json({ ok: true });
  })
);

module.exports = router;
