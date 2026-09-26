// Portal API, settings.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const settings = require('../../services/settings');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');

const router = express.Router();

router.get(
  '/settings',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json(settings.view(auth.can(req.user, 'settings:write')));
  })
);

router.put(
  '/settings',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const incoming = req.body && typeof req.body === 'object' ? req.body : {};
    const { changed, fetchingGithub } = await settings.save(actorOf(req), incoming);
    res.json({ ok: true, changed, fetchingGithub });
  })
);

module.exports = router;
