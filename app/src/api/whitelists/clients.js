// Portal API, registry client allow list.
// Author: Tim Rice
// same as the portal list but no lockout guard, this one doesn't gate the portal

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const ipacl = require('../../security/network/ipacl');
const ghmeta = require('../../security/network/github-ranges');
const allowlists = require('../../services/allowlists');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, required, boolFlag } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/registry-acl',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({
      acl: await allowlists.list('registry'),
      enabled: db.settings.getBool('registry_acl_enabled'),
      tokenOk: db.settings.getBool('registry_acl_token_ok'),
      github: await ghmeta.status(),
      yourIp: auth.clientIp(req)
    });
  })
);

// fetch GitHub ranges now, and wait for it (someone's staring at the button)
router.post(
  '/registry-acl/github/refresh',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    if (!db.settings.getBool('registry_acl_github')) fail(400, 'switch the GitHub feed on first');
    const result = await ghmeta.sync(req.user.username);
    await auth.auditReq(req, 'registry.acl.github', result.ok ? 'fetched' : 'failed', result.error || `${result.ranges} network(s)`);
    if (!result.ok) fail(502, `could not fetch the github ranges: ${result.error}`);
    res.json({ ok: true, ranges: result.ranges, changed: result.changed });
  })
);

router.post(
  '/registry-acl',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const raw = required(req.body.cidr, 64, 'network');
    const cidr = ipacl.normalizeCidr(raw);
    if (!cidr) fail(400, `"${raw}" is not an address or a network, try 10.0.0.0/8 or 203.0.113.7`);
    const label = str(req.body.label, 128, 'label');
    await allowlists.add(actorOf(req), 'registry', { cidr, label });
    res.status(201).json({ ok: true, cidr });
  })
);

router.patch(
  '/registry-acl/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await allowlists.setEnabled(actorOf(req), 'registry', idParam(req.params.id), boolFlag(req.body.enabled, true) ? 1 : 0);
    res.json({ ok: true });
  })
);

router.delete(
  '/registry-acl/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await allowlists.remove(actorOf(req), 'registry', idParam(req.params.id));
    res.json({ ok: true });
  })
);

module.exports = router;
