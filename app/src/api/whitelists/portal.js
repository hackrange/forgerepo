// Portal API, portal allow list.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const ipacl = require('../../security/network/ipacl');
const allowlists = require('../../services/allowlists');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, required, boolFlag } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/acl',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({
      acl: await allowlists.list('portal'),
      enabled: db.settings.getBool('acl_enabled'),
      yourIp: auth.clientIp(req)
    });
  })
);

router.post(
  '/acl',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const raw = required(req.body.cidr, 64, 'network');
    const cidr = ipacl.normalizeCidr(raw);
    if (!cidr) fail(400, `"${raw}" is not an address or a network, try 10.0.0.0/8 or 203.0.113.7`);
    const label = str(req.body.label, 128, 'label');
    await allowlists.add(actorOf(req), 'portal', { cidr, label });
    res.status(201).json({ ok: true, cidr });
  })
);

router.patch(
  '/acl/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await allowlists.setEnabled(actorOf(req), 'portal', idParam(req.params.id), boolFlag(req.body.enabled, true) ? 1 : 0);
    res.json({ ok: true });
  })
);

router.delete(
  '/acl/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    await allowlists.remove(actorOf(req), 'portal', idParam(req.params.id));
    res.json({ ok: true });
  })
);

module.exports = router;
