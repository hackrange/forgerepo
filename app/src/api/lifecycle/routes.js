// Portal API, lifecycle stages of package versions.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const lifecycle = require('../../services/lifecycle');
const { STAGES } = require('../../policy/lifecycle');
const { ruleEcosystem } = require('../../policy/rulecheck');
const { toolsType } = require('../shared/tools-type');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { required } = require('../../lib/validate');

const router = express.Router();

// a stage is on one exact version, never a whole package
function targetOf(source) {
  const type = toolsType(ruleEcosystem(source.ecosystem));
  const typed = required(source.name, 214, 'package name');
  if (!type.validName(typed)) fail(400, type.badName);
  const version = required(source.version, 128, 'version');
  if (!type.validVersion(version)) fail(400, 'that is not a version of that kind of package');
  return { ecosystem: type.id, name: type.name(typed), version };
}

router.get(
  '/lifecycle',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json({ ...(await lifecycle.get(targetOf(req.query))), stages: STAGES, canMove: auth.can(req.user, 'rules:write') });
  })
);

router.get(
  '/lifecycle/counts',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json({ stages: STAGES, counts: await lifecycle.counts() });
  })
);

// approvers and admins, the people who already decide what gets served
router.post(
  '/lifecycle/move',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const moved = await lifecycle.move(actorOf(req), targetOf(body), { stage: String(body.stage || ''), from: body.from, reason: body.reason });
    res.json({ ok: true, ...moved });
  })
);

module.exports = router;
