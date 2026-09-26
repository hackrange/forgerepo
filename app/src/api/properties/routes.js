// Portal API, properties on packages and versions.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const properties = require('../../services/properties');
const { ruleEcosystem } = require('../../policy/rulecheck');
const { toolsType } = require('../shared/tools-type');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { str, required } = require('../../lib/validate');

const router = express.Router();

// which package, and which version of it. no version = the whole package
function targetOf(source) {
  const type = toolsType(ruleEcosystem(source.ecosystem));
  const typed = required(source.name, 214, 'package name');
  if (!type.validName(typed)) fail(400, type.badName);
  const version = str(source.version, 128, 'version') || '';
  if (version && !type.validVersion(version)) fail(400, 'that is not a version of that kind of package');
  return { ecosystem: type.id, name: type.name(typed), version };
}

router.get(
  '/properties/keys',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json({ keys: (await properties.keys()).map((r) => ({ key: r.k, uses: Number(r.n) })) });
  })
);

router.get(
  '/properties',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const target = targetOf(req.query);
    const own = await properties.list(target);
    // a version also shows what its package carries, marked as such
    const applies = target.version ? await properties.effective(target.ecosystem, target.name, target.version) : null;
    res.json({ ...own, effective: applies, canChange: auth.can(req.user, 'rules:write') });
  })
);

// the same people who write rules, since policy can come to lean on these
router.put(
  '/properties',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    res.json({ ok: true, ...(await properties.change(actorOf(req), targetOf(body), body)) });
  })
);

module.exports = router;
