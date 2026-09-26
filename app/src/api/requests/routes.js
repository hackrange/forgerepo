// Portal API, approval requests: the list and asking for one.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const ecosystems = require('../../ecosystems');
const requests = require('../../services/requests');
const { ruleEcosystem, checkRange } = require('../../policy/rulecheck');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { required, boolFlag, oneOf, paging } = require('../../lib/validate');
const { toolsType } = require('../shared/tools-type');
const { ownerFor } = require('./owner');

const router = express.Router();

router.get(
  '/requests',
  auth.requirePerm('requests:read:own'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const status = oneOf(
      req.query.status,
      ['pending', 'approved', 'rejected', 'withdrawn', 'blocked'],
      null
    );
    const mine = boolFlag(req.query.mine, false);
    const ecosystem = req.query.ecosystem ? String(req.query.ecosystem) : null;
    if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
    const ownerId = mine ? req.user.id : ownerFor(req);
    const { rows, total } = await requests.list({ ownerId, ecosystem, status }, { limit, offset });
    res.json({ requests: rows, total, page, limit, canDecide: auth.can(req.user, 'requests:decide') });
  })
);

router.get(
  '/requests/vulnerabilities',
  auth.requirePerm('requests:read:own'),
  wrap(async (req, res) => {
    const ids = String(req.query.ids || '')
      .split(',')
      .map((n) => parseInt(n, 10))
      .filter((n) => Number.isInteger(n) && n > 0)
      .slice(0, 200);
    if (!ids.length) return res.json({ results: {} });
    res.json({ results: await requests.advisories(ids, ownerFor(req)) });
  })
);

router.post(
  '/requests',
  auth.requirePerm('requests:create'),
  wrap(async (req, res) => {
    const type = toolsType(ruleEcosystem(req.body.ecosystem, { mustBeOn: true }));
    const typed = required(req.body.package_name, 214, 'package name');
    if (!type.validName(typed)) fail(400, type.badName);
    const name = type.name(typed);
    const range = checkRange(req.body.version_range, type.id);
    const reason = required(req.body.reason, 1000, 'reason');

    const outcome = await requests.ask(actorOf(req), { type, name, range, reason });
    if (outcome.alreadyAllowed) {
      return res.status(409).json({ error: `${name} is already approved, you can install it now`, alreadyAllowed: true });
    }
    const checking = require('../../services/auto-approve').waitNote(type.id);
    if (outcome.bumped) return res.json({ ok: true, id: outcome.bumped, note: `You already had one open for this, it was bumped. ${checking}` });
    res.status(201).json({ ok: true, id: outcome.created, note: `Your request is in. ${checking}` });
  })
);

router.post(
  '/requests/bulk',
  auth.requirePerm('requests:create'),
  wrap(async (req, res) => {
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    if (!items.length) fail(400, 'nothing was ticked');
    if (items.length > 200) fail(400, 'that is over two hundred packages, ask for them in batches');
    const reason = required(req.body.reason, 1000, 'reason');
    const type = toolsType(ruleEcosystem(req.body.ecosystem, { mustBeOn: true }));
    const { created, bumped, skipped } = await requests.askMany(actorOf(req), { type, items, reason });
    res.json({ ok: true, created, bumped, skipped });
  })
);

module.exports = router;
