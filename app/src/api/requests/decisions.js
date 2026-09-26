// Portal API, deciding on requests.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const requests = require('../../services/requests');
const dependencies = require('../../services/dependencies');
const { ruleEcosystem } = require('../../policy/rulecheck');
const { toolsType } = require('../shared/tools-type');
const { checkRange } = require('../../policy/rulecheck');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, required, boolFlag } = require('../../lib/validate');
const { ownerFor } = require('./owner');

const router = express.Router();

const load = (req) => requests.load(idParam(req.params.id), ownerFor(req));

router.post(
  '/requests/:id/withdraw',
  auth.requirePerm('requests:withdraw:own'),
  wrap(async (req, res) => {
    await requests.withdraw(actorOf(req), await load(req));
    res.json({ ok: true });
  })
);

// what approving it brings in behind it. same limit as the tree walk, it is the same walk
router.get(
  '/requests/:id/dependencies',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const row = await load(req);
    const type = toolsType(ruleEcosystem(row.ecosystem, { mustBeOn: true }));
    const gate = await auth.rateLimit(`resolve:${req.user.id}`, 30, 10 * 60000);
    if (!gate.ok) fail(429, 'slow down a moment, that is a lot of tree walking');
    // what an image asked for is made of, from the first tag it names
    if (type.id === 'oci') {
      const first = String(row.version_range || '').split('||').map((s) => s.trim()).find((s) => s && !s.includes('*')) || 'latest';
      return res.json(await require('../../services/image-tree').tree(type, row.package_name, first, { scope: null, canScan: false, scan: false }));
    }
    res.json({ ...(await dependencies.forRequest(type, row)), approveClean: dependencies.enabled() && auth.can(req.user, 'rules:write') });
  })
);

router.post(
  '/requests/:id/approve',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const row = await load(req);
    if (row.status !== 'pending') fail(400, 'that request is already settled');

    const note = str(req.body.note, 1000, 'note');
    // no version = empty string, version_range isn't nullable
    const range = req.body.version_range !== undefined
      ? checkRange(req.body.version_range, row.ecosystem || 'npm')
      : (row.version_range || '');
    const addRule = boolFlag(req.body.add_rule, true);
    if (addRule && !auth.can(req.user, 'rules:write')) fail(403, 'your role cannot write rules');
    // checked before anything is approved, so a refusal here leaves the request as it was
    const withDependencies = boolFlag(req.body.with_dependencies, false);
    let type = null;
    if (withDependencies && (row.ecosystem || 'npm') === 'oci') fail(400, 'an image has no dependencies to approve along with it');
    if (withDependencies) {
      if (!addRule || !dependencies.enabled()) fail(400, 'approving dependencies along with a request is switched off in Settings');
      type = toolsType(ruleEcosystem(row.ecosystem, { mustBeOn: true }));
      const gate = await auth.rateLimit(`resolve:${req.user.id}`, 30, 10 * 60000);
      if (!gate.ok) fail(429, 'slow down a moment, that is a lot of tree walking');
    }

    await requests.approve(actorOf(req), row, { note, range, addRule });
    let deps = null;
    if (withDependencies) {
      // the request is approved either way, this only says what happened to the rest
      deps = await dependencies.approveForRequest(actorOf(req), type, row).catch((err) => {
        if (!err.status) require('../../logger').error(`approving the dependencies of request #${row.id} failed`, err.message);
        return { approved: 0, error: err.status ? err.message : 'the dependency tree could not be walked, so none of its packages were approved' };
      });
    }
    res.json({ ok: true, ruleAdded: addRule, dependencies: deps });
  })
);

router.post(
  '/requests/bulk-approve',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const raw = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (!raw.length) fail(400, 'nothing was selected');
    if (raw.length > 500) fail(400, 'that is over five hundred, do it in batches');
    const ids = [...new Set(raw.map(idParam))];

    const note = str(req.body.note, 1000, 'note');
    const addRule = boolFlag(req.body.add_rule, true);
    if (addRule && !auth.can(req.user, 'rules:write')) fail(403, 'your role cannot write rules');

    const rows = await require('../../db/repositories/requests').byIds(ids, ownerFor(req));
    const { approved, skipped } = await requests.approveMany(actorOf(req), ids, rows, { note, addRule });
    res.json({
      ok: true,
      affected: approved.length,
      ruleAdded: addRule,
      packages: approved.map((r) => r.package_name).slice(0, 50),
      skipped
    });
  })
);

router.post(
  '/requests/:id/block',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const row = await load(req);
    if (row.status !== 'pending') fail(400, 'that request is already settled');
    if (!auth.can(req.user, 'rules:write')) fail(403, 'your role cannot write rules');

    const note = required(req.body.note, 1000, 'reason for blocking it');
    const range = req.body.version_range !== undefined
      ? checkRange(req.body.version_range, row.ecosystem || 'npm')
      : (row.version_range || '');

    const blocked = await requests.block(actorOf(req), row, { note, range });
    res.json({ ok: true, blocked, ruleAdded: true });
  })
);

router.post(
  '/requests/:id/clear',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const id = idParam(req.params.id);
    await requests.load(id, ownerFor(req));
    const cleared = await requests.clear(actorOf(req), [id]);
    res.json({ ok: true, cleared: cleared.length });
  })
);

// tick box version
router.post(
  '/requests/bulk-clear',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const raw = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (raw.length > 1000) fail(400, 'that is over a thousand, do it in batches');
    const ids = [...new Set(raw.map(idParam))];
    if (!ids.length) fail(400, 'nothing was selected');
    // only what the caller could see. everyone who can decide sees all today, this keeps it that way if roles ever move
    const visible = await require('../../db/repositories/requests').byIds(ids, ownerFor(req), { brief: true });
    if (!visible.length) fail(404, 'none of those requests exist');
    const cleared = await requests.clear(actorOf(req), visible.map((r) => r.id));
    res.json({ ok: true, cleared: cleared.length, packages: cleared.map((r) => r.package_name).slice(0, 50) });
  })
);

router.post(
  '/requests/:id/reject',
  auth.requirePerm('requests:decide'),
  wrap(async (req, res) => {
    const row = await load(req);
    if (row.status !== 'pending') fail(400, 'that request is already settled');
    const note = required(req.body.note, 1000, 'reason for turning it down');
    await requests.reject(actorOf(req), row, note);
    res.json({ ok: true });
  })
);

module.exports = router;
