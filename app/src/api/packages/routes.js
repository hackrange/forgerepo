// Portal API, packages seen.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const upstream = require('../../registry/npm/upstream');
const packages = require('../../services/packages');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { str, required, likeTerm, oneOf, paging } = require('../../lib/validate');
const { ruleEcosystem } = require('../../policy/rulecheck');

const router = express.Router();

router.get(
  '/packages',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const search = str(req.query.q, 200, 'search');
    const dir = oneOf(req.query.dir, ['asc', 'desc'], 'desc');
    // a type that is switched off is a 400, not an empty list that looks like nothing is cached
    const type = req.query.type ? ruleEcosystem(req.query.type, { mustBeOn: true }) : 'npm';
    const { rows, total } = await packages.list(search ? likeTerm(search) : null, { sort: req.query.sort, dir, limit, offset }, type);
    res.json({ type, packages: rows, total, page, limit });
  })
);

router.get(
  '/packages/versions',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const name = required(req.query.name, 214, 'package name');
    if (!upstream.validName(name)) fail(400, 'that is not a valid package name');
    res.json({ name, versions: await packages.versions(name) });
  })
);

router.post(
  '/packages/purge',
  auth.requirePerm('packages:purge'),
  wrap(async (req, res) => {
    const name = required(req.body.name, 214, 'package name');
    if (!upstream.validName(name)) fail(400, 'that is not a valid package name');
    await packages.purge(actorOf(req), name);
    res.json({ ok: true });
  })
);

module.exports = router;
