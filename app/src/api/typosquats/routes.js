// Portal API, lookalike packages.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const typosquats = require('../../services/typosquats');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam, oneOf } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/typosquats',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json(await typosquats.list(oneOf(req.query.status, ['open', 'dismissed'], 'open')));
  })
);

// approvers make the call, same as allowing a package
for (const [action, status] of [['dismiss', 'dismissed'], ['reopen', 'open']]) {
  router.post(
    `/typosquats/:id/${action}`,
    auth.requirePerm('rules:write'),
    wrap(async (req, res) => {
      await typosquats.setStatus(actorOf(req), idParam(req.params.id), action, status);
      res.json({ ok: true, status });
    })
  );
}

module.exports = router;
