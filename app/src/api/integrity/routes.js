// Portal API, integrity alerts.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const integrityRules = require('../../policy/integrity');
const ecosystems = require('../../ecosystems');
const integrity = require('../../services/integrity');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, likeTerm, oneOf, paging } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/integrity',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const status = String(req.query.status || '') === 'all' ? null : oneOf(req.query.status, integrityRules.STATUSES, 'open');
    const ecosystem = req.query.ecosystem ? String(req.query.ecosystem) : null;
    if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
    const search = str(req.query.q, 200, 'search');
    const found = await integrity.list({ status, ecosystem, search: search ? likeTerm(search) : null }, { limit, offset });
    res.json({ ...found, page, limit });
  })
);

router.get(
  '/integrity/:id',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    res.json(await integrity.detail(idParam(req.params.id)));
  })
);

for (const action of ['accept', 'dismiss']) {
  router.post(
    `/integrity/:id/${action}`,
    auth.requirePerm('cache:purge'),
    wrap(async (req, res) => {
      const id = idParam(req.params.id);
      const noteText = str(req.body.note, 1000, 'note');
      const ev = await integrity.resolve(actorOf(req), id, action, noteText);
      res.json({ ok: true, event: ev });
    })
  );
}

module.exports = router;
