// Portal API, quarantine holds.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const holdRules = require('../../policy/quarantine');
const ecosystems = require('../../ecosystems');
const quarantine = require('../../services/quarantine');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, likeTerm, oneOf, paging } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/quarantine',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const status = String(req.query.status || '') === 'all' ? null : oneOf(req.query.status, holdRules.STATUSES, 'open');
    const ecosystem = req.query.ecosystem ? String(req.query.ecosystem) : null;
    if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
    const search = str(req.query.q, 200, 'search');
    const found = await quarantine.list({ status, ecosystem, search: search ? likeTerm(search) : null }, { limit, offset });
    res.json({ ...found, page, limit });
  })
);

router.post(
  '/artifacts/:id/hold',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const placed = await quarantine.holdArtifact(actorOf(req), idParam(req.params.id), req.body.reason);
    res.status(placed.created ? 201 : 200).json({ ok: true, id: placed.id, created: placed.created });
  })
);

for (const action of ['release', 'reject']) {
  router.post(
    `/quarantine/:id/${action}`,
    auth.requirePerm('cache:purge'),
    wrap(async (req, res) => {
      const id = idParam(req.params.id);
      const noteText = quarantine.plainText(req.body.note, 'note', false);
      const h = await quarantine.resolve(actorOf(req), id, action, noteText);
      res.json({ ok: true, hold: h });
    })
  );
}

module.exports = router;
