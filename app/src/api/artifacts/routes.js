// Portal API, cached files.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const artifacts = require('../../services/artifacts');
const statuses = require('../../storage/artifacts');
const license = require('../../policy/licenses');
const provenance = require('../../policy/provenance');
const ecosystems = require('../../ecosystems');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, oneOf, paging } = require('../../lib/validate');
const { parseList } = require('../shared/json');
const properties = require('../../services/properties');
const { STAGES } = require('../../policy/lifecycle');

const router = express.Router();

router.get(
  '/artifacts',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const dir = oneOf(req.query.dir, ['asc', 'desc'], 'desc');
    const ecosystem = req.query.ecosystem ? String(req.query.ecosystem) : null;
    if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
    const status = oneOf(req.query.status, statuses.STATUSES, null);
    const search = str(req.query.q, 200, 'search');
    const licensed = oneOf(req.query.license, [...license.VERDICTS, 'unchecked'], null);
    const proven = oneOf(req.query.provenance, [...provenance.STATUSES, 'unchecked'], null);
    // owner, or owner=security
    const property = properties.parseFilter(str(req.query.property, 330, 'property'));
    const stage = oneOf(req.query.stage, STAGES, null);

    const found = await artifacts.list(
      { licensed, ecosystem, proven, status, search, property, stage },
      { sort: req.query.sort, dir, limit, offset },
      auth.can(req.user, 'cache:purge')
    );
    res.json({ ...found, page, limit });
  })
);

router.get(
  '/artifacts/:id',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const found = await artifacts.detail(idParam(req.params.id));
    res.json({ ...found, scans: found.scans.map((s) => ({ ...s, findings: parseList(s.findings) })) });
  })
);

router.post(
  '/artifacts/:id/provenance',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const result = await artifacts.checkProvenance(actorOf(req), req.params.id);
    res.json({ ok: true, status: result.status, reason: result.reason || null });
  })
);

router.post(
  '/artifacts/:id/verify',
  auth.requirePerm('cache:purge'),
  wrap(async (req, res) => {
    const ok = await artifacts.verify(actorOf(req), idParam(req.params.id));
    res.json({ ok });
  })
);

router.post(
  '/artifacts/:id/purge',
  auth.requirePerm('packages:purge'),
  wrap(async (req, res) => {
    await artifacts.purge(actorOf(req), idParam(req.params.id));
    res.json({ ok: true });
  })
);

module.exports = router;
