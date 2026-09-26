// Portal API, safe version resolution log.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const ecosystems = require('../../ecosystems');
const resolutions = require('../../services/resolutions');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { str, likeTerm, paging } = require('../../lib/validate');
const { parseList } = require('../shared/json');

const router = express.Router();

router.get(
  '/resolutions',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const ecosystem = req.query.ecosystem ? String(req.query.ecosystem) : null;
    if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');
    const search = str(req.query.q, 200, 'search');
    const application = str(req.query.application, 128, 'application');
    const environment = str(req.query.environment, 128, 'environment');

    const found = await resolutions.list(
      { ecosystem, search: search ? likeTerm(search) : null, application, environment },
      { limit, offset }
    );
    res.json({
      resolutions: found.rows.map((r) => ({ ...r, excluded: parseList(r.excluded) })),
      total: found.total,
      enabled: found.enabled,
      threshold: found.threshold,
      page,
      limit
    });
  })
);

module.exports = router;
