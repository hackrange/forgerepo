// The Composer facing side. A composer.json repository of type composer points at /composer/.
// Author: Tim Rice
// packages.json, p2/<vendor>/<name>.json (and ~dev, which is refused), dists/<vendor>/<name>/<version>/<file>.zip

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const serve = require('./serve');
const { record, text } = require('./respond');

const router = express.Router();
const V = '([a-z0-9]([_.-]?[a-z0-9]+)*)';
const N = '([a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*)';

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.get(/^\/packages\.json$/, serve.root);
router.get(new RegExp(`^/p2/${V}/${N}~dev\\.json$`), serve.devFile);
router.get(new RegExp(`^/p2/${V}/${N}\\.json$`), wrap((req, res) => serve.metadata(req, res, `${req.params[0]}/${req.params[2]}`)));
router.get(new RegExp(`^/dists/${V}/${N}/([^/]{1,128})/([^/]{1,300})$`), wrap((req, res) => serve.archive(req, res, `${req.params[0]}/${req.params[2]}`, req.params[5], req.params[6])));

router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such Composer endpoint' });
  return text(res, 404, 'not found');
});

module.exports = router;
