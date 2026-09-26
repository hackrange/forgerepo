// The RPM facing side. A .repo file's baseurl points at /rpm/<mirror>/.
// Author: Tim Rice
// repodata/repomd.xml (and .asc), the metadata files it lists, and the packages its index lists

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const serve = require('./serve');
const { record, text } = require('./respond');

const router = express.Router();
const M = '([a-z0-9][a-z0-9-]{0,63})';

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.get(new RegExp(`^/${M}/repodata/repomd\\.xml$`), wrap((req, res) => serve.withMirror(req, res, req.params[0], serve.repomdXml)));
router.get(new RegExp(`^/${M}/repodata/repomd\\.xml\\.asc$`), wrap((req, res) => serve.withMirror(req, res, req.params[0], serve.repomdAsc)));
router.get(new RegExp(`^/${M}/repodata/([A-Za-z0-9._-]+)$`), wrap((req, res) => serve.withMirror(req, res, req.params[0], (q, r, up) => serve.metadata(q, r, up, req.params[1]))));
router.get(new RegExp(`^/${M}/([A-Za-z0-9._+~^/-]+\\.rpm)$`), wrap((req, res) => serve.withMirror(req, res, req.params[0], (q, r, up) => serve.pkg(q, r, up, req.params[1]))));

router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such RPM mirror path' });
  return text(res, 404, 'not found. A mirror hands out its repodata and the packages its index lists, nothing else');
});

module.exports = router;
