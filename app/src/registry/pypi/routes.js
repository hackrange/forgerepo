// The PyPI facing side. pip, uv and poetry point here.
// Author: Tim Rice
// /pypi/simple/, /pypi/files/<project>/<filename>, /pypi/pypi/<project>/json

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const pages = require('./simple-pages');
const { serveFile } = require('./files');
const { serveJson } = require('./json-api');
const upload = require('./upload');
const { OURS, record, text } = require('./respond');

const router = express.Router();

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.post('/', wrap(upload.handleUpload));
router.get(/^\/simple\/?$/, wrap(pages.projectList));
router.get(/^\/simple\/([^/]+)\/?$/, wrap(pages.projectPage));
router.get(/^\/files\/([^/]+)\/([^/]+)$/, wrap(serveFile));
router.get(/^\/pypi\/([^/]+)\/(?:([^/]+)\/)?json\/?$/, wrap(serveJson));

router.get(OURS, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such PyPI endpoint' });
  return text(res, 404, 'not found');
});

module.exports = router;
