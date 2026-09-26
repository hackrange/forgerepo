// The Maven facing side. mvn's settings.xml mirror, gradle's maven { url } and sbt point at /maven/.
// Author: Tim Rice
// /maven/<group path>/<artifact>/maven-metadata.xml and /maven/<group path>/<artifact>/<version>/<file>, checksums too

const express = require('express');
const { wrap } = require('../../lib/http');
const mavenPath = require('../../ecosystems/maven/path');
const deploy = require('./deploy');
const front = require('./front');
const { serveMetadata, serveFile } = require('./serve');
const { record, text } = require('./respond');

const router = express.Router();

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.put(/.*/, wrap((req, res) => deploy.handlePut(req, res)));
router.delete(/.*/, (req, res) => deploy.handleOther(req, res));

router.get(/.*/, wrap(async (req, res) => {
  const asked = mavenPath.parse(req.path);
  if (asked && asked.kind === 'metadata') return serveMetadata(req, res, asked);
  if (asked && asked.kind === 'file') return serveFile(req, res, asked);
  // mvn asks for snapshot metadata of its own modules on every build. there are none here
  const why = asked && asked.kind === 'snapshot' ? 'snapshots are not served here, only releases' : 'no such Maven path';
  record(req, { action: 'error', status: 404, reason: why });
  return text(res, 404, 'not found');
}));

module.exports = router;
