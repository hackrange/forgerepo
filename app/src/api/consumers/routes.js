// Portal API, who consumed what.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const upstream = require('../../registry/npm/upstream');
const consumption = require('../../consumption');
const { ruleEcosystem, checkRange } = require('../../policy/rulecheck');
const pypiName = require('../../ecosystems/pypi/name');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { str } = require('../../lib/validate');

const router = express.Router();

// ---------------------------------------------------------------- consumers

// who took a package, version, file (by sha256) or advisory. the traffic page already shows all of this, row by row
router.get(
  '/consumers',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const asked = consumption.classify(str(req.query.q, 214, 'search'));
    if (!asked) fail(400, 'search for a package name, a sha256, or a CVE, GHSA or PYSEC id');
    if (asked.kind === 'package') {
      const ecosystem = ruleEcosystem(req.query.ecosystem);
      if (ecosystem === 'pypi') {
        if (!pypiName.valid(asked.name)) fail(400, 'that is not a valid PyPI project name, a sha256 or an advisory id');
        asked.name = pypiName.normalize(asked.name);
      } else if (ecosystem === 'oci') {
        const ociName = require('../../ecosystems/oci/name');
        if (!ociName.valid(asked.name)) fail(400, 'that is not an image name, a sha256 or an advisory id');
        asked.name = (await require('../../registry/oci/upstream').canonicalName(ociName.fold(asked.name))).name;
      } else if (require('../../registry/kinds').get(ecosystem)) {
        const kind = require('../../registry/kinds').get(ecosystem);
        if (!kind.validName(asked.name)) fail(400, `${kind.badName}, a sha256 or an advisory id`);
        asked.name = await kind.canonical(asked.name);
      } else if (!upstream.validName(asked.name)) {
        fail(400, 'that is not a valid npm package name, a sha256 or an advisory id');
      }
      asked.ecosystem = ecosystem;
      const version = str(req.query.version, 128, 'version');
      if (version) asked.version = checkRange(version, ecosystem);
    }
    res.json(await consumption.find(asked));
  })
);

module.exports = router;
