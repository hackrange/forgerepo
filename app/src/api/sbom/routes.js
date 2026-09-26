// Portal API, SBOMs of cached files and of what an application downloaded.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const sbom = require('../../services/sbom');
const { wrap } = require('../../lib/http');
const { actorOf, audit } = require('../../lib/actor');
const { idParam, required, str } = require('../../lib/validate');
const { fail } = require('../../lib/errors');

const router = express.Router();

// always a download, never something a browser would render
function send(res, out) {
  res.set('content-type', out.format === 'spdx' ? 'application/spdx+json' : 'application/vnd.cyclonedx+json');
  res.set('content-disposition', `attachment; filename="${out.filename}"`);
  res.set('x-content-type-options', 'nosniff');
  res.send(JSON.stringify(out.doc, null, 2));
}

router.get(
  '/artifacts/:id/sbom',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    send(res, await sbom.forArtifact(idParam(req.params.id), req.query.format));
  })
);

// an image's contents, by tag or digest. the same permission as reading its dependency tree
router.get(
  '/sbom/image',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const repository = required(req.query.repository, 255, 'repository');
    const reference = required(req.query.reference, 200, 'tag or digest');
    const ociName = require('../../ecosystems/oci/name');
    if (!ociName.valid(repository)) fail(400, 'that is not an image repository name');
    if (!ociName.validTag(reference) && !ociName.isDigest(reference)) fail(400, 'give a tag or a sha256 digest');
    send(res, await sbom.forImage(repository, reference, req.query.format));
  })
);

// who took what is traffic data, so it needs what the Consumers page needs, and the export is audited
router.get(
  '/sbom/application',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const application = required(req.query.application, 128, 'application');
    const environment = str(req.query.environment, 128, 'environment');
    const out = await sbom.forApplication({ application, environment }, req.query.format);
    await audit(actorOf(req), 'sbom.export', `application:${application}${environment ? `/${environment}` : ''}`,
      `${out.format}, ${out.components} component(s)`);
    send(res, out);
  })
);

module.exports = router;
