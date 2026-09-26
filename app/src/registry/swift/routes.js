// The Swift package registry facing side (SE-0292). swift package-registry set points SwiftPM at /swift/.
// Author: Tim Rice
// /<scope>/<name>, /<scope>/<name>/<version>, its Package.swift and .zip, /identifiers?url=, /login

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const serve = require('./serve');
const { record, problem } = require('./respond');

const router = express.Router();
const S = '([A-Za-z0-9][A-Za-z0-9-]{0,38})';
const N = '([A-Za-z0-9][A-Za-z0-9_-]{0,99})';
const V = '([0-9A-Za-z.+-]{1,128}?)';

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.get(/^\/identifiers$/, wrap(serve.identifiers));
router.all(/^\/login$/, serve.login);
router.post('/', serve.login);
router.get(new RegExp(`^/${S}/${N}(?:\\.json)?$`), wrap((req, res) => serve.listReleases(req, res, req.params[0], req.params[1])));
router.get(new RegExp(`^/${S}/${N}/${V}/Package\\.swift$`), wrap((req, res) => serve.manifest(req, res, req.params[0], req.params[1], req.params[2])));
router.get(new RegExp(`^/${S}/${N}/${V}\\.zip$`), wrap((req, res) => serve.archive(req, res, req.params[0], req.params[1], req.params[2])));
router.get(new RegExp(`^/${S}/${N}/${V}(?:\\.json)?$`), wrap((req, res) => serve.releaseInfo(req, res, req.params[0], req.params[1], req.params[2])));

router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such Swift registry endpoint' });
  return problem(res, 404, 'not found');
});

module.exports = router;
