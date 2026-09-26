// The CocoaPods facing side. A Podfile's source and pod repo add-cdn point at /cocoapods/.
// Author: Tim Rice
// the CDN's CocoaPods-version.yml and shards, Specs/<a>/<b>/<c>/<pod>/<version>/<pod>.podspec.json, and archives/...

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const serve = require('./serve');
const { record, text } = require('./respond');

const router = express.Router();

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.get(/^\/CocoaPods-version\.yml$/, wrap(serve.versionFile));
router.get(/^\/(deprecated_podspecs|all_pods)\.txt$/, serve.emptyList);
router.get(/^\/(all_pods_versions_[0-9a-f_]+\.txt)$/, wrap((req, res) => serve.serveShard(req, res, req.params[0])));
router.get(/^\/Specs\/([0-9a-f])\/([0-9a-f])\/([0-9a-f])\/([^/]+)\/([^/]+)\/([^/]+)$/, wrap((req, res) => serve.servePodspec(req, res, [0, 1, 2, 3, 4, 5].map((i) => req.params[i]))));
router.get(/^\/archives\/([^/]+)\/([^/]+)\/([^/]+)$/, wrap((req, res) => serve.serveArchive(req, res, req.params[0], req.params[1], req.params[2])));

router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such CocoaPods endpoint' });
  return text(res, 404, 'not found');
});

module.exports = router;
