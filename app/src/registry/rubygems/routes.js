// The RubyGems facing side. gem sources, bundler's Gemfile source and BUNDLE_MIRROR point at /rubygems/.
// Author: Tim Rice
// the compact index (/versions, /info/<gem>), /gems/<file>.gem, /quick/Marshal.4.8/<file>.gemspec.rz, the full index files

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const serve = require('./serve');
const push = require('./push');
const { record, text } = require('./respond');

const router = express.Router();

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

// gem push, and the yank it never takes
router.post(/^\/api\/v1\/gems$/, wrap((req, res) => push.handlePush(req, res)));
router.delete(/^\/api\/v1\/gems\/yank$/, (req, res) => push.handleYank(req, res));

router.get(/^\/versions$/, wrap(serve.versions));
router.get(/^\/info\/([^/]+)$/, wrap((req, res) => serve.serveInfo(req, res, req.params[0])));
router.get(/^\/gems\/([^/]+\.gem)$/, wrap((req, res) => serve.serveFile(req, res, req.params[0], false)));
router.get(/^\/quick\/Marshal\.4\.8\/([^/]+\.gemspec\.rz)$/, wrap((req, res) => serve.serveFile(req, res, req.params[0], true)));
router.get(/^\/((?:latest_|prerelease_)?specs\.4\.8\.gz)$/, wrap((req, res) => serve.serveIndex(req, res, req.params[0])));

// the old dependency API and the name list are not offered, the compact index is what bundler uses first
router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such RubyGems endpoint' });
  return text(res, 404, 'not found');
});

module.exports = router;
