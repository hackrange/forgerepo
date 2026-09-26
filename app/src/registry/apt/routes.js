// The APT facing side. A sources.list line (or .sources file) points at /apt/<mirror>/.
// Author: Tim Rice
// dists/<suite>/InRelease (Release, Release.gpg), the files a Release lists (by path or by-hash), pool/..., and the
// box's own signing key at /apt/signing-key.asc

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const serve = require('./serve');
const { record, text } = require('./respond');

const router = express.Router();
const M = '([a-z0-9][a-z0-9-]{0,63})';
const SUITE = '([a-z0-9][a-z0-9._-]{0,63})';

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.get(/^\/signing-key\.asc$/, wrap(serve.signingKey));
router.get(new RegExp(`^/${M}/dists/${SUITE}/(InRelease|Release|Release\\.gpg)$`), wrap((req, res) => serve.withMirror(req, res, req.params[0], (q, r, up) => serve.releaseFile(q, r, up, req.params[1], req.params[2]))));
router.get(new RegExp(`^/${M}/dists/${SUITE}/([A-Za-z0-9._+~/-]{1,400})$`), wrap((req, res) => {
  if (req.params[2].split('/').includes('..')) return text(res, 404, 'not found');
  return serve.withMirror(req, res, req.params[0], (q, r, up) => serve.suiteFile(q, r, up, req.params[1], req.params[2]));
}));
router.get(new RegExp(`^/${M}/(pool/[A-Za-z0-9._+~/-]{1,400}\\.u?deb)$`), wrap((req, res) => {
  if (req.params[1].split('/').includes('..')) return text(res, 404, 'not found');
  return serve.withMirror(req, res, req.params[0], (q, r, up) => serve.pool(q, r, up, req.params[1]));
}));

router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such APT mirror path' });
  return text(res, 404, 'not found. A mirror hands out its dists and the packages its index lists, nothing else');
});

module.exports = router;
