// Portal API, keys for the REST API. admins only, for everything including just looking.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const apiKeys = require('../../services/api-keys');
const spec = require('../v1/spec');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam } = require('../../lib/validate');

const router = express.Router();
const admin = auth.requirePerm('apikeys:manage');

// what the browser came in on. Host is trusted like everywhere else in the portal
const originOf = (req) => `${req.protocol}://${req.get('host')}`;

router.get('/api-keys', admin, wrap(async (req, res) => {
  // your_ip so the page can say what to add to try a key from this browser
  res.json({ keys: await apiKeys.list(), scopes: apiKeys.SCOPES, base: spec.BASE, operations: spec.consoleOps(), your_ip: auth.clientIp(req) });
}));

router.post('/api-keys', admin, wrap(async (req, res) => {
  const made = await apiKeys.create(actorOf(req), req.body || {});
  res.status(201).json({ ok: true, key: made.key, apiKey: made.apiKey });
}));

router.patch('/api-keys/:id', admin, wrap(async (req, res) => {
  res.json({ ok: true, apiKey: await apiKeys.update(actorOf(req), idParam(req.params.id), req.body || {}) });
}));

router.post('/api-keys/:id/revoke', admin, wrap(async (req, res) => {
  res.json({ ok: true, apiKey: await apiKeys.revoke(actorOf(req), idParam(req.params.id)) });
}));

// revoked first, the service says so if not
router.delete('/api-keys/:id', admin, wrap(async (req, res) => {
  await apiKeys.remove(actorOf(req), idParam(req.params.id));
  res.json({ ok: true });
}));

router.get('/api-keys/openapi.json', admin, (req, res) => {
  res.set('content-disposition', 'attachment; filename="forgerepo-openapi.json"');
  res.json(spec.openapi(originOf(req)));
});

router.get('/api-keys/postman.json', admin, (req, res) => {
  res.set('content-disposition', 'attachment; filename="forgerepo.postman_collection.json"');
  res.json(spec.postman(originOf(req)));
});

module.exports = router;
