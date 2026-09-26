// Portal API, external registries.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const ecosystems = require('../../ecosystems');
const upstreams = require('../../services/upstreams');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/upstreams',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    const rows = await upstreams.list();
    res.json({
      upstreams: rows.map(upstreams.publicUpstream),
      writable: auth.can(req.user, 'settings:write'),
      ecosystems: ecosystems.enabled((k) => db.settings.getBool(k)).map((e) => ({ id: e.id, label: e.label })),
      labels: Object.fromEntries(ecosystems.ALL.map((e) => [e.id, e.label])),
      defaults: rows.filter((r) => r.is_default).map((r) => r.ecosystem || 'npm'),
      // the types whose registries are mirrors, and the advisory feeds each can take
      mirrors: require('../../registry/shared/mirror-options').FEEDS
    });
  })
);

router.post(
  '/upstreams',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const { id, note } = await upstreams.create(actorOf(req), req.body);
    res.json({ ok: true, id, note });
  })
);

router.put(
  '/upstreams/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const row = await upstreams.get(idParam(req.params.id));
    const changed = await upstreams.update(actorOf(req), row, req.body);
    res.json({ ok: true, changed });
  })
);

router.delete(
  '/upstreams/:id',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const row = await upstreams.get(idParam(req.params.id));
    const cached = await upstreams.remove(actorOf(req), row);
    res.json({
      ok: true,
      cached,
      note: cached
        ? `${cached} cached document(s) came from ${row.name}. They will not be served now that the name routes elsewhere, they get fetched again from wherever it points next.`
        : null
    });
  })
);

module.exports = router;
