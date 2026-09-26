// Portal API, branding.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const branding = require('../../branding');
const log = require('../../logger');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');

const router = express.Router();

// ---------------------------------------------------------------- branding

router.get(
  '/branding',
  auth.requirePerm('settings:read'),
  wrap(async (req, res) => {
    res.json({ ...(await branding.current()), maxBytes: branding.MAX_BYTES, minSide: branding.MIN_SIDE, maxSide: branding.MAX_SIDE });
  })
);

router.put(
  '/branding/:kind',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    let saved;
    try {
      saved = await branding.save(req.params.kind, req.body && req.body.data, req.user.username);
    } catch (err) {
      if (!err.status) log.error('could not save a branding image', err.message);
      fail(err.status || 500, err.status ? err.message : 'the image could not be saved');
    }
    await auth.auditReq(req, 'branding.update', saved.kind, `${saved.type} ${saved.width}x${saved.height} ${saved.sha256.slice(0, 12)}`);
    res.json({ ok: true, ...saved });
  })
);

router.delete(
  '/branding/:kind',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    if (!branding.isKind(req.params.kind)) fail(404, 'there is no such image to reset');
    const removed = await branding.reset(req.params.kind);
    if (removed) await auth.auditReq(req, 'branding.reset', req.params.kind, null);
    res.json({ ok: true, reset: removed > 0 });
  })
);

module.exports = router;
