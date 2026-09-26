// Portal API, registry tokens.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const mail = require('../../integrations/mail');
const tokens = require('../../services/tokens');
const { LABELS, labelIdFor } = require('../../services/labels');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, required, boolFlag, intIn } = require('../../lib/validate');
const { refuseLabelsUnlessAdmin } = require('../applications/labels');

const router = express.Router();

router.get(
  '/tokens',
  auth.requirePerm('tokens:read:own'),
  wrap(async (req, res) => {
    const all = boolFlag(req.query.all, false) && auth.can(req.user, 'tokens:read:all');
    const rows = await tokens.list(all ? null : req.user.id);
    res.json({ tokens: rows, scope: all ? 'all' : 'mine', canSeeAll: auth.can(req.user, 'tokens:read:all') });
  })
);

router.post(
  '/tokens',
  auth.requirePerm('tokens:create:own'),
  wrap(async (req, res) => {
    const name = required(req.body.name, 128, 'token name');
    const days = intIn(req.body.expires_days, 0, 3650, 0);
    // optional. blocked install digest goes here, else to whoever minted it
    const email = String(req.body.email || '').trim();
    if (email && !mail.validAddress(email)) fail(400, `"${email}" is not an email address`);

    // app + env from the admin lists, stamped on every traffic row from now on.
    // rules can be scoped by them, so only an admin says which ones a token belongs to
    refuseLabelsUnlessAdmin(req);
    const applicationId = await labelIdFor(req.body.application_id, LABELS.applications);
    const environmentId = await labelIdFor(req.body.environment_id, LABELS.environments);

    const made = await tokens.mint(actorOf(req), { name, days, email, applicationId, environmentId });
    // shown once. blink and it's gone
    res.status(201).json({
      ok: true,
      id: made.id,
      token: made.token,
      note: 'copy this now, it is not stored and cannot be shown again'
    });
  })
);

// contact, app and env can change later without reissuing (and editing some .npmrc).
// only sent fields get touched; old traffic rows keep what was true then
router.put(
  '/tokens/:id',
  auth.requirePerm('tokens:create:own'),
  wrap(async (req, res) => {
    const id = idParam(req.params.id);
    const row = await tokens.get(id, auth.can(req.user, 'tokens:read:all') ? null : req.user.id);

    const sets = [];
    const done = [];
    if (req.body.email !== undefined) {
      const email = String(req.body.email || '').trim();
      if (email && !mail.validAddress(email)) fail(400, `"${email}" is not an email address`);
      sets.push(['email', email || null]);
      done.push(`contact ${email || 'cleared'}`);
    }
    refuseLabelsUnlessAdmin(req);
    if (req.body.application_id !== undefined) {
      const labeled = await labelIdFor(req.body.application_id, LABELS.applications);
      sets.push(['application_id', labeled]);
      done.push(labeled ? 'application set' : 'application cleared');
    }
    if (req.body.environment_id !== undefined) {
      const labeled = await labelIdFor(req.body.environment_id, LABELS.environments);
      sets.push(['environment_id', labeled]);
      done.push(labeled ? 'environment set' : 'environment cleared');
    }
    await tokens.relabel(actorOf(req), row, sets, done);
    res.json({ ok: true });
  })
);

router.delete(
  '/tokens/:id',
  auth.requirePerm('tokens:revoke:own'),
  wrap(async (req, res) => {
    const id = idParam(req.params.id);
    const row = await tokens.get(id, auth.can(req.user, 'tokens:revoke:all') ? null : req.user.id);
    await tokens.revoke(actorOf(req), row);
    res.json({ ok: true });
  })
);

module.exports = router;
