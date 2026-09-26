// Portal API, allow and deny rules.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const rules = require('../../services/rules');
const { ruleEcosystem, checkPattern, checkRange } = require('../../policy/rulecheck');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, boolFlag, intIn, oneOf, paging } = require('../../lib/validate');
const { ruleScope } = require('../shared/scope');
const { parseRuleFilters } = require('./filters');

const router = express.Router();

router.get(
  '/rules',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const dir = oneOf(req.query.dir, ['asc', 'desc'], 'desc');
    const filters = parseRuleFilters(req.query);
    const { rows, total } = await rules.list(filters, { sort: req.query.sort, dir, limit, offset });
    res.json({ rules: rows, total, page, limit });
  })
);

router.post(
  '/rules',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const body = req.body;
    const ecosystem = ruleEcosystem(body.ecosystem, { mustBeOn: true });
    const pattern = checkPattern(body.pattern, ecosystem);
    const kind = oneOf(body.kind, ['allow', 'deny'], null);
    if (!kind) fail(400, 'kind has to be allow or deny');
    const range = checkRange(body.version_range, ecosystem);
    const note = str(body.note, 512, 'note');
    const priority = intIn(body.priority, -1000, 1000, 0);
    const enabled = boolFlag(body.enabled, true) ? 1 : 0;
    const scope = await ruleScope(body);
    const rule = await rules.save(actorOf(req), { ecosystem, pattern, kind, range, note, priority, enabled, scope });
    res.status(201).json({ ok: true, rule });
  })
);

router.patch(
  '/rules/:id',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const existing = await rules.get(idParam(req.params.id));
    const patch = {
      // ecosystem is set in stone once written
      pattern: req.body.pattern !== undefined ? checkPattern(req.body.pattern, existing.ecosystem) : existing.pattern,
      kind: req.body.kind !== undefined ? oneOf(req.body.kind, ['allow', 'deny'], existing.kind) : existing.kind,
      version_range: req.body.version_range !== undefined ? checkRange(req.body.version_range, existing.ecosystem) : existing.version_range,
      note: req.body.note !== undefined ? str(req.body.note, 512, 'note') : existing.note,
      priority: req.body.priority !== undefined ? intIn(req.body.priority, -1000, 1000, 0) : existing.priority,
      enabled: req.body.enabled !== undefined ? (boolFlag(req.body.enabled, true) ? 1 : 0) : existing.enabled
    };
    const scope = await ruleScope(req.body, existing);
    patch.application_id = scope.app;
    patch.environment_id = scope.env;
    res.json({ ok: true, rule: await rules.update(actorOf(req), existing, patch) });
  })
);

router.delete(
  '/rules/:id',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    await rules.remove(actorOf(req), idParam(req.params.id));
    res.json({ ok: true });
  })
);

router.post(
  '/rules/bulk',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const kind = oneOf(req.body.kind, ['allow', 'deny'], null);
    if (!kind) fail(400, 'kind has to be allow or deny');
    const note = str(req.body.note, 512, 'note');
    const lines = String(req.body.patterns || '')
      .split(/[\r\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!lines.length) fail(400, 'nothing to add');
    if (lines.length > 2000) fail(400, 'that is more than 2000 lines, split it up');

    const ecosystem = ruleEcosystem(req.body.ecosystem, { mustBeOn: true });
    const scope = await ruleScope(req.body);
    const { added, skipped } = await rules.addMany(actorOf(req), { ecosystem, kind, note, scope, lines });
    res.json({ ok: true, added, skipped });
  })
);

// ids checked as ints, placeholders come from the count. no user input in the SQL
router.post(
  '/rules/actions',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const action = oneOf(req.body.action, ['delete', 'allow', 'deny', 'enable', 'disable'], null);
    if (!action) fail(400, 'pick delete, allow, deny, enable or disable');

    const raw = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (!raw.length) fail(400, 'nothing was selected');
    if (raw.length > 1000) fail(400, 'that is over a thousand rules, do it in batches');
    const ids = [...new Set(raw.map(idParam))];

    const { affected, skipped } = await rules.act(actorOf(req), action, ids);
    res.json({ ok: true, action, affected, skipped });
  })
);

module.exports = router;
