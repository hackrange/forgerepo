// Portal API, allow and deny rules.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const rules = require('../../services/rules');
const { ruleEcosystem, checkPattern, checkRange, checkExpiry } = require('../../policy/rulecheck');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, boolFlag, intIn, oneOf, paging } = require('../../lib/validate');
const { ruleScope } = require('../shared/scope');
const { parseRuleFilters } = require('./filters');
const rulesRepo = require('../../db/repositories/rules');

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
    const expires = checkExpiry(body.expires_at, { future: true });
    const scope = await ruleScope(body);
    const rule = await rules.save(actorOf(req), { ecosystem, pattern, kind, range, note, priority, enabled, expires, scope });
    res.status(201).json({ ok: true, rule });
  })
);

// the findings behind one red version. the version has to be one the rule pins, nothing else gets looked up
router.get(
  '/rules/:id/advisories',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const rule = await rules.get(idParam(req.params.id));
    const version = str(req.query.version, 128, 'version');
    const pins = String(rule.version_range || '').split(' || ').map((v) => v.trim());
    if (!version || !pins.includes(version)) fail(400, 'that version is not one this rule pins');
    res.json({ rule: { id: rule.id, ecosystem: rule.ecosystem, pattern: rule.pattern, version_range: rule.version_range }, version,
      advisories: await rulesRepo.advisoriesFor(rule, version) });
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
      enabled: req.body.enabled !== undefined ? (boolFlag(req.body.enabled, true) ? 1 : 0) : existing.enabled,
      expires_ts: existing.expires_ts === null || existing.expires_ts === undefined ? null : Number(existing.expires_ts)
    };
    // blank clears it. a new date has to be ahead of us, the one it already had can stay put even if it's gone by
    if (req.body.expires_at !== undefined) {
      const asked = checkExpiry(req.body.expires_at);
      patch.expires_ts = asked === null || asked === patch.expires_ts ? asked : checkExpiry(req.body.expires_at, { future: true });
    }
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
    const expires = checkExpiry(req.body.expires_at, { future: true });
    const scope = await ruleScope(req.body);
    const { added, skipped } = await rules.addMany(actorOf(req), { ecosystem, kind, note, expires, scope, lines });
    res.json({ ok: true, added, skipped });
  })
);

// ids checked as ints, placeholders come from the count. no user input in the SQL
router.post(
  '/rules/actions',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const action = oneOf(req.body.action, ['delete', 'allow', 'deny', 'enable', 'disable', 'extend', 'expire'], null);
    if (!action) fail(400, 'pick delete, allow, deny, enable, disable, extend or expire');
    // expire = put this date on them, permanent ones included. has to be ahead of us, a date in the past is a delete in disguise
    const expiresTs = action === 'expire' ? checkExpiry(req.body.expires_at, { future: true }) : null;
    if (action === 'expire' && !expiresTs) fail(400, 'pick the date they should run out');
    const days = action === 'extend' ? intIn(req.body.days, 1, 365, 0) : 0;
    if (action === 'extend' && !days) fail(400, 'extend by 1 to 365 days');

    const raw = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (!raw.length) fail(400, 'nothing was selected');
    if (raw.length > 1000) fail(400, 'that is over a thousand rules, do it in batches');
    const ids = [...new Set(raw.map(idParam))];

    const { affected, skipped } = await rules.act(actorOf(req), action, ids, { days, expiresTs });
    res.json({ ok: true, action, affected, skipped });
  })
);

module.exports = router;
