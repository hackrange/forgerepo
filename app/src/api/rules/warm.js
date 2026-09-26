// Portal API, caching what the rules allow ahead of time.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const rules = require('../../db/repositories/rules');
const warm = require('../../warm');
const ecosystems = require('../../ecosystems');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { idParam } = require('../../lib/validate');

const router = express.Router();

// ---------------------------------------------------------------- cache warming

// background job, portal polls the GET for progress
router.post(
  '/rules/warm',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const raw = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (!raw.length) fail(400, 'nothing was selected');
    if (raw.length > 1000) fail(400, 'that is over a thousand rules, do it in batches');
    const ids = [...new Set(raw.map(idParam))];

    const rows = await rules.byIds(ids);

    // allow rules, real names, exact versions only. wildcards and ranges would be a job that does nothing
    const usable = [];
    const skipped = [];
    for (const row of rows) {
      const eco = row.ecosystem || 'npm';
      if (!warm.ECOSYSTEMS.includes(eco)) {
        skipped.push({ pattern: row.pattern, error: `a ${(ecosystems.get(eco) || { name: eco }).name} rule, and that kind of package cannot be cached yet` });
      } else if (row.kind !== 'allow') skipped.push({ pattern: row.pattern, error: 'not an allow rule' });
      else if (!row.enabled) skipped.push({ pattern: row.pattern, error: 'rule is disabled' });
      else if (row.pattern.includes('*')) skipped.push({ pattern: row.pattern, error: 'wildcard, there is no list of names to expand it against' });
      else if (!warm.cacheable(row.version_range, eco)) {
        skipped.push({ pattern: row.pattern, error: `${row.version_range} is a tag pattern, name the tags to cache` });
      } else usable.push(row);
    }
    // say why, one line per rule, instead of a riddle
    if (!usable.length) {
      fail(400, `none of those rules can be cached. ${skipped.slice(0, 5).map((s) => `${s.pattern}: ${s.error}`).join('. ')}`);
    }

    const started = warm.start(usable, req.user.username);
    await auth.auditReq(req, 'cache.warm', `${usable.length} rules`, ids.slice(0, 50).join(','));
    res.status(202).json({ ok: true, started: usable.length, skipped, job: started });
  })
);

router.get(
  '/rules/warm',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    res.json({ ok: true, job: warm.status(), limits: { maxTarballs: warm.MAX_TARBALLS } });
  })
);

router.post(
  '/rules/warm/cancel',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const job = warm.cancel();
    await auth.auditReq(req, 'cache.warm.cancel', null, null);
    res.json({ ok: true, job });
  })
);

module.exports = router;
