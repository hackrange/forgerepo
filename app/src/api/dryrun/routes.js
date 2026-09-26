// Portal API, policy dry run.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const resolution = require('../../policy/resolution');
const dryrun = require('../../policy/dryrun');
const { ruleEcosystem, checkPattern, checkRange } = require('../../policy/rulecheck');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { intIn, oneOf } = require('../../lib/validate');
const { ruleScope } = require('../shared/scope');

const router = express.Router();

// ---------------------------------------------------------------- policy dry run

// reads the traffic log and says what a change would have refused. saves nothing, enforces nothing
router.post(
  '/dryrun',
  auth.requirePerm('rules:read'),
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const who = `dryrun:${req.user.id}`;
    const limited = await auth.rateLimit(who, 20, 60000);
    if (!limited.ok) fail(429, 'that is a lot of dry runs, give it a minute');
    const type = oneOf(req.body.type, dryrun.KINDS, null);
    if (!type) fail(400, 'a dry run is for a rule, a vulnerability threshold or the license lists');
    const days = intIn(req.body.days, 1, 90, 30);
    let proposal;
    if (type === 'rule') {
      const ecosystem = ruleEcosystem(req.body.ecosystem);
      const kind = oneOf(req.body.kind, ['allow', 'deny'], null);
      if (!kind) fail(400, 'kind has to be allow or deny');
      const scope = await ruleScope(req.body);
      proposal = {
        type, ecosystem, kind,
        pattern: checkPattern(req.body.pattern, ecosystem),
        version_range: checkRange(req.body.version_range, ecosystem),
        application_id: scope.app, environment_id: scope.env,
        priority: intIn(req.body.priority, -1000, 1000, 0)
      };
    } else if (type === 'severity') {
      const severity = oneOf(String(req.body.severity || '').toUpperCase(), resolution.SEVERITIES, null);
      if (!severity) fail(400, 'pick low, moderate, high or critical');
      proposal = { type, severity };
    } else {
      const text = (k, name) => {
        const v = req.body[k] === undefined ? db.settings.get(`license_${k}`) || '' : req.body[k];
        if (typeof v !== 'string' || v.length > 8000) fail(400, `the ${name} list is too long`);
        return v;
      };
      const verdict = (k) => {
        const v = req.body[k] === undefined ? db.settings.get(`license_${k}`) : req.body[k];
        return oneOf(v, ['allowed', 'review', 'blocked'], null) || fail(400, `${k} has to be allowed, review or blocked`);
      };
      proposal = {
        type, allowed: text('allowed', 'allowed'), review: text('review', 'review'), blocked: text('blocked', 'blocked'),
        unlisted: verdict('unlisted'), unknown: verdict('unknown')
      };
    }
    const result = await dryrun.simulate(proposal, days);
    res.json({ ok: true, proposal, result });
  })
);

module.exports = router;
