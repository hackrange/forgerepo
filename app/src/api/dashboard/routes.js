// Portal API, dashboard numbers.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const dashboard = require('../../dashboard');
const registryMode = require('../../policy/mode');
const stats = require('../../services/stats');
const waivers = require('../../services/waivers');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { boolFlag } = require('../../lib/validate');

const router = express.Router();

// the numbers are worked out once and shared, so what came from the traffic log is taken back out for anyone who
// can't read traffic: request counts, busiest applications, bandwidth, and how many applications pulled a risky version
function withoutTraffic(user, numbers) {
  if (auth.can(user, 'logs:read')) return numbers;
  const { allows24h, denies24h, topApplications, cards, ...rest } = numbers;
  const { bandwidth, risky, ...otherCards } = cards || {};
  return { ...rest, cards: { ...otherCards, risky: risky ? { versions: risky.versions, kev: risky.kev } : risky } };
}

router.get(
  '/stats',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const numbers = await dashboard.stats({ refresh: boolFlag(req.query.refresh, false) });
    // the mode is read live, the numbers may be minutes old
    const shown = withoutTraffic(req.user, numbers);
    // the shared waiver numbers count everyone's, anyone who isn't staff gets their own instead
    if (!waivers.seesAll(req.user) && shown.cards) shown.cards = { ...shown.cards, waivers: await dashboard.waiverNumbers(req.user.id) };
    res.json({
      ...shown,
      registryMode: { ...registryMode.describe(), canRaise: auth.can(req.user, 'rules:write'), canLower: auth.can(req.user, 'settings:write') },
      autoApprove: { ...require('../../services/auto-approve').describe(), canChange: auth.can(req.user, 'settings:write') }
    });
  })
);

// the packages behind a card. each list asks for the permission its own page does
const LIST_PERMS = {
  vulnerable: 'rules:read', malicious: 'packages:read', license: 'packages:read', risky: 'rules:read', integrity: 'packages:read', waivers: 'packages:read'
};

router.get(
  '/stats/list/:kind',
  (req, res, next) => {
    const kind = req.params.kind;
    if (!Object.prototype.hasOwnProperty.call(LIST_PERMS, kind)) return res.status(404).json({ error: 'there is no such list' });
    return auth.requirePerm(LIST_PERMS[kind])(req, res, next);
  },
  wrap(async (req, res) => {
    res.json({ kind: req.params.kind, rows: await dashboard.list(req.params.kind, { traffic: auth.can(req.user, 'logs:read'), waiverOwner: waivers.seesAll(req.user) ? null : req.user.id }), limit: 100 });
  })
);

// these only empty a list on the dashboard. logs, cache and rules untouched
router.post(
  '/stats/clear-blocked',
  auth.requirePerm('packages:purge'),
  wrap(async (req, res) => {
    await stats.clearBlocked(actorOf(req));
    res.json({ ok: true });
  })
);

router.post(
  '/stats/clear-busiest',
  auth.requirePerm('packages:purge'),
  wrap(async (req, res) => {
    const cleared = await stats.clearBusiest(actorOf(req));
    res.json({ ok: true, cleared });
  })
);

module.exports = router;
