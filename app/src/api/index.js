// Portal API. every area router, in the order they always answered.
// Author: Tim Rice
//
// any id-taking handler does the ownership check inside the same query. browser numbers aren't trusted, ever.

const express = require('express');
const auth = require('../security/auth');
const dashboard = require('../dashboard');

const router = express.Router();

// signing in, before there is a session to check
router.use(require('./session/routes'));

// Everything past here needs a session. No ticket, no ride.
router.use(auth.requireLogin);
router.use(auth.requirePasswordCurrent);

// any successful write drops the cached dashboard numbers. npm traffic doesn't come through here, on purpose
router.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.on('finish', () => {
      if (res.statusCode < 400) dashboard.invalidate();
    });
  }
  next();
});

router.use(require('./impersonation/routes'));
router.use(require('./docs/routes'));
router.use(require('./dashboard/routes'));
router.use(require('./rules/routes'));
router.use(require('./rules/warm'));
router.use(require('./vulnerabilities/routes'));
router.use(require('./intel/routes'));
router.use(require('./properties/routes'));
router.use(require('./lifecycle/routes'));
router.use(require('./sbom/routes'));
router.use(require('./private-names/routes'));
router.use(require('./image-trust/routes'));
router.use(require('./transfer/routes'));
router.use(require('./packages/routes'));
router.use(require('./artifacts/routes'));
router.use(require('./integrity/routes'));
router.use(require('./quarantine/routes'));
router.use(require('./resolutions/routes'));
router.use(require('./utilization/routes'));
router.use(require('./integrations/routes'));
router.use(require('./consumers/routes'));
router.use(require('./dryrun/routes'));
router.use(require('./waivers/routes'));
router.use(require('./killswitch/routes'));
router.use(require('./mode/routes'));
router.use(require('./typosquats/routes'));
router.use(require('./licenses/routes'));
router.use(require('./malware/routes'));
router.use(require('./cache/routes'));
router.use(require('./logs/routes'));
router.use(require('./requests/routes'));
router.use(require('./requests/decisions'));
router.use(require('./tools/routes'));
router.use(require('./review/routes'));
router.use(require('./users/routes'));
router.use(require('./applications/routes'));
router.use(require('./tokens/routes'));
router.use(require('./settings/routes'));
router.use(require('./storage/routes'));
router.use(require('./branding/routes'));
router.use(require('./email/routes'));
router.use(require('./sso/routes'));
router.use(require('./upstreams/routes'));
router.use(require('./whitelists/portal'));
router.use(require('./whitelists/clients'));
router.use(require('./whitelists/breakglass'));
router.use(require('./audit/routes'));

module.exports = router;
