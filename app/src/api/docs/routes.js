// Portal API, what the documentation needs to know to write examples for this registry.
// Author: Tim Rice
//
// the address the registry calls itself and which package types are switched on, for everyone signed in. the names
// reserved for publishing only for those who can publish, and how the registry is set up only for those who can read
// its settings. nothing here is a secret the pages do not already show that same person

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const ecosystems = require('../../ecosystems');
const { wrap } = require('../../lib/http');

const router = express.Router();

router.get(
  '/docs/context',
  wrap(async (req, res) => {
    const out = {
      publicUrl: db.settings.get('public_url') || null,
      ecosystems: ecosystems.enabled((k) => db.settings.getBool(k)).map((e) => ({ id: e.id, name: e.name })),
      requireAuth: db.settings.getBool('require_auth'),
      ssoEnabled: db.settings.getBool('sso_enabled')
    };
    if (auth.can(req.user, 'packages:publish')) {
      out.reservedNames = (await require('../../services/private-names').list()).map((r) => ({ ecosystem: r.ecosystem, pattern: r.pattern }));
    }
    if (auth.can(req.user, 'settings:read')) {
      out.settings = {
        policyMode: db.settings.get('policy_mode'),
        auditMode: db.settings.getBool('audit_mode'),
        quarantineMode: db.settings.get('quarantine_mode'),
        safeResolution: db.settings.getBool('safe_resolution'),
        safeResolutionSeverity: db.settings.get('safe_resolution_severity'),
        cooloffHours: db.settings.getInt('cooloff_hours', 0),
        malwareScanning: db.settings.getBool('malware_scanning'),
        licenseEnforcement: db.settings.get('license_enforcement'),
        ociScan: db.settings.getBool('oci_scan')
      };
    }
    res.json(out);
  })
);

module.exports = router;
