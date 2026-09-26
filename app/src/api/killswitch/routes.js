// Portal API, kill switch.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const upstream = require('../../registry/npm/upstream');
const killswitch = require('../../services/killswitch');
const killRules = require('../../policy/killswitch');
const { ruleEcosystem, checkRange } = require('../../policy/rulecheck');
const pypiName = require('../../ecosystems/pypi/name');
const ociName = require('../../ecosystems/oci/name');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, required, boolFlag, intIn, oneOf } = require('../../lib/validate');

const router = express.Router();

router.get(
  '/killswitch',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const { active, lifted } = await killswitch.lists();
    res.json({ active, lifted, canKill: auth.can(req.user, 'rules:write') });
  })
);

// approvers and admins. waiting for an admin to wake up is how the malware gets installed
router.post(
  '/killswitch',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const kind = oneOf(req.body.kind || 'package', killRules.KINDS, null);
    if (!kind) fail(400, 'a kill names a package, a file hash or an advisory');
    let fields;
    if (kind === 'hash') {
      const digest = String(req.body.subject || '').trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(digest)) fail(400, 'a file kill takes the sha256 of the file, 64 hex characters');
      fields = { kind, subject: digest };
    } else if (kind === 'advisory') {
      const id = killRules.advisoryId(req.body.subject);
      if (!id) fail(400, 'that is not an advisory id, like CVE-2021-44228, GHSA-xxxx-xxxx-xxxx or PYSEC-2024-1');
      fields = { kind, subject: id };
    } else {
      const ecosystem = ruleEcosystem(req.body.ecosystem);
      const raw = required(req.body.package_name, 214, 'package name');
      let name;
      // not called kind: that is the kill's own kind, sent on below
      const newer = require('../../registry/kinds').get(ecosystem);
      if (newer) {
        if (raw.includes('*') || !newer.validName(raw)) fail(400, `${newer.badName}, and a kill names one exact package`);
        name = newer.killKey(raw);
      } else if (ecosystem === 'pypi') {
        if (!pypiName.valid(raw)) fail(400, 'that is not a valid PyPI project name');
        name = pypiName.normalize(raw);
      } else if (ecosystem === 'oci') {
        const folded = ociName.fold(raw);
        if (raw.includes('*') || !ociName.valid(folded)) fail(400, 'that is not an image repository, and a kill names one exact repository');
        name = folded;
      } else {
        if (raw.includes('*') || !upstream.validName(raw)) fail(400, 'that is not a valid npm package name, and a kill names one exact package');
        name = raw;
      }
      fields = { kind, ecosystem, packageName: name, versionRange: checkRange(req.body.version_range, ecosystem) };
    }
    const made = await killswitch.kill(actorOf(req), {
      ...fields, reason: req.body.reason,
      purgeCache: boolFlag(req.body.purge, false) && auth.can(req.user, 'packages:purge')
    });
    res.status(201).json({ ok: true, kill: made });
  })
);

// a CSV of kills. admins only: hundreds of packages refused to everyone at once is theirs to decide.
// dry_run says what would happen and changes nothing, the page shows that before the real run
router.post(
  '/killswitch/bulk',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    const body = req.body || {};
    if (typeof body.csv !== 'string' || !body.csv.trim()) fail(400, 'paste or upload the CSV: package, version, type');
    const dry = boolFlag(body.dry_run, true);
    try {
      const out = await require('../../services/killswitch-csv').run(actorOf(req), {
        csv: body.csv, reason: body.reason, dry,
        purge: boolFlag(body.purge, false) && auth.can(req.user, 'packages:purge')
      });
      res.status(dry ? 200 : 201).json({ ok: true, dry, ...out });
    } catch (err) {
      fail(err.status || 400, err.message);
    }
  })
);

router.post(
  '/killswitch/:id/lift',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const row = await killswitch.lift(actorOf(req), idParam(req.params.id), req.body && req.body.note);
    res.json({ ok: true, kill: row });
  })
);

// the traffic log says who already has it. same permission as reading the traffic page
router.get(
  '/killswitch/:id/impact',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const entry = await killswitch.get(idParam(req.params.id));
    const days = intIn(req.query.days, 1, 400, 30);
    res.json({ kill: entry, days, pulled: await killswitch.impact(entry, days) });
  })
);

module.exports = router;
