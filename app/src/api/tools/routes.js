// Portal API, check a package and resolve.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const rules = require('../../db/repositories/rules');
const policy = require('../../policy');
const { ruleEcosystem } = require('../../policy/rulecheck');
const dependencies = require('../../services/dependencies');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { str, required, boolFlag, intIn } = require('../../lib/validate');
const { previewScope } = require('../shared/scope');
const { toolsType } = require('../shared/tools-type');

const router = express.Router();

// ---------------------------------------------------------------- tools


// dependency tree + policy verdicts. what people (should) run before approving
router.post(
  '/tools/resolve',
  auth.requirePerm('tools:resolve'),
  wrap(async (req, res) => {
    const type = toolsType(ruleEcosystem(req.body.ecosystem, { mustBeOn: true }));
    const typed = required(req.body.name, 214, 'package name');
    if (!type.validName(typed)) fail(400, type.badName);
    const name = type.name(typed);
    const range = str(req.body.version_range, 128, 'version range') || 'latest';
    const depth = intIn(req.body.depth, 0, 25, 12);
    const includeDev = boolFlag(req.body.dev, false);
    const preview = await previewScope(req.body);

    const gate = await auth.rateLimit(`resolve:${req.user.id}`, 30, 10 * 60000);
    if (!gate.ok) fail(429, 'slow down a moment, that is a lot of tree walking');

    // an image is a tree of platforms, layers and the packages inside, not of dependencies
    if (type.id === 'oci') {
      const canScan = auth.can(req.user, 'rules:write');
      const imageTree = await require('../../services/image-tree').tree(type, name, range, { scope: preview.scope, canScan, scan: boolFlag(req.body.scan, false) });
      if (imageTree.platforms.some((p) => p.queued)) await auth.auditReq(req, 'image.scan', imageTree.root, 'from the dependency tree');
      return res.json(imageTree);
    }
    const tree = await dependencies.analyze(type, name, range, { depth, dev: includeDev, scope: preview.scope });
    const { packages } = tree;
    const blocked = packages.filter((p) => !p.allowed);
    res.json({
      ecosystem: type.id,
      root: type.id === 'pypi' ? `${name}${range === 'latest' ? '' : ` ${range}`}` : `${name}@${range}`,
      total: packages.length,
      blocked: blocked.length,
      denied: packages.filter((p) => p.denied).length,
      truncated: tree.truncated,
      // counts leave the package itself out: direct, transitive, blocked, vulnerable, not approved, never seen here
      summary: tree.summary,
      packages,
      problems: tree.problems
    });
  })
);

// allow everything the resolver found, except what a deny names.
// otherwise one button quietly undoes a blacklist
router.post(
  '/tools/allow-tree',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const names = Array.isArray(req.body.names) ? req.body.names : [];
    if (!names.length) fail(400, 'nothing to allow');
    if (names.length > 2000) fail(400, 'that is over two thousand packages, do it in batches');
    const note = str(req.body.note, 512, 'note') || 'added from a dependency review';
    const type = toolsType(ruleEcosystem(req.body.ecosystem, { mustBeOn: true }));

    let added = 0;
    const skipped = [];
    for (const raw of names) {
      const typed = String(raw || '').trim();
      if (!type.validName(typed)) continue;
      const name = type.name(typed);
      // whole-name rule, so any deny on the name counts
      const denies = await policy.denyRulesFor(name, type.adapter);
      if (denies.length) {
        skipped.push({
          name,
          error: `blacklisted by rule ${denies[0].pattern}${denies[0].version_range ? ` ${denies[0].version_range}` : ''}, so it was left blocked`
        });
        continue;
      }
      await rules.upsert({ ecosystem: type.id, pattern: name, kind: 'allow', note, created_by: req.user.username }, { note: 'values', enabled: 1 });
      added += 1;
    }
    policy.invalidate();
    await auth.auditReq(req, 'rules.allow-tree', `${added} packages`, note);
    res.json({ ok: true, added, skipped });
  })
);

module.exports = router;
