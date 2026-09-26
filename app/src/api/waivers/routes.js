// Portal API, waivers.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const upstream = require('../../registry/npm/upstream');
const waiverRules = require('../../policy/waivers');
const waivers = require('../../services/waivers');
const { ruleEcosystem, checkRange } = require('../../policy/rulecheck');
const pypiName = require('../../ecosystems/pypi/name');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, required, boolFlag, oneOf } = require('../../lib/validate');
const { ruleScope } = require('../shared/scope');

const router = express.Router();

const canGrant = (user) => auth.can(user, 'rules:write') && auth.can(user, 'requests:decide');

// 1 to maxDays, as text so 1e2 and friends don't sneak through
function checkDays(value) {
  const d = String(value).trim();
  if (!/^\d{1,3}$/.test(d) || Number(d) < 1 || Number(d) > waiverRules.maxDays()) fail(400, `a waiver lasts 1 to ${waiverRules.maxDays()} days`);
  return Number(d);
}

router.get(
  '/waivers',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const all = waivers.seesAll(req.user);
    const { pending, active, history } = await waivers.lists(all ? null : req.user.id);
    res.json({
      pending, active, history, scope: all ? 'all' : 'mine', maxDays: waiverRules.maxDays(),
      canAsk: auth.can(req.user, 'requests:create'),
      canGrant: canGrant(req.user)
    });
  })
);

// the advisory ids on one exact version, so a waiver names what it waives
router.get(
  '/waivers/advisories',
  auth.requirePerm('packages:read'),
  wrap(async (req, res) => {
    const ecosystem = ruleEcosystem(req.query.ecosystem);
    const typed = required(req.query.name, 255, 'package name');
    const name = ecosystem === 'pypi' ? pypiName.normalize(typed)
      : require('../../registry/kinds').get(ecosystem) ? await require('../../registry/kinds').get(ecosystem).canonical(typed)
      : ecosystem === 'oci' ? (await require('../../registry/oci/upstream').canonicalName(require('../../ecosystems/oci/name').fold(typed))).name : typed;
    const version = required(req.query.version, 128, 'version');
    res.json(await waivers.advisories(ecosystem, name, version));
  })
);

router.post(
  '/waivers',
  auth.requirePerm('requests:create'),
  wrap(async (req, res) => {
    const kind = oneOf(req.body.kind, waiverRules.KINDS, null);
    if (!kind) fail(400, 'a waiver is for an advisory, a license or cooling off');
    const ecosystem = ruleEcosystem(req.body.ecosystem);
    const raw = required(req.body.package_name, 214, 'package name');
    let name;
    if (ecosystem === 'pypi') {
      if (!pypiName.valid(raw)) fail(400, 'that is not a valid PyPI project name');
      name = pypiName.normalize(raw);
    } else if (ecosystem === 'oci') {
      const ociName = require('../../ecosystems/oci/name');
      if (raw.includes('*') || !ociName.valid(raw)) fail(400, 'that is not an image name, and a waiver names one exact image');
      if (kind !== 'advisory') fail(400, 'an image has no license or cooling off to waive, only the advisories found inside it');
      name = (await require('../../registry/oci/upstream').canonicalName(ociName.fold(raw))).name;
    } else if (require('../../registry/kinds').get(ecosystem)) {
      const kind = require('../../registry/kinds').get(ecosystem);
      if (raw.includes('*') || !kind.validName(raw)) fail(400, `${kind.badName}, and a waiver names one exact package`);
      name = await kind.canonical(raw);
    } else {
      if (raw.includes('*') || !upstream.validName(raw)) fail(400, 'that is not a valid npm package name, and a waiver names one exact package');
      name = raw;
    }
    const range = checkRange(req.body.version_range, ecosystem);
    const reason = required(req.body.reason, 1000, 'reason');
    // a ticket number or a link, kept as one line of text. the page never makes it clickable
    const reference = str(req.body.reference, 255, 'reference') || '';
    // eslint-disable-next-line no-control-regex -- one line, nothing hidden in it
    if (/[\u0000-\u001f\u007f]/.test(reference)) fail(400, 'the reference is one line of plain text');

    let subject = '';
    if (kind === 'advisory' && ecosystem === 'oci' && String(req.body.subject || '').trim() === '*') {
      // the image as it is. only for tags or digests named, never a whole repository
      if (!range || range.includes('*')) fail(400, 'waiving every advisory in an image needs the exact tags or digests it covers');
      subject = '*';
    } else if (kind === 'advisory') {
      const ids = waiverRules.splitIds(req.body.subject);
      if (!ids.length) fail(400, 'name the advisory ids being waived, a new advisory must not ride along on an old waiver');
      if (ids.length > 20 || ids.some((id) => !/^[A-Z0-9][A-Z0-9._:-]{2,63}$/.test(id))) fail(400, 'those are not advisory ids, like GHSA-xxxx-xxxx-xxxx or PYSEC-2024-1');
      subject = ids.join(',');
      if (subject.length > 512) fail(400, 'that is too many advisories for one waiver');
    } else if (kind === 'license') {
      subject = String(req.body.subject || '').trim();
      if (!subject || subject.length > 255 || !/^[A-Za-z0-9.+:() -]+$/.test(subject)) fail(400, 'name the license being waived, like GPL-3.0-only, or unknown');
    } else if (req.body.subject) {
      fail(400, 'a cooling off waiver has nothing to name besides the package and versions');
    }

    const scope = await ruleScope(req.body);
    if (kind === 'license' && (scope.app || scope.env)) {
      fail(400, 'a license waiver covers everyone, since a license hold is on the file itself and not on one application');
    }
    const days = checkDays(req.body.days === undefined ? 30 : req.body.days);

    const grant = boolFlag(req.body.grant, false);
    if (grant && !canGrant(req.user)) fail(403, 'your role can ask for a waiver, not grant one');
    const row = await waivers.create(
      actorOf(req),
      { kind, ecosystem, packageName: name, versionRange: range, subject, app: scope.app, env: scope.env, reason, reference, days },
      grant
    );
    res.status(201).json({ ok: true, waiver: row });
  })
);

for (const action of ['approve', 'reject', 'revoke']) {
  router.post(
    `/waivers/:id/${action}`,
    auth.requirePerm('rules:write'),
    wrap(async (req, res) => {
      if (action !== 'revoke' && !auth.can(req.user, 'requests:decide')) fail(403, 'your role cannot decide on waivers');
      const note = str(req.body.note, 1000, 'note');
      if (action === 'reject' && !note) fail(400, 'say why it was turned down');
      const days = action === 'approve' && req.body.days !== undefined && req.body.days !== '' ? checkDays(req.body.days) : undefined;
      const row = await waivers.decide(actorOf(req), idParam(req.params.id), action, { note, days });
      res.json({ ok: true, waiver: row });
    })
  );
}

module.exports = router;
