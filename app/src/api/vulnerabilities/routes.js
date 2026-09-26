// Portal API, vulnerability scans and findings.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const ecosystems = require('../../ecosystems');
const vulnerabilities = require('../../services/vulnerabilities');
const imageScans = require('../../services/image-scans');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');
const { actorOf } = require('../../lib/actor');
const { idParam, str, likeTerm, boolFlag, oneOf, paging } = require('../../lib/validate');
const { UNASSIGNED } = require('../shared/constants');
const { parseFindingFilters } = require('./filters');

const router = express.Router();

router.post(
  '/cve/scan',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const job = await vulnerabilities.startScan(actorOf(req));
    res.status(202).json({ ok: true, job });
  })
);

router.post(
  '/cve/scan/cancel',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const job = await vulnerabilities.cancelScan(actorOf(req));
    res.json({ ok: true, job });
  })
);

router.get(
  '/cve/scan',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    res.json(await vulnerabilities.scanStatus());
  })
);

// "which of our apps pulled this?" is the whole point of those two columns
const tagFilter = (value) => (!value ? undefined : value === UNASSIGNED ? null : value);

router.get(
  '/cve/downloads',
  // who pulled a vulnerable version, from where, with which token: traffic
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const severity = oneOf(req.query.severity, ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'unrated'], null);
    const search = str(req.query.q, 214, 'search');
    const application = str(req.query.application, 128, 'application');
    const environment = str(req.query.environment, 128, 'environment');
    const ecosystem = req.query.ecosystem ? String(req.query.ecosystem) : null;
    if (ecosystem && !ecosystems.get(ecosystem)) fail(400, 'that is not a kind of registry this box knows about');

    const { rows, total } = await vulnerabilities.downloads(
      { severity, search: search ? likeTerm(search) : null, ecosystem, application: tagFilter(application), environment: tagFilter(environment) },
      { limit, offset }
    );
    res.json({ downloads: rows, total, page, limit });
  })
);

router.get(
  '/cve/findings',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const dir = oneOf(req.query.dir, ['asc', 'desc'], 'desc');
    const filters = parseFindingFilters(req.query);
    const { rows, total, counts } = await vulnerabilities.findings(filters, { sort: req.query.sort, dir, limit, offset });
    res.json({ ok: true, findings: rows, total, page, limit, counts });
  })
);

router.post(
  '/cve/findings/:id/block',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const blocked = await vulnerabilities.block(actorOf(req), idParam(req.params.id));
    res.json({ ok: true, blocked });
  })
);

router.post(
  '/cve/findings/:id/ack',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const id = idParam(req.params.id);
    const on = boolFlag(req.body.acknowledged, true);
    await vulnerabilities.acknowledge(actorOf(req), id, on);
    res.json({ ok: true, acknowledged: on });
  })
);

// images pulled through here and what is inside them. read like the findings list, rescanned by whoever can scan
router.get(
  '/cve/images',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const status = oneOf(req.query.status, ['queued', 'scanning', 'done', 'skipped', 'failed'], null);
    const search = str(req.query.q, 255, 'search');
    const result = await imageScans.list({ status, search: search ? likeTerm(search) : null }, { limit, offset });
    res.json({ ok: true, images: result.rows, total: result.total, counts: result.counts, page, limit,
      enabled: result.enabled, waiting: result.waiting, settings: result.settings });
  })
);

router.get(
  '/cve/images/detail',
  auth.requirePerm('rules:read'),
  wrap(async (req, res) => {
    const repository = str(req.query.repository, 255, 'repository');
    const digest = str(req.query.digest, 80, 'digest');
    const detail = await imageScans.detail(repository, digest, { all: boolFlag(req.query.all, false) });
    res.json({ ok: true, ...detail });
  })
);

router.post(
  '/cve/images/scan',
  auth.requirePerm('rules:write'),
  wrap(async (req, res) => {
    const repository = str(req.body.repository, 255, 'repository');
    const digest = str(req.body.digest, 80, 'digest');
    res.status(202).json({ ok: true, ...(await imageScans.rescan(actorOf(req), repository, digest)) });
  })
);

module.exports = router;
