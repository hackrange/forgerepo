// Portal API, traffic log.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const logs = require('../../services/logs');
const accessLog = require('../../db/repositories/access-log');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { idParam, str, likeTerm, oneOf, paging } = require('../../lib/validate');
const { UNASSIGNED } = require('../shared/constants');
const { csvEscape, writeChunk, eachRow } = require('../shared/csv');
const { ownerFor } = require('../requests/owner');

const router = express.Router();

const tagFilter = (value) => (!value ? undefined : value === UNASSIGNED ? null : value);

// checked here, turned into SQL by the repository. the page and the export share it
function logFilters(query) {
  const action = oneOf(query.action, ['allow', 'deny', 'error', 'audit'], null);
  const pkg = str(query.package, 214, 'package');
  const ip = str(query.ip, 45, 'ip');
  const application = str(query.application, 128, 'application');
  const environment = str(query.environment, 128, 'environment');
  return { action, pkg: pkg ? likeTerm(pkg) : null, ip, application: tagFilter(application), environment: tagFilter(environment) };
}

router.get(
  '/logs',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const { rows, total } = await logs.list(logFilters(req.query), { limit, offset });
    res.json({ entries: rows, total, page, limit });
  })
);

// every matching row, streamed. logs:read is enough, the page already shows all of it.
router.get(
  '/logs/export',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    const format = oneOf(req.query.format, ['json', 'csv'], 'json');
    const { clause, params } = accessLog.filterClause(logFilters(req.query));
    const sql = accessLog.exportSql(clause);
    const columns = accessLog.EXPORT_COLUMNS;
    const stamp = new Date().toISOString().slice(0, 10);
    let written = 0;

    if (format === 'csv') {
      res.set('content-type', 'text/csv; charset=utf-8');
      res.set('content-disposition', `attachment; filename="forgerepo-traffic-${stamp}.csv"`);
      await writeChunk(res, `${columns.join(',')}\n`);
      await eachRow(sql, params, async (row) => {
        written += 1;
        await writeChunk(res, `${columns.map((c) => csvEscape(row[c])).join(',')}\n`);
      });
      await logs.exported(actorOf(req), format, written);
      return res.end();
    }

    const count = await accessLog.count(clause, params);
    res.set('content-type', 'application/json; charset=utf-8');
    res.set('content-disposition', `attachment; filename="forgerepo-traffic-${stamp}.json"`);
    await writeChunk(res, `${JSON.stringify({
      kind: 'npm-repo-traffic',
      format_version: 1,
      exported_at: new Date().toISOString(),
      exported_by: req.user.username,
      count
    }, null, 2).slice(0, -2)},\n  "entries": [\n`);

    await eachRow(sql, params, async (row) => {
      await writeChunk(res, `${written ? ',\n' : ''}    ${JSON.stringify(row)}`);
      written += 1;
    });

    await writeChunk(res, '\n  ]\n}\n');
    await logs.exported(actorOf(req), format, written);
    res.end();
  })
);

// one line explained: what happened, why, who, what applied, the evidence and what to do next.
// the same permission as the page. the waiting requests in it follow the Requests page though: yours, or all of them for
// people who decide requests. it used to list everybody's, with who asked, to anyone who could read traffic
router.get(
  '/logs/:id',
  auth.requirePerm('logs:read'),
  wrap(async (req, res) => {
    res.json(await require('../../services/event-detail').detail(idParam(req.params.id), { ownerId: ownerFor(req) }));
  })
);

module.exports = router;
