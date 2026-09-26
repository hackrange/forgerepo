// Portal API, audit trail.
// Author: Tim Rice

const express = require('express');
const auth = require('../../security/auth');
const audit = require('../../services/audit');
const repo = require('../../db/repositories/audit');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { str, likePrefix, oneOf, paging } = require('../../lib/validate');
const { csvEscape, writeChunk, eachRow } = require('../shared/csv');

const router = express.Router();

// checked here, turned into SQL by the repository. the page and the export share it
function auditFilters(query) {
  const action = str(query.action, 64, 'action');
  const who = str(query.user, 64, 'user');
  const result = oneOf(query.result, ['success', 'failure', 'denied'], null);
  return { action: action ? likePrefix(action) : null, who, result };
}

router.get(
  '/audit',
  auth.requirePerm('audit:read'),
  wrap(async (req, res) => {
    const { limit, offset, page } = paging(req.query);
    const { rows, total } = await audit.list(auditFilters(req.query), { limit, offset });
    res.json({ entries: rows, total, page, limit });
  })
);

// every matching row, streamed. taking the trail away is itself on the trail
router.get(
  '/audit/export',
  auth.requirePerm('audit:read'),
  wrap(async (req, res) => {
    const format = oneOf(req.query.format, ['json', 'csv'], 'json');
    const { clause, params } = repo.filterClause(auditFilters(req.query));
    const sql = repo.exportSql(clause);
    const columns = repo.EXPORT_COLUMNS;
    const stamp = new Date().toISOString().slice(0, 10);
    let written = 0;

    if (format === 'csv') {
      res.set('content-type', 'text/csv; charset=utf-8');
      res.set('content-disposition', `attachment; filename="forgerepo-audit-${stamp}.csv"`);
      await writeChunk(res, `${columns.join(',')}\n`);
      await eachRow(sql, params, async (row) => {
        written += 1;
        await writeChunk(res, `${columns.map((c) => csvEscape(row[c])).join(',')}\n`);
      });
    } else {
      res.set('content-type', 'application/json; charset=utf-8');
      res.set('content-disposition', `attachment; filename="forgerepo-audit-${stamp}.json"`);
      await writeChunk(res, '[');
      await eachRow(sql, params, async (row) => {
        const out = Object.fromEntries(columns.map((c) => [c, row[c] instanceof Date ? row[c].toISOString() : row[c]]));
        await writeChunk(res, `${written ? ',' : ''}\n${JSON.stringify(out)}`);
        written += 1;
      });
      await writeChunk(res, '\n]\n');
    }
    await audit.exported(actorOf(req), format, written);
    return res.end();
  })
);

module.exports = router;
