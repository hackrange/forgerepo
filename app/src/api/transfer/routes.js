// Portal API, import and export.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const transfer = require('../../services/transfer');
const exports_ = require('../../db/repositories/transfer');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { boolFlag, oneOf } = require('../../lib/validate');
const { csvEscape, writeChunk, eachRow } = require('../shared/csv');
const { ruleFilters } = require('../rules/filters');
const { findingFilters } = require('../vulnerabilities/filters');

const router = express.Router();

// header object, rows streamed into its list, so the whole file never sits in memory
async function streamJson(res, header, listName, sql, params) {
  await writeChunk(res, `${JSON.stringify(header, null, 2).slice(0, -2)},\n  "${listName}": [\n`);
  let written = 0;
  await eachRow(sql, params, async (row) => {
    await writeChunk(res, `${written ? ',\n' : ''}    ${JSON.stringify(row)}`);
    written += 1;
  });
  await writeChunk(res, '\n  ]\n}\n');
  return written;
}

async function streamCsv(res, columns, sql, params) {
  await writeChunk(res, `${columns.join(',')}\n`);
  let written = 0;
  await eachRow(sql, params, async (row) => {
    written += 1;
    await writeChunk(res, `${columns.map((c) => csvEscape(row[c])).join(',')}\n`);
  });
  return written;
}

function attachment(res, format, name) {
  res.set('content-type', format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8');
  res.set('content-disposition', `attachment; filename="${name}-${new Date().toISOString().slice(0, 10)}.${format}"`);
}

// same filters as the rules list. none = every rule
router.get(
  '/rules/export',
  auth.requirePerm('rules:export'),
  wrap(async (req, res) => {
    const format = oneOf(req.query.format, ['json', 'csv'], 'json');
    const { clause, params } = await ruleFilters(req.query);
    const sql = exports_.rulesExportSql(clause);
    const count = await exports_.countRules(clause, params);
    attachment(res, format, 'forgerepo-rules');
    const written = format === 'csv'
      ? await streamCsv(res, exports_.RULE_COLUMNS, sql, params)
      : await streamJson(res, {
        kind: 'npm-repo-rules',
        format_version: 1,
        exported_at: new Date().toISOString(),
        exported_by: req.user.username,
        policy_mode: db.settings.get('policy_mode'),
        count
      }, 'rules', sql, params);
    await transfer.exported(actorOf(req), 'rules.export', format, `${written} rules`);
    res.end();
  })
);

// every matching finding, streamed, no page cap
router.get(
  '/cve/findings/export',
  auth.requirePerm('rules:export'),
  wrap(async (req, res) => {
    const format = oneOf(req.query.format, ['json', 'csv'], 'json');
    const { clause, params } = findingFilters(req.query);
    const sql = exports_.findingsExportSql(clause);
    const count = await exports_.countFindings(clause, params);
    attachment(res, format, 'forgerepo-vulnerabilities');
    const written = format === 'csv'
      ? await streamCsv(res, exports_.FINDING_COLUMNS, sql, params)
      : await streamJson(res, {
        kind: 'npm-repo-vulnerabilities',
        format_version: 1,
        exported_at: new Date().toISOString(),
        exported_by: req.user.username,
        count
      }, 'findings', sql, params);
    await transfer.exported(actorOf(req), 'cve.export', format, `${written} findings`);
    res.end();
  })
);

// either format. mode=merge keeps what's there, mode=replace wipes first (careful)
router.post(
  '/rules/import',
  auth.requirePerm('rules:import'),
  wrap(async (req, res) => {
    const mode = oneOf(req.body.mode, ['merge', 'replace'], 'merge');
    const dryRun = boolFlag(req.body.dry_run, false);
    res.json(await transfer.importRules(actorOf(req), { mode, dryRun, raw: req.body.data }));
  })
);

// whole config for moving boxes. no secrets
router.get(
  '/export',
  auth.requirePerm('backup:export'),
  wrap(async (req, res) => {
    const snap = await transfer.configSnapshot();
    attachment(res, 'json', 'forgerepo-config');
    const written = await streamJson(res, {
      // kinds keep old npm-repo names, old exports still have to import
      kind: 'npm-repo-config',
      format_version: 1,
      exported_at: new Date().toISOString(),
      exported_by: req.user.username,
      note: 'users, tokens and break glass keys are left out on purpose',
      count: snap.count,
      settings: snap.settings,
      ip_acl: snap.acl,
      registry_acl: snap.registryAcl
    }, 'rules', exports_.CONFIG_RULES_SQL, []);
    await transfer.exported(actorOf(req), 'config.export', null, `${written} rules`);
    res.end();
  })
);

router.post(
  '/import',
  auth.requirePerm('backup:import'),
  wrap(async (req, res) => {
    const summary = await transfer.importConfig(actorOf(req), req.body);
    res.json({ ok: true, ...summary });
  })
);

module.exports = router;
