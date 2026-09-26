// Import and export: rules in and out as json or csv, and the whole config for moving boxes.
// Author: Tim Rice
// everything in a file is checked before anything is written

const db = require('../db');
const ipacl = require('../security/network/ipacl');
const policy = require('../policy');
const config = require('../config');
const log = require('../logger');
const rules = require('../db/repositories/rules');
const transfer = require('../db/repositories/transfer');
const { ruleEcosystem, checkPattern, checkRange } = require('../policy/rulecheck');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { str, boolFlag, intIn, oneOf } = require('../lib/validate');

// rules per insert. few round trips, well under max_allowed_packet
const IMPORT_BATCH = 500;

// undo csvEscape's apostrophe, or scoped @ patterns won't re-import
function unguard(value) {
  if (typeof value !== 'string') return value;
  return value.startsWith("'") ? value.slice(1) : value;
}

// tiny csv reader. quotes and commas, that's it
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  const src = String(text).replace(/\r\n/g, '\n');

  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => String(c).trim() !== ''));
}

// json or csv, into plain objects
function readRuleFile(raw) {
  if (typeof raw !== 'string' || !raw.trim()) fail(400, 'there is nothing to import');
  // no rule-count cap, just the body limit express already enforces
  if (raw.length > config.maxImportBytes) {
    fail(413, `that file is ${(raw.length / 1048576).toFixed(1)}MB and the limit is ${Math.round(config.maxImportBytes / 1048576)}MB`);
  }
  const trimmed = raw.trim();

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (err) {
      fail(400, 'that json will not parse');
    }
    const list = Array.isArray(parsed) ? parsed : parsed.rules;
    if (!Array.isArray(list)) fail(400, 'the json needs a rules array');
    return list;
  }
  const rows = parseCsv(trimmed);
  if (!rows.length) fail(400, 'that csv is empty');
  const header = rows[0].map((h) => String(h).trim().toLowerCase());
  if (!header.includes('pattern')) fail(400, 'the csv needs a pattern column');
  return rows.slice(1).map((cells) => {
    const obj = {};
    header.forEach((key, i) => {
      obj[key] = unguard(cells[i]);
    });
    return obj;
  });
}

// mode=merge keeps what's there, mode=replace wipes first (careful)
async function importRules(actor, { mode, dryRun, raw }) {
  const incoming = readRuleFile(raw);

  // Validate everything before touching anything.
  const valid = [];
  const errors = [];
  // names, looked up once. an unknown name is an error, never quietly widened to everyone
  const appIds = await transfer.labelIds('applications');
  const envIds = await transfer.labelIds('environments');
  const scopeName = (value, ids, label) => {
    const text = value === undefined || value === null ? '' : String(value).trim();
    if (!text) return 0;
    const id = ids.get(text.toLowerCase());
    if (!id) fail(400, `there is no ${label} called ${text.slice(0, 60)} on this box, add it under Settings, Applications first`);
    return id;
  };
  incoming.forEach((item, index) => {
    try {
      // old npm-only files have no ecosystem column, blank reads as npm
      const ecosystem = ruleEcosystem(item.ecosystem);
      const pattern = checkPattern(item.pattern, ecosystem);
      const kind = oneOf(item.kind, ['allow', 'deny'], null);
      if (!kind) fail(400, 'kind has to be allow or deny');
      valid.push({
        ecosystem,
        pattern,
        kind,
        version_range: checkRange(item.version_range, ecosystem),
        application_id: scopeName(item.application, appIds, 'application'),
        environment_id: scopeName(item.environment, envIds, 'environment'),
        note: str(item.note, 512, 'note'),
        priority: intIn(item.priority, -1000, 1000, 0),
        enabled: boolFlag(item.enabled, true) ? 1 : 0
      });
    } catch (err) {
      errors.push({ row: index + 1, pattern: item && item.pattern, error: err.message });
    }
  });

  const types = [...new Set(valid.map((r) => r.ecosystem))].sort();

  if (dryRun) return { ok: true, dryRun: true, wouldImport: valid.length, mode, types, errors };
  if (!valid.length) fail(400, 'nothing in that file was usable');

  // batched, but ONE transaction - replace mode depends on it landing whole
  let done = 0;
  await db.transaction(async (q) => {
    // only wipe ecosystems in the file. an old npm export must not nuke the Python rules
    if (mode === 'replace') await rules.removeEcosystems(types, q);

    for (let i = 0; i < valid.length; i += IMPORT_BATCH) {
      const batch = valid.slice(i, i + IMPORT_BATCH).map((rule) => ({ ...rule, created_by: actor.name }));
      await rules.upsertMany(
        ['ecosystem', 'pattern', 'kind', 'version_range', 'application_id', 'environment_id', 'note', 'priority', 'enabled', 'created_by'],
        batch,
        { note: 'values', priority: 'values', enabled: 'values' },
        q
      );
      done += batch.length;
      if (valid.length > IMPORT_BATCH * 10 && done % (IMPORT_BATCH * 10) === 0) {
        log.info(`rules import: ${done}/${valid.length} written`);
      }
    }
  });

  policy.invalidate();
  await audit(actor, 'rules.import', mode, `${valid.length} rules, ${errors.length} skipped`);
  return { ok: true, imported: valid.length, mode, types, batches: Math.ceil(valid.length / IMPORT_BATCH), errors };
}

// whole config for moving boxes, less the rules which get streamed after it. no secrets
async function configSnapshot() {
  const acl = await transfer.aclForExport('ip_acl');
  const registryAcl = await transfer.aclForExport('registry_acl');
  const settings = {};
  for (const [k, v] of Object.entries(db.settings.all())) {
    // credentials never leave the box in a file
    if (db.settings.secrets.has(k)) continue;
    settings[k] = v;
  }
  return { count: await transfer.countRules(), settings, acl, registryAcl };
}

async function importConfig(actor, body) {
  let parsed;
  try {
    parsed = JSON.parse(String(body.data || ''));
  } catch (err) {
    fail(400, 'that json will not parse');
  }
  if (!parsed || parsed.kind !== 'npm-repo-config') fail(400, 'that is not a ForgeRepo config export');

  const wantRules = boolFlag(body.rules, true);
  const wantSettings = boolFlag(body.settings, false);
  const wantAcl = boolFlag(body.ip_acl, false);
  const summary = { rules: 0, settings: 0, ip_acl: 0, errors: [] };

  if (wantRules && Array.isArray(parsed.rules)) {
    // validate first so one bad row doesn't kill a batch
    const good = [];
    for (const item of parsed.rules) {
      try {
        const kind = oneOf(item.kind, ['allow', 'deny'], null);
        if (!kind) fail(400, 'bad kind');
        const ecosystem = ruleEcosystem(item.ecosystem);
        good.push({
          ecosystem,
          pattern: checkPattern(item.pattern, ecosystem),
          kind,
          version_range: checkRange(item.version_range, ecosystem),
          note: str(item.note, 512, 'note'),
          priority: intIn(item.priority, -1000, 1000, 0),
          enabled: boolFlag(item.enabled, true) ? 1 : 0,
          created_by: actor.name
        });
      } catch (err) {
        summary.errors.push({ pattern: item && item.pattern, error: err.message });
      }
    }

    const cols = ['ecosystem', 'pattern', 'kind', 'version_range', 'note', 'priority', 'enabled', 'created_by'];
    for (let i = 0; i < good.length; i += IMPORT_BATCH) {
      const batch = good.slice(i, i + IMPORT_BATCH);
      await rules.upsertMany(cols, batch, { note: 'values', priority: 'values', enabled: 'values' });
      summary.rules += batch.length;
    }
    policy.invalidate();
  }

  if (wantSettings && parsed.settings) {
    // the same checks and audit as saving the Settings page. credentials and the registry mode never come in from a file
    const incoming = {};
    for (const [k, v] of Object.entries(parsed.settings)) {
      if (!(k in db.settings.defaults) || db.settings.secrets.has(k) || k === 'upstream_token' || k.startsWith('registry_mode')) continue;
      incoming[k] = v === null || v === undefined ? '' : String(v);
    }
    try {
      const saved = await require('./settings').save(actor, incoming, { skipMovedSecrets: true });
      summary.settings = saved.changed.length;
      // a stored secret goes to these, and an import can't carry one, so this box's address stays
      for (const k of saved.keptDestinations || []) {
        summary.errors.push({ setting: k.keys.join(', '), error: `kept as it is here: ${k.secret} is stored for it and an import does not carry secrets. Change it in Settings and enter the secret again` });
      }
    } catch (err) {
      summary.errors.push({ setting: true, error: err.status ? err.message : 'the settings could not be imported' });
    }
  }

  if (wantAcl && Array.isArray(parsed.ip_acl)) {
    for (const item of parsed.ip_acl) {
      const cidr = ipacl.normalizeCidr(item.cidr);
      if (!cidr) {
        summary.errors.push({ cidr: item && item.cidr, error: 'not a valid network' });
        continue;
      }
      await transfer.importPortalAcl({ cidr, label: str(item.label, 128, 'label'), enabled: boolFlag(item.enabled, true) ? 1 : 0, createdBy: actor.name });
      ipacl.invalidateAcl();
      summary.ip_acl += 1;
    }
  }

  await audit(actor, 'config.import', null, JSON.stringify(summary));
  return summary;
}

// the exports stream straight to the response, this just records that one went out
function exported(actor, action, target, detail) {
  return audit(actor, action, target, detail);
}

module.exports = { IMPORT_BATCH, unguard, parseCsv, readRuleFile, importRules, configSnapshot, importConfig, exported };
