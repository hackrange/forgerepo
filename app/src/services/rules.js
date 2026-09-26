// Allow and deny rules: saving, editing, bulk changes. the policy cache and the audit trail follow every write.
// Author: Tim Rice
// callers hand over values that are already checked. no request objects in here

const policy = require('../policy');
const ecosystems = require('../ecosystems');
const rules = require('../db/repositories/rules');
const imageCache = require('../registry/oci/cache-state');
const { checkPattern } = require('../policy/rulecheck');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

// npm rules keep the old naming so old audit searches still hit
function ruleTarget(ecosystem, kind, pattern) {
  return !ecosystem || ecosystem === 'npm' ? `${kind}:${pattern}` : `${ecosystem}:${kind}:${pattern}`;
}

// images get their cache columns from the layers on disk, not from whether the manifest is known
async function list(filters, paging) {
  const res = await rules.page(await withImageCache(filters), paging);
  await imageCache.annotate(res.rows);
  return res;
}

// the Cache filter, for image rules: which ones really are, or are not, on disk
async function withImageCache(filters) {
  if (!filters.cached || (filters.ecosystem && filters.ecosystem !== 'oci')) return filters;
  const candidates = await imageCache.annotate(await rules.imageCandidates(filters));
  const want = filters.cached === 'yes';
  const imageIds = candidates.filter((r) => imageCache.fullyCached(r) === want).map((r) => Number(r.id));
  return { ...filters, imageIds };
}

async function get(id) {
  const row = await rules.byId(id);
  if (!row) fail(404, 'no such rule');
  return row;
}

// r: { ecosystem, pattern, kind, range, note, priority, enabled, scope: { app, env } }
async function save(actor, r) {
  const key = {
    ecosystem: r.ecosystem, pattern: r.pattern, kind: r.kind, version_range: r.range, application_id: r.scope.app, environment_id: r.scope.env
  };
  const result = await rules.upsert(
    { ...key, note: r.note, priority: r.priority, enabled: r.enabled, created_by: actor.name },
    { note: 'values', priority: 'values', enabled: 'values' }
  );
  policy.invalidate();
  await audit(actor, 'rule.save', ruleTarget(r.ecosystem, r.kind, r.pattern),
    JSON.stringify({ range: r.range, priority: r.priority, enabled: r.enabled, application_id: r.scope.app, environment_id: r.scope.env }),
    { after: { ...key, note: r.note, priority: r.priority, enabled: r.enabled } });
  const id = result.insertId || (await rules.byKey(key)).id;
  const saved = await rules.byId(id);
  // an allow for every version with nothing cached gets its current version pulled in the background
  require('../warm-latest').queueRules([saved], actor);
  return saved;
}

// patch carries every column, in the order the audit detail has always listed them
async function update(actor, existing, patch) {
  // pattern+kind+range+scope is unique, an edit can collide. say so instead of a 500
  try {
    await rules.update(existing.id, patch);
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      const type = existing.ecosystem && existing.ecosystem !== 'npm'
        ? `${(ecosystems.get(existing.ecosystem) || { name: existing.ecosystem }).name} ` : '';
      fail(409, `a ${type}${patch.kind} rule for ${patch.pattern} with that version range and scope already exists`);
    }
    throw err;
  }
  policy.invalidate();
  await audit(actor, 'rule.update', ruleTarget(existing.ecosystem, patch.kind, patch.pattern), JSON.stringify(patch),
    { before: Object.fromEntries((Object.keys(patch)).map((k) => [k, existing[k]])), after: patch });
  return rules.byId(existing.id);
}

async function remove(actor, id) {
  const existing = await get(id);
  await rules.remove(id);
  policy.invalidate();
  await audit(actor, 'rule.delete', `${existing.kind}:${existing.pattern}`, null,
    { before: Object.fromEntries((['ecosystem', 'kind', 'pattern', 'version_range', 'note', 'priority', 'enabled', 'application_id', 'environment_id']).map((k) => [k, existing[k]])) });
}

// one line per pattern, a bad line is reported and the rest still go in
async function addMany(actor, { ecosystem, kind, note, scope, lines }) {
  const added = [];
  const skipped = [];
  for (const line of lines) {
    try {
      const pattern = checkPattern(line, ecosystem);
      await rules.upsert(
        { ecosystem, pattern, kind, application_id: scope.app, environment_id: scope.env, note, created_by: actor.name },
        { note: 'values' }
      );
      added.push(pattern);
    } catch (err) {
      skipped.push({ line, error: err.message });
    }
  }
  policy.invalidate();
  if (kind === 'allow') {
    require('../warm-latest').queueRules(added.map((pattern) => ({
      ecosystem, pattern, kind, version_range: '', enabled: 1, application_id: scope.app, environment_id: scope.env
    })), actor);
  }
  await audit(actor, 'rule.bulk', ecosystem === 'npm' ? kind : `${ecosystem}:${kind}`, `${added.length} added, ${skipped.length} skipped`);
  return { added: added.length, skipped };
}

// ids are already integers
async function act(actor, action, ids) {
  const skipped = [];
  let affected = 0;
  if (action === 'delete') {
    affected = await rules.removeMany(ids);
  } else if (action === 'enable' || action === 'disable') {
    affected = await rules.setEnabled(ids, action === 'enable');
  } else {
    //kind flip can hit the unique key, so one at a time
    for (const id of ids) {
      try {
        affected += await rules.setKind(id, action);
      } catch (err) {
        const row = await rules.byId(id);
        skipped.push({
          id,
          pattern: row ? row.pattern : null,
          error: err.code === 'ER_DUP_ENTRY' ? `a ${action} rule for that pattern already exists` : 'could not change it'
        });
      }
    }
  }
  policy.invalidate();
  await audit(actor, `rule.bulk.${action}`, `${affected} rules`, ids.slice(0, 50).join(','));
  return { affected, skipped };
}

module.exports = { ruleTarget, list, withImageCache, get, save, update, remove, addMany, act };
