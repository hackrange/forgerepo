// The rules table, every read and write the portal makes. SQL for rules lives here and nowhere else.
// Author: Tim Rice
// values are always placeholders. column names only ever come from the allowlist below

const db = require('../../db');
const { CACHE_TYPES, CACHED_VERSIONS, CACHED_PIN_COUNT, PINNED_COUNT, FULLY_CACHED, VULN_COUNT, VULN_WORST } = require('./rule-columns');

const WRITABLE = new Set([
  'ecosystem', 'pattern', 'kind', 'version_range', 'application_id', 'environment_id', 'note', 'priority', 'enabled', 'created_by'
]);

function checkColumns(columns) {
  for (const c of columns) {
    if (!WRITABLE.has(c)) throw new Error(`rules has no writable column called ${c}`);
  }
}

/**
 * INSERT ... ON DUPLICATE KEY UPDATE for one or more rows.
 * onDuplicate maps a column to 'values' (take the new value) or a number (set it to that)
 * @param {string[]} columns
 * @param {number} rows
 * @param {Record<string, 'values'|number>} onDuplicate
 */
function upsertSql(columns, rows, onDuplicate) {
  checkColumns(columns);
  checkColumns(Object.keys(onDuplicate));
  const one = `(${columns.map(() => '?').join(', ')})`;
  const sets = Object.entries(onDuplicate).map(([c, v]) => (v === 'values' ? `${c} = VALUES(${c})` : `${c} = ${Number(v)}`));
  return `INSERT INTO rules (${columns.join(', ')}) VALUES ${new Array(rows).fill(one).join(', ')} `
    + `ON DUPLICATE KEY UPDATE ${[...sets, 'updated_at = NOW()'].join(', ')}`;
}

// q is a query function, a transaction's own when the write has to land with something else
async function upsert(fields, onDuplicate, q = db.query) {
  const columns = Object.keys(fields);
  return q(upsertSql(columns, 1, onDuplicate), columns.map((c) => fields[c]));
}

async function upsertMany(columns, rows, onDuplicate, q = db.query) {
  if (!rows.length) return null;
  return q(upsertSql(columns, rows.length, onDuplicate), rows.flatMap((r) => columns.map((c) => r[c])));
}

// ---------------------------------------------------------------- the list

// filters arrive already checked. search is a LIKE term, application and environment are 'none' or an id
function filterClause(f) {
  const where = [];
  const params = [];
  if (f.ecosystem) {
    where.push('ecosystem = ?');
    params.push(f.ecosystem);
  }
  if (f.kind) {
    where.push('kind = ?');
    params.push(f.kind);
  }
  // 'none' = covers everyone, a number = that one
  for (const [value, column] of [[f.application, 'application_id'], [f.environment, 'environment_id']]) {
    if (value === 'none') {
      where.push(`${column} = 0`);
    } else if (typeof value === 'number') {
      where.push(`${column} = ?`);
      params.push(value);
    }
  }
  if (f.search) {
    where.push('(pattern LIKE ? OR note LIKE ?)');
    params.push(f.search, f.search);
  }
  // cached = we hold the versions the rule names, not just *something*. wildcards never count. images are worked out
  // from the layers on disk, which SQL can't see through, so the service hands over the image rules that qualify
  const images = Array.isArray(f.imageIds) && f.imageIds.length
    ? { sql: ` OR id IN (${f.imageIds.map(() => '?').join(', ')})`, params: f.imageIds } : { sql: '', params: [] };
  if (f.cached === 'yes') {
    where.push(`((ecosystem IN (${CACHE_TYPES}) AND (${FULLY_CACHED}) = 1)${images.sql})`);
    params.push(...images.params);
  } else if (f.cached === 'no') {
    where.push(`((ecosystem IN (${CACHE_TYPES}) AND pattern NOT LIKE '%*%' AND (${FULLY_CACHED}) = 0)${images.sql})`);
    params.push(...images.params);
  }
  if (f.vuln === 'yes') {
    where.push(`${VULN_COUNT} > 0`);
  } else if (f.vuln === 'no') {
    // wildcards left out - we definitely can't promise those are clean
    where.push("pattern NOT LIKE '%*%'");
    where.push(`${VULN_COUNT} = 0`);
  }
  return { clause: where.length ? `WHERE ${where.join(' AND ')}` : '', params };
}

const SORTS = { pattern: 'pattern', kind: 'kind', priority: 'priority', created: 'created_at', updated: 'updated_at' };

const LIST_COLUMNS = `id, ecosystem, pattern, kind, version_range, application_id, environment_id,
              (SELECT name FROM applications WHERE id = rules.application_id) AS application_name,
              (SELECT name FROM environments WHERE id = rules.environment_id) AS environment_name,
              note, priority, enabled, created_by, created_at, updated_at,
              ${CACHED_VERSIONS} AS cached_versions,
              ${CACHED_PIN_COUNT} AS cached_pins,
              ${PINNED_COUNT} AS pinned_versions,
              ${VULN_COUNT} AS vuln_findings,
              ${VULN_WORST} AS vuln_worst`;

async function page(filters, { sort, dir, limit, offset }) {
  const { clause, params } = filterClause(filters);
  const order = SORTS[String(sort || '').toLowerCase()] || 'priority';
  const direction = dir === 'asc' ? 'ASC' : 'DESC';
  const rows = await db.query(
    `SELECT ${LIST_COLUMNS} FROM rules ${clause} ORDER BY ${order} ${direction}, pattern ASC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM rules ${clause}`, params);
  return { rows, total: Number(total.n) };
}

// image rules matching every other filter, for the service to judge against what is on disk. few enough to read whole
async function imageCandidates(filters) {
  const { clause, params } = filterClause({ ...filters, ecosystem: 'oci', cached: null, imageIds: null });
  return db.query(`SELECT id, ecosystem, pattern, version_range FROM rules ${clause} LIMIT 5000`, params);
}

// ---------------------------------------------------------------- one rule, or a few

function byId(id) {
  return db.one('SELECT * FROM rules WHERE id = ?', [id]);
}

// the unique key, for finding a row an upsert updated instead of inserting
function byKey(k) {
  return db.one(
    `SELECT id FROM rules WHERE ecosystem = ? AND pattern = ? AND kind = ? AND version_range = ?
        AND application_id = ? AND environment_id = ?`,
    [k.ecosystem, k.pattern, k.kind, k.version_range, k.application_id, k.environment_id]
  );
}

function byIds(ids) {
  return db.query(
    `SELECT id, ecosystem, pattern, kind, version_range, application_id, environment_id, enabled FROM rules WHERE id IN (${ids.map(() => '?').join(',')})`,
    ids
  );
}

function update(id, p) {
  return db.query(
    'UPDATE rules SET pattern=?, kind=?, version_range=?, application_id=?, environment_id=?, note=?, priority=?, enabled=? WHERE id = ?',
    [p.pattern, p.kind, p.version_range, p.application_id, p.environment_id, p.note, p.priority, p.enabled, id]
  );
}

function remove(id) {
  return db.query('DELETE FROM rules WHERE id = ?', [id]);
}

async function removeMany(ids) {
  return (await db.query(`DELETE FROM rules WHERE id IN (${ids.map(() => '?').join(',')})`, ids)).affectedRows;
}

async function setEnabled(ids, on) {
  return (await db.query(`UPDATE rules SET enabled = ? WHERE id IN (${ids.map(() => '?').join(',')})`, [on ? 1 : 0, ...ids])).affectedRows;
}

async function setKind(id, kind) {
  return (await db.query('UPDATE rules SET kind = ? WHERE id = ?', [kind, id])).affectedRows;
}

// replace mode on import clears only the ecosystems in the file
function removeEcosystems(types, q = db.query) {
  return q(`DELETE FROM rules WHERE ecosystem IN (${types.map(() => '?').join(',')})`, types);
}

// ---------------------------------------------------------------- what the engine reads

// every live rule with its scope names, the engine compiles these
function enabledForEngine() {
  return db.query(
    `SELECT r.id, r.ecosystem, r.pattern, r.kind, r.version_range, r.application_id, r.environment_id, r.note, r.priority, r.enabled,
            a.name AS application_name, e.name AS environment_name
       FROM rules r
       LEFT JOIN applications a ON a.id = r.application_id
       LEFT JOIN environments e ON e.id = r.environment_id
      WHERE r.enabled = 1`
  );
}

// allow rules naming one exact package, no wildcards
function exactAllowPatterns(ecosystem) {
  return db.query("SELECT pattern FROM rules WHERE ecosystem = ? AND kind = 'allow' AND enabled = 1 AND pattern NOT LIKE '%*%'", [ecosystem]);
}

module.exports = {
  upsertSql, upsert, upsertMany, filterClause, imageCandidates, page, byId, byKey, byIds, update, remove, removeMany, setEnabled, setKind, removeEcosystems,
  enabledForEngine, exactAllowPatterns
};
