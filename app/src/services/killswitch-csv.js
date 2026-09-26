// Killing a supply chain attack's worth of packages at once: a CSV of package, version and type, checked row by
// row, previewed, then killed with one reason. requested September 18, 2026. admins only.
// Author: Tim Rice

const policy = require('../policy/killswitch');
const upstream = require('../registry/npm/upstream');
const pypiName = require('../ecosystems/pypi/name');
const ociName = require('../ecosystems/oci/name');
const { checkRange } = require('../policy/rulecheck');
const aliases = require('../ecosystems/aliases');

const MAX_ROWS = 5000;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_RANGE = 128;
// how people write the type in a spreadsheet, shared with the file review
const TYPES = aliases.all();

// one csv line into cells, quotes and doubled quotes understood
function cells(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i += 1; } else if (c === '"') quoted = false; else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',' || c === '\t' || c === ';') { out.push(cur.trim()); cur = ''; } else cur += c;
  }
  out.push(cur.trim());
  return out;
}

function nameFor(eco, raw) {
  if (!raw) throw new Error('no package name');
  if (raw.includes('*')) throw new Error('a kill names one exact package, no wildcards');
  if (eco === 'pypi') {
    if (!pypiName.valid(raw)) throw new Error('not a valid PyPI project name');
    return pypiName.normalize(raw);
  }
  if (eco === 'oci') {
    const folded = ociName.fold(raw);
    if (!ociName.valid(folded)) throw new Error('not an image repository');
    return folded;
  }
  const kind = require('../registry/kinds').get(eco);
  if (kind) {
    if (!kind.validName(raw)) throw new Error(kind.badName);
    return kind.killKey(raw);
  }
  if (!upstream.validName(raw)) throw new Error('not a valid npm package name');
  return raw;
}

// csv text -> { rows: [{ line, ecosystem, name, version }], errors: [{ line, text, error }] }
// columns are package, version, type in that order, unless a header row names them in another
function parse(text) {
  const raw = String(text || '');
  if (Buffer.byteLength(raw) > MAX_BYTES) throw Object.assign(new Error('that file is over 2 MB, split it up'), { status: 400 });
  const lines = raw.replace(/^\uFEFF/, '').split(/\r?\n/);
  let order = { name: 0, version: 1, type: 2 };
  const rows = [];
  const errors = [];
  let first = true;
  lines.forEach((text, i) => {
    const line = i + 1;
    if (!text.trim() || /^\s*#/.test(text)) return;
    const c = cells(text);
    if (first) {
      first = false;
      const lower = c.map((x) => x.toLowerCase());
      const at = (...names) => lower.findIndex((x) => names.includes(x));
      if (at('package', 'package name', 'packagename', 'name', 'package_name') >= 0) {
        order = { name: at('package', 'package name', 'packagename', 'name', 'package_name'), version: at('version', 'versions', 'version range', 'range'), type: at('type', 'ecosystem', 'kind') };
        return;
      }
    }
    if (rows.length + errors.length >= MAX_ROWS) {
      if (errors.length < MAX_ROWS + 1) errors.push({ line, text: text.slice(0, 200), error: `only the first ${MAX_ROWS} rows are read` });
      return;
    }
    const get = (k) => (order[k] >= 0 ? String(c[order[k]] || '').trim() : '');
    const typed = get('type').toLowerCase() || 'npm';
    const ecosystem = aliases.typeOf(typed);
    try {
      if (!ecosystem) throw new Error(`"${get('type')}" is not a type, use npm, pypi, oci (docker), ${require('../registry/kinds').ids().join(' or ')}`);
      const name = nameFor(ecosystem, get('name'));
      const version = get('version');
      if (version && version !== '*') checkRange(version, ecosystem);
      rows.push({ line, ecosystem, name, version: version === '*' ? '' : version });
    } catch (err) {
      errors.push({ line, text: text.slice(0, 200), error: err.message });
    }
  });
  return { rows, errors };
}

// one kill per package: versions joined with ||, an every-version row wins, and a list too long for one range
// is split over several kills
function group(rows) {
  const by = new Map();
  for (const r of rows) {
    const key = `${r.ecosystem}\n${r.name}`;
    if (!by.has(key)) by.set(key, { ecosystem: r.ecosystem, name: r.name, versions: new Set(), all: false, lines: [] });
    const g = by.get(key);
    g.lines.push(r.line);
    if (!r.version) g.all = true;
    else g.versions.add(r.version);
  }
  const kills = [];
  for (const g of by.values()) {
    if (g.all) {
      kills.push({ ecosystem: g.ecosystem, name: g.name, range: '', lines: g.lines });
      continue;
    }
    let chunk = [];
    const flush = () => {
      if (chunk.length) kills.push({ ecosystem: g.ecosystem, name: g.name, range: chunk.join(' || '), lines: g.lines });
      chunk = [];
    };
    for (const v of g.versions) {
      if ([...chunk, v].join(' || ').length > MAX_RANGE) flush();
      chunk.push(v);
    }
    flush();
  }
  return kills;
}

// the preview and the real thing share this. dry means say what would happen and change nothing
async function run(actor, { csv, reason, purge, dry }) {
  const { rows, errors } = parse(csv);
  const kills = group(rows);
  const repo = require('../db/repositories/killswitch');
  const planned = [];
  for (const k of kills) {
    const dupe = await repo.activeDuplicate({ kind: 'package', ecosystem: k.ecosystem, name: policy.normalize(k.ecosystem, k.name), range: k.range, subject: '' });
    planned.push({ ...k, already: !!dupe });
  }
  if (dry) return { rows: rows.length, errors, kills: planned };
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  if (!String(reason || '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim()) throw Object.assign(new Error('say why, the reason goes to everyone who gets refused'), { status: 400 });
  const done = [];
  const failed = [];
  for (const k of planned) {
    if (k.already) continue;
    try {
      const made = await policy.kill({
        kind: 'package', ecosystem: k.ecosystem, packageName: k.name, versionRange: k.range, reason, purgeCache: !!purge,
        user: actor.name, userId: actor.id, ip: actor.ip, quiet: true
      });
      done.push({ ...k, id: made.id, purged: made.purged_files || 0 });
    } catch (err) {
      failed.push({ ...k, error: err.message });
    }
  }
  const auth = require('../security/auth');
  await auth.audit(actor.id || null, actor.name, actor.ip, 'killswitch.kill.bulk', `${done.length} kills from a csv`,
    `${String(reason).slice(0, 300)}; ${rows.length} rows, ${errors.length} unreadable, ${planned.filter((k) => k.already).length} already killed, ${failed.length} failed`);
  if (done.length) policy.tellAdminsBulk(done, reason, actor.name).catch(() => {});
  return { rows: rows.length, errors, killed: done, skipped: planned.filter((k) => k.already), failed };
}

module.exports = { MAX_ROWS, TYPES, cells, parse, group, run };
