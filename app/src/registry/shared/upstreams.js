// Which registry a package gets pulled from.
// Author: Tim Rice
//
// routing by pattern, first match wins. "ask each registry until one answers" is literally
// the recipe for dependency confusion. fallback to default exists per upstream, off by default.
// too broad = a 404 from the supplier, too narrow = public registry = owned. inconvenience vs breach

const db = require('../../db');
const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const config = require('../../config');
const log = require('../../logger');

let list = [];
let loadedAt = 0;
let dirty = true;

const TTL_MS = 5000;

// pattern matched like a deny rule for that ecosystem. unknown type claims nothing
function shape(row) {
  const ecosystem = row.ecosystem || 'npm';
  const adapter = ecosystems.adapter(ecosystem);
  return {
    id: row.id,
    name: row.name,
    ecosystem,
    url: String(row.url).replace(/\/+$/, ''),
    token: row.token || '',
    pattern: row.pattern || '',
    priority: row.priority,
    enabled: !!row.enabled,
    isDefault: !!row.is_default,
    fallback: !!row.fallback,
    // a mirror's own settings (RPM, APT), see mirror-options.js
    options: require('./mirror-options').parse(row.options),
    regex: row.pattern && adapter ? policy.toRegex(adapter.rulePattern('deny', String(row.pattern))) : null,
    weight: row.pattern ? policy.specificity(String(row.pattern)) : -1
  };
}

// exact name beats a glob, longer glob beats shorter, same as the rules. so the
// order two patterns happened to be typed in never decides anything
function compare(a, b) {
  if (b.priority !== a.priority) return b.priority - a.priority;
  if (b.weight !== a.weight) return b.weight - a.weight;
  return a.id - b.id;
}

async function reload(force) {
  if (!force && !dirty && Date.now() - loadedAt < TTL_MS) return list;
  const rows = await db.query(
    'SELECT id, name, ecosystem, url, token, pattern, priority, enabled, is_default, fallback, options FROM upstreams'
  );
  list = rows.map(shape).sort(compare);
  loadedAt = Date.now();
  dirty = false;
  return list;
}

function invalidate() {
  dirty = true;
}

async function all(ecosystem) {
  const rows = await reload();
  return ecosystem ? rows.filter((u) => u.ecosystem === ecosystem) : rows;
}

// catch-all for an ecosystem. npm falls back to its first row, others need an explicit default
async function defaultUpstream(ecosystem) {
  const eco = ecosystem || 'npm';
  const rows = (await reload()).filter((u) => u.ecosystem === eco);
  return rows.find((u) => u.isDefault) || (eco === 'npm' ? rows[0] : null) || null;
}

// a disabled upstream is NOT skipped for the next pattern, quietly going elsewhere is
// exactly what this module stops. same ecosystem only
async function forPackage(name, ecosystem) {
  const eco = ecosystem || 'npm';
  const adapter = ecosystems.adapter(eco);
  if (!adapter) return null;
  const rows = await reload();
  const spelled = adapter.ruleName('deny', name);
  for (const up of rows) {
    if (up.ecosystem !== eco || !up.regex) continue;
    if (up.regex.test(spelled)) return up;
  }
  return defaultUpstream(eco);
}

// by name not id, ids get reused. renaming an upstream costs a refetch, safe way around
function sourceName(up) {
  return up ? up.name : '';
}

function sameSource(cachedSource, up) {
  if (!cachedSource) return false;
  return cachedSource === sourceName(up);
}

// whether a cached copy came from where this name is routed now: its upstream, the default when that upstream falls
// back to it, or published here. an old copy with no source on record predates routing and is taken as it is
async function fromRoute(cachedSource, name, ecosystem) {
  if (!cachedSource || cachedSource === require('./published').SOURCE) return true;
  const up = await forPackage(name, ecosystem);
  if (!up) return false;
  if (cachedSource === sourceName(up)) return true;
  if (up.fallback && !up.isDefault) {
    const fallback = await defaultUpstream(ecosystem);
    return !!fallback && cachedSource === sourceName(fallback);
  }
  return false;
}

// what a client is told when the only copy came from a registry that no longer serves the name
function movedReason(what, cachedSource, name, ecosystem) {
  return `${what} is cached from ${cachedSource}, but ${name} is now routed to another ${ecosystem} registry, and the upstream registries are switched off, so it can not be fetched again from there`;
}

// first boot: the old single upstream setting becomes the default row
async function ensureDefault() {
  const existing = await db.one('SELECT COUNT(*) AS n FROM upstreams');
  if (Number(existing.n)) return null;

  const url = String(db.settings.get('upstream_registry') || config.upstreamRegistry).replace(/\/+$/, '');
  const token = db.settings.get('upstream_token') || config.upstreamToken || '';
  let name = 'default';
  try {
    name = new URL(url).hostname.replace(/^registry\./, '').split('.')[0] || 'default';
  } catch (err) {
    name = 'default';
  }

  await db.query(
    `INSERT INTO upstreams (name, url, token, pattern, priority, enabled, is_default, fallback, created_by)
     VALUES (?, ?, ?, '', 0, 1, 1, 0, 'setup')`,
    [name.slice(0, 64), url, token]
  );
  invalidate();
  log.info(`upstream registries are a list now, ${url} is the default and is called ${name}`);
  return name;
}

// the headers for a registry that has a token: "Bearer x" as it is, username:token as basic auth, anything else taken
// to be encoded already. the same reading the image side does
function headersFor(up, extra) {
  const h = { ...(extra || {}) };
  if (up && up.token) {
    h.authorization = up.token.includes(' ') ? up.token
      : up.token.includes(':') ? `Basic ${Buffer.from(up.token, 'utf8').toString('base64')}` : `Basic ${up.token}`;
  }
  return h;
}

module.exports = {
  headersFor,
  reload,
  invalidate,
  all,
  forPackage,
  defaultUpstream,
  sourceName,
  sameSource,
  fromRoute,
  movedReason,
  ensureDefault
};
