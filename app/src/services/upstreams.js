// Upstream registries: where packages come from. the default gets the leftovers, the rest match a pattern.
// Author: Tim Rice
// the server fetches these addresses, so what one may be is checked before it is ever saved

const db = require('../db');
const routing = require('../registry/shared/upstreams');
const ecosystems = require('../ecosystems');
const upstreams = require('../db/repositories/upstreams');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { str, required, boolFlag, intIn } = require('../lib/validate');
const { checkUpstreamUrl } = require('../lib/upstream-url');
const mirrorOptions = require('../registry/shared/mirror-options');

// tokens are write only, stars mean leave it alone
const STARS = '********';

function publicUpstream(row) {
  return {
    id: row.id,
    name: row.name,
    ecosystem: row.ecosystem || 'npm',
    url: row.url,
    pattern: row.pattern,
    priority: row.priority,
    enabled: !!row.enabled,
    is_default: !!row.is_default,
    fallback: !!row.fallback,
    has_token: !!row.token,
    // a mirror (RPM, APT) is reached at its own address. every kind has options now, so they always go out, and
    // the portal is told what this kind does when nobody has chosen
    options: mirrorOptions.parse(row.options),
    requires_hash: mirrorOptions.requiresHash({ ecosystem: row.ecosystem, options: mirrorOptions.parse(row.options) }),
    hash_expected: mirrorOptions.HASH_EXPECTED.includes(row.ecosystem),
    ...(mirrorOptions.isMirror(row.ecosystem) ? { path: `/${row.ecosystem}/${mirrorOptions.slug(row.name)}/` } : {}),
    created_by: row.created_by,
    created_at: row.created_at
  };
}

// patterns look like package names, * anywhere. empty = default. python ones have no scope
function checkPattern(raw, ecosystem) {
  const pattern = String(raw || '').trim();
  if (!pattern) return '';
  if (pattern.length > 214) fail(400, 'that pattern is too long');
  if (ecosystem === 'pypi') {
    if (!/^[A-Za-z0-9*][A-Za-z0-9._\-*]*$/.test(pattern)) {
      fail(400, 'a PyPI pattern looks like a project name, like acme-*, with a * where you want to match anything');
    }
  } else if (require('../registry/kinds').get(ecosystem)) {
    const kind = require('../registry/kinds').get(ecosystem);
    if (!kind.upstreamPattern.re.test(pattern)) fail(400, kind.upstreamPattern.message);
  } else if (ecosystem === 'oci') {
    if (!require('../ecosystems/oci/name').validPattern(pattern)) {
      fail(400, 'an image pattern looks like a repository, like acme/* or bitnami/*, lower case, with a * where you want to match anything');
    }
  } else if (!/^[@A-Za-z0-9*][A-Za-z0-9._\-*/@]*$/.test(pattern)) {
    fail(400, 'a pattern looks like a package name, with a * where you want to match anything');
  }
  if (pattern === '*') {
    fail(400, 'a pattern of * would take everything, which is what the default registry is for');
  }
  return pattern;
}

// missing type = npm (older pages). switched off types can't be added, existing ones stay
function checkEcosystem(raw) {
  const id = raw === undefined || raw === null || raw === '' ? 'npm' : String(raw);
  const known = ecosystems.get(id);
  if (!known) fail(400, 'that is not a kind of registry this box knows about');
  if (known.setting && !db.settings.getBool(known.setting)) {
    fail(400, `the ${known.label} type is switched off, turn it on in Settings first`);
  }
  return id;
}

function list() {
  return upstreams.list();
}

async function get(id) {
  const row = await upstreams.byId(id);
  if (!row) fail(404, 'no such upstream registry');
  return row;
}

// an image registry has to be one. Docker Hub's website is swapped for its registry, anything else is asked
async function checkImageRegistry(url) {
  const probe = require('../registry/oci/probe');
  const fix = probe.dockerHubFix(url);
  if (fix) {
    return { url: fix.url, note: `${fix.host} is the Docker Hub website, not the registry images are pulled from, so it was saved as ${fix.url}` };
  }
  const got = await probe.probe(url);
  if (got.registry === false) {
    fail(400, `${url} answered with ${got.status} but not like a container registry, which answers at /v2/. `
      + `For Docker Hub use ${probe.DOCKER_HUB_REGISTRY}`);
  }
  return { url, note: got.registry === null ? `${url} could not be reached to check it is a registry (${got.error}), so it was saved without that check` : null };
}

async function create(actor, body) {
  const name = required(body.name, 64, 'name');
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(name)) {
    fail(400, 'a name is letters, numbers, and spaces or dashes in the middle');
  }
  let url = checkUpstreamUrl(String(body.url || ''));
  const ecosystem = checkEcosystem(body.ecosystem);
  let note = null;
  if (ecosystem === 'oci') ({ url, note } = await checkImageRegistry(url));
  const pattern = checkPattern(body.pattern, ecosystem);
  const token = str(body.token, 500, 'token') || '';
  const priority = intIn(body.priority, 0, 100000, 100);

  // a mirror stands alone at its own address: no pattern, no default, a name that makes an address of its own
  const mirror = mirrorOptions.isMirror(ecosystem);
  if (mirror) {
    if (pattern) fail(400, 'a mirror is a whole repository, it has no pattern');
    if (!mirrorOptions.slug(name)) fail(400, 'give it a name with letters or numbers in it, it becomes part of the mirror address');
    if ((await upstreams.list()).some((u) => u.ecosystem === ecosystem && mirrorOptions.slug(u.name) === mirrorOptions.slug(name))) {
      fail(400, `a mirror's address would be /${ecosystem}/${mirrorOptions.slug(name)}/, and another mirror already has it`);
    }
  }

  // npm's default already exists, so new npm rows need a pattern. other types: first patternless one is the default
  let isDefault = 0;
  if (!pattern && !mirror) {
    if (ecosystem === 'npm') fail(400, 'give it a pattern, like @acme/*, so it has something to serve');
    const existing = await upstreams.defaultFor(ecosystem);
    if (existing) {
      fail(400, `${existing.name} is already the default for that type, so give this one a pattern, like acme-*`);
    }
    isDefault = 1;
  }

  if (await upstreams.nameTaken(name)) fail(400, 'there is already an upstream registry with that name');

  const result = await upstreams.create({
    name, ecosystem, url, token, pattern, priority,
    enabled: boolFlag(body.enabled, true) ? 1 : 0,
    is_default: isDefault,
    // the default has nowhere to fall back to
    fallback: !isDefault && !mirror && boolFlag(body.fallback, false) ? 1 : 0,
    options: body.options !== undefined || mirror ? mirrorOptions.check(ecosystem, body.options, fail) : null,
    created_by: actor.name
  });
  routing.invalidate();
  await audit(actor, 'upstream.create', name,
    ecosystem === 'npm' ? `${pattern} -> ${url}` : `${ecosystem} ${pattern || 'everything else'} -> ${url}${note ? ` (${note})` : ''}`);
  return { id: result.insertId, note };
}

// only what was sent changes. returns the columns that did
async function update(actor, row, body) {
  const changes = {};
  const ecosystem = row.ecosystem || 'npm';

  // Type is fixed forever, the cache belongs to that ecosystem
  if (body.ecosystem !== undefined && String(body.ecosystem) !== ecosystem) {
    fail(400, 'a registry keeps the type it was added with, add a new one for the other type');
  }

  if (body.name !== undefined && String(body.name) !== row.name) {
    const name = required(body.name, 64, 'name');
    if (await upstreams.nameTaken(name, row.id)) fail(400, 'there is already an upstream registry with that name');
    if (mirrorOptions.isMirror(ecosystem)) {
      if (!mirrorOptions.slug(name)) fail(400, 'give it a name with letters or numbers in it, it becomes part of the mirror address');
      if ((await upstreams.list()).some((u) => u.id !== row.id && u.ecosystem === ecosystem && mirrorOptions.slug(u.name) === mirrorOptions.slug(name))) {
        fail(400, `a mirror's address would be /${ecosystem}/${mirrorOptions.slug(name)}/, and another mirror already has it`);
      }
    }
    changes.name = name;
  }
  let note = null;
  if (body.url !== undefined) {
    changes.url = checkUpstreamUrl(String(body.url || ''));
    if (ecosystem === 'oci' && changes.url !== row.url) ({ url: changes.url, note } = await checkImageRegistry(changes.url));
    if (changes.url === row.url) delete changes.url;
  }
  // a token only goes to the server it was entered for. a new server needs it entered again. same server
  // written another way (case, :443, a seeded address never tidied up) is not a move
  const tokenSent = body.token !== undefined && String(body.token) !== STARS;
  const origin = (u) => {
    try {
      return new URL(u).origin;
    } catch (err) {
      return null;
    }
  };
  const moved = changes.url !== undefined && (origin(changes.url) === null || origin(changes.url) !== origin(row.url));
  if (moved && row.token && !tokenSent) {
    fail(400, 'the address changed, so enter the token again (or empty it to drop it)');
  }
  if (body.priority !== undefined) changes.priority = intIn(body.priority, 0, 100000, 100);
  if (body.enabled !== undefined) changes.enabled = boolFlag(body.enabled, true) ? 1 : 0;
  if (body.fallback !== undefined && !mirrorOptions.isMirror(ecosystem)) changes.fallback = boolFlag(body.fallback, false) ? 1 : 0;
  if (body.options !== undefined) {
    changes.options = mirrorOptions.check(ecosystem, body.options, fail);
    if (changes.options === (row.options || null)) delete changes.options;
  }

  //default gets the leftovers, so it never has a pattern. a mirror has none either
  if (body.pattern !== undefined && !row.is_default && !mirrorOptions.isMirror(ecosystem)) {
    const pattern = checkPattern(body.pattern, ecosystem);
    if (!pattern) {
      const kind = require('../registry/kinds').get(ecosystem);
      fail(400, `give it a pattern, like ${kind ? kind.upstreamPattern.example : ({ pypi: 'acme-*', oci: 'acme/*' }[ecosystem] || '@acme/*')}, so it has something to serve`);
    }
    changes.pattern = pattern;
  }
  // stars back = token untouched. empty string = clear it
  if (body.token !== undefined && String(body.token) !== STARS) {
    changes.token = str(body.token, 500, 'token') || '';
  }

  const keys = Object.keys(changes);
  if (!keys.length) return keys;

  await upstreams.update(row.id, changes);
  routing.invalidate();
  // a token never leaves this service, only whether there is one
  const tokenShown = (v) => (v ? '(set)' : '');
  await audit(actor, 'upstream.update', row.name, keys.join(','), {
    before: { ...Object.fromEntries((keys).map((k) => [k, row[k]])), ...(keys.includes('token') ? { token: tokenShown(row.token) } : {}) },
    after: { ...changes, ...(keys.includes('token') ? { token: tokenShown(changes.token) } : {}) }
  });
  return keys;
}

// removing one leaves its cache, those copies stop being served once the name routes elsewhere. returns how many
async function remove(actor, row) {
  if (row.is_default) {
    fail(400, 'the default registry is where everything else comes from, so it cannot be removed. Point it somewhere else instead.');
  }
  await upstreams.remove(row.id);
  routing.invalidate();
  const orphaned = await upstreams.cachedFrom(row.name);
  await audit(actor, 'upstream.delete', row.name, `${row.pattern} -> ${row.url}`,
    { before: { ...Object.fromEntries((['name', 'ecosystem', 'url', 'pattern', 'priority', 'enabled', 'fallback']).map((k) => [k, row[k]])), token: row.token ? '(set)' : '' } });
  return orphaned;
}

module.exports = { STARS, publicUpstream, checkUpstreamUrl, checkPattern, checkEcosystem, list, get, create, update, remove };
