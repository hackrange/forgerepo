// Properties on packages and versions: owner=security, criticality=high, review-date=2026-09-12.
// Author: Tim Rice
// plain text in, plain text out. keys are a small fixed shape so they can be filtered on and used by policy later

const repo = require('../db/repositories/properties');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const KEY = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_VALUE = 255;
// per package or per version. anything more is a database, not metadata
const MAX_PER_TARGET = 50;
const MAX_CHANGES = 100;

function checkKey(raw) {
  const k = String(raw === undefined || raw === null ? '' : raw).trim().toLowerCase();
  if (!KEY.test(k)) fail(400, `"${String(raw).slice(0, 40)}" is not a property name: letters, digits, dots, dashes and underscores, up to 64, starting with a letter or digit`);
  return k;
}

function checkValue(raw, k) {
  if (raw === null || raw === undefined || typeof raw === 'object') fail(400, `the value of ${k} has to be text`);
  const v = String(raw).trim();
  if (!v) fail(400, `${k} needs a value, remove it instead of setting it empty`);
  if (v.length > MAX_VALUE) fail(400, `the value of ${k} is too long, max ${MAX_VALUE} characters`);
  // eslint-disable-next-line no-control-regex -- one line of plain text
  if (/[\u0000-\u001f\u007f]/.test(v)) fail(400, `the value of ${k} is one line of plain text`);
  return v;
}

// "owner=security" or "owner" for the artifacts filter
function parseFilter(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const text = String(raw);
  const eq = text.indexOf('=');
  if (eq < 0) return { key: checkKey(text), value: null };
  return { key: checkKey(text.slice(0, eq)), value: checkValue(text.slice(eq + 1), text.slice(0, eq)) };
}

const label = (t) => `${t.ecosystem}:${t.name}${t.version ? `@${t.version}` : ' (every version)'}`;

async function list(target) {
  return { target, properties: await repo.onTarget(target.ecosystem, target.name, target.version) };
}

// what applies to one version, each one saying whether it is set on the version or on the package
async function effective(ecosystem, name, version) {
  const rows = await repo.forVersion(ecosystem, name, version);
  const out = new Map();
  for (const r of rows) if (!out.has(r.k)) out.set(r.k, { k: r.k, v: r.v, scope: r.version ? 'version' : 'package', set_by: r.set_by, set_at: r.set_at });
  return [...out.values()];
}

// body: { set: { key: value }, remove: [key] }
async function change(actor, target, body) {
  const setIn = body && body.set && typeof body.set === 'object' && !Array.isArray(body.set) ? body.set : {};
  const removeIn = body && Array.isArray(body.remove) ? body.remove : [];
  if (Object.keys(setIn).length + removeIn.length > MAX_CHANGES) fail(400, `that is more than ${MAX_CHANGES} changes at once`);
  const set = {};
  for (const [rawKey, rawValue] of Object.entries(setIn)) {
    const k = checkKey(rawKey);
    set[k] = checkValue(rawValue, k);
  }
  const remove = [...new Set(removeIn.map(checkKey))].filter((k) => !(k in set));
  if (!Object.keys(set).length && !remove.length) fail(400, 'nothing to change');

  const current = await repo.onTarget(target.ecosystem, target.name, target.version);
  const was = Object.fromEntries(current.map((r) => [r.k, r.v]));
  const next = { ...was };
  for (const k of remove) delete next[k];
  Object.assign(next, set);
  if (Object.keys(next).length > MAX_PER_TARGET) fail(400, `a package or version holds at most ${MAX_PER_TARGET} properties`);

  const touched = [...new Set([...Object.keys(set), ...remove])].filter((k) => was[k] !== next[k]);
  if (!touched.length) return list(target);
  await repo.apply(target, { set, remove }, actor.name);
  await audit(actor, 'property.change', label(target), touched.join(','), {
    before: Object.fromEntries(touched.map((k) => [k, was[k] === undefined ? null : was[k]])),
    after: Object.fromEntries(touched.map((k) => [k, next[k] === undefined ? null : next[k]]))
  });
  return list(target);
}

function keys() {
  return repo.keys(200);
}

module.exports = { KEY, MAX_PER_TARGET, checkKey, checkValue, parseFilter, list, effective, change, keys };
