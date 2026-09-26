// Reserving names for private packages, and letting them go. Every change is audited.
// Author: Tim Rice

const policy = require('../policy/private-names');
const repo = require('../db/repositories/private-names');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const MAX_NAMES = 1000;
const MAX_NOTE = 255;

function list() {
  return repo.all();
}

const label = (row) => `${row.ecosystem}:${row.pattern}`;

async function add(actor, { ecosystem, pattern, note }) {
  if (!policy.ECOSYSTEMS.includes(ecosystem)) fail(400, 'the ecosystem is npm, pypi, oci, nuget, rubygems or maven');
  const folded = policy.checkPattern(ecosystem, pattern);
  if (!folded) {
    fail(400, {
      npm: 'an npm reserved name is an exact name, a scope like @acme/*, or a prefix ending in *',
      pypi: 'a PyPI reserved name is an exact project name, or a prefix ending in * like acme-*',
      oci: 'an image reserved name is an exact repository like acme/api, a namespace like acme/*, or a prefix ending in *',
      nuget: 'a NuGet reserved name is an exact package id like Acme.Logging, or a prefix ending in * like Acme.*',
      rubygems: 'a gem reserved name is an exact gem name like acme-logger, or a prefix ending in * like acme-*',
      maven: 'a Maven reserved name is a coordinate like com.acme:widgets, a group with a * like com.acme:*, or a prefix ending in * like com.acme.*'
    }[ecosystem]);
  }
  // eslint-disable-next-line no-control-regex -- one line of plain text
  const why = String(note === undefined || note === null ? '' : note).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_NOTE);
  if ((await repo.count()) >= MAX_NAMES) fail(400, `there are already ${MAX_NAMES} reserved names, take some away first`);
  const id = await repo.add({ ecosystem, pattern: folded, note: why, user: actor.name });
  if (!id) fail(409, `${ecosystem}:${folded} is reserved already`);
  policy.invalidate();
  const row = await repo.byId(id);
  await audit(actor, 'private_name.add', label(row), why || null, { after: { ecosystem, pattern: folded, note: why } });
  return row;
}

async function remove(actor, id) {
  const row = await repo.byId(id);
  if (!row) fail(404, 'there is no such reserved name');
  if (!(await repo.remove(id))) fail(409, 'that reserved name was taken away a moment ago');
  policy.invalidate();
  await audit(actor, 'private_name.remove', label(row), null, { before: { ecosystem: row.ecosystem, pattern: row.pattern, note: row.note } });
  return row;
}

module.exports = { MAX_NAMES, list, add, remove };
