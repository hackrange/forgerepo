// Lookalike packages from the portal: the list, dismissing and reopening.
// Author: Tim Rice

const typosquat = require('../policy/typosquat');
const repo = require('../db/repositories/typosquats');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

async function list(status) {
  const findings = await repo.byStatus(status);
  const counts = await repo.counts();
  return { mode: typosquat.mode(), status, findings, counts: Object.fromEntries(counts.map((c) => [c.status, Number(c.n)])) };
}

// dismissing says a person looked and it is not a squat
async function setStatus(actor, id, action, status) {
  const row = await repo.byId(id);
  if (!row) fail(404, 'there is no such finding');
  if (row.status === status) fail(409, `that finding is already ${status}`);
  await typosquat.setStatus(row.id, status, actor.name);
  await audit(actor, `typosquat.${action}`, `${row.ecosystem}:${row.package_name}`, `looked like ${row.looks_like}`);
}

module.exports = { list, setStatus };
