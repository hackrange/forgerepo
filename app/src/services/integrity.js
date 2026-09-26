// Integrity alerts from the portal: the list, one alert with its file, accepting or dismissing.
// Author: Tim Rice

const artifacts = require('../storage/artifacts');
const artifactstore = require('../storage');
const integrity = require('../policy/integrity');
const dashboard = require('../dashboard');
const repo = require('../db/repositories/integrity');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { resolving } = require('../lib/resolving');

async function list(filters, paging) {
  const { rows, total } = await repo.page(filters, paging);
  return { events: rows, total, open: await repo.openCount() };
}

async function detail(id) {
  const ev = await integrity.byId(id);
  if (!ev) fail(404, 'there is no such integrity alert');
  const artifact = await artifacts.find(ev.ecosystem, ev.package_name, ev.version, ev.filename);
  const held = ev.held_sha256 ? await artifactstore.has(ev.held_sha256) : false;
  return {
    event: { ...ev, metadata: artifacts.parseMeta(ev.metadata) },
    artifact: artifact ? { id: Number(artifact.id), sha256: artifact.sha256, size: Number(artifact.size), first_seen: artifact.first_seen } : null,
    heldOnDisk: held
  };
}

// action is accept or dismiss, the route only mounts those two
async function resolve(actor, id, action, note) {
  const ev = await resolving(() => integrity[action](id, actor.name, note));
  await audit(actor, `integrity.${action}`, `${ev.ecosystem}:${ev.package_name}:${ev.filename}`,
    `${ev.kind}: ${ev.expected} -> ${ev.observed}${note ? ` (${note})` : ''}`, { before: { status: 'open' }, after: { status: ev.status } });
  dashboard.invalidate();
  return ev;
}

module.exports = { list, detail, resolve };
