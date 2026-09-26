// Network allow lists. the portal list can never lock out the person changing it,
// and the client list can never be left switched on with nothing in it.
// Author: Tim Rice

const db = require('../db');
const ipacl = require('../security/network/ipacl');
const lists = require('../db/repositories/allowlists');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const KINDS = {
  portal: { setting: 'acl_enabled', action: 'acl', invalidate: () => ipacl.invalidateAcl() },
  registry: { setting: 'registry_acl_enabled', action: 'registry.acl', invalidate: () => ipacl.invalidateRegistryAcl() }
};

function list(kind) {
  return lists.list(kind);
}

async function add(actor, kind, { cidr, label }) {
  await lists.add(kind, { cidr, label, createdBy: actor.name });
  KINDS[kind].invalidate();
  await audit(actor, `${KINDS[kind].action}.add`, cidr, label);
}

async function entry(kind, id) {
  const row = await lists.byId(kind, id);
  if (!row) fail(404, 'no such entry');
  return row;
}

// last one off = filter on with nothing in it. fetched ranges count as networks
async function refuseLastNetwork(id) {
  const others = await ipacl.registryNetworkCount(id);
  if (!others.total) fail(400, 'that is the last network on the list, turn the filter off first');
}

async function setEnabled(actor, kind, id, enabled) {
  const k = KINDS[kind];
  const row = await entry(kind, id);
  const filterOn = db.settings.getBool(k.setting);

  if (kind === 'portal' && !enabled && filterOn) {
    // don't let someone lock themselves out. try it, check, undo
    await lists.setEnabled(kind, id, 0);
    k.invalidate();
    if (!(await ipacl.ipAllowed(actor.ip))) {
      await lists.setEnabled(kind, id, 1);
      k.invalidate();
      fail(400, 'that entry is what lets you in right now, so it stays');
    }
  } else {
    if (kind === 'registry' && !enabled && filterOn) await refuseLastNetwork(id);
    await lists.setEnabled(kind, id, enabled);
    k.invalidate();
  }
  await audit(actor, `${k.action}.update`, row.cidr, enabled ? 'enabled' : 'disabled',
    { before: { enabled: Number(row.enabled) ? 1 : 0 }, after: { enabled: enabled ? 1 : 0 } });
}

async function remove(actor, kind, id) {
  const k = KINDS[kind];
  const row = await entry(kind, id);
  const filterOn = db.settings.getBool(k.setting);
  if (kind === 'registry' && filterOn) await refuseLastNetwork(id);

  await lists.remove(kind, id);
  k.invalidate();

  // same safety net: if that was your way in, it goes right back
  if (kind === 'portal' && filterOn && !(await ipacl.ipAllowed(actor.ip))) {
    await lists.restore(kind, { cidr: row.cidr, label: 'restored, it was your own access', createdBy: actor.name });
    k.invalidate();
    fail(400, 'that entry is what lets you in right now, so it stays');
  }
  await audit(actor, `${k.action}.delete`, row.cidr, null, { before: { cidr: row.cidr, label: row.label, enabled: row.enabled } });
}

module.exports = { list, add, setEnabled, remove };
