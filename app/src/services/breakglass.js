// Break glass keys: the only way into the portal from an address that isn't on the list.
// Author: Tim Rice
// a key is shown once when it's made. after that only its hint exists, anywhere

const ipacl = require('../security/network/ipacl');
const log = require('../logger');
const breakglass = require('../db/repositories/breakglass');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

// expired or used up isn't 'live'
async function keys() {
  return (await breakglass.liveKeys()).map(({ expired, ...k }) => ({
    ...k,
    status: Number(expired) ? 'expired' : k.max_uses > 0 && k.uses >= k.max_uses ? 'used up' : 'live'
  }));
}

async function create(actor, { label, maxUses, grantMinutes, days }) {
  const made = ipacl.newKeyUuid();
  const result = await breakglass.createKey({
    label, hash: made.hash, hint: made.hint, maxUses, grantMinutes, createdBy: actor.id, days
  });
  await audit(actor, 'breakglass.create', label, `${maxUses || 'unlimited'} uses, ${grantMinutes} minute grant`);
  log.warn(`a break glass key was created by ${actor.name}: ${label}`);
  return { id: result.insertId, uuid: made.uuid };
}

async function remove(actor, id) {
  const row = await breakglass.keyById(id);
  if (!row) fail(404, 'no such key');
  const ended = await breakglass.deleteKey(id);
  await audit(actor, 'breakglass.delete', row.label, `${ended} live grant(s) ended`);
  return ended;
}

// just enough of the hash to tell grants apart
async function grants() {
  return (await breakglass.recentGrants()).map((g) => ({
    id: g.id.slice(0, 8),
    ip: g.ip,
    user_agent: g.user_agent,
    created_at: g.created_at,
    expires_at: g.expires_at,
    revoked: !!g.revoked,
    key_label: g.key_label,
    active: !g.revoked && new Date(g.expires_at) > new Date()
  }));
}

async function revokeAll(actor) {
  const revoked = await breakglass.revokeActiveGrants();
  await audit(actor, 'breakglass.revoke-grants', `${revoked} grants`, null);
  return revoked;
}

module.exports = { keys, create, remove, grants, revokeAll };
