// Registry tokens: minting, relabeling, revoking. a token is shown once and only its hash is kept.
// Author: Tim Rice

const auth = require('../security/auth');
const tokens = require('../db/repositories/tokens');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const MAX_LIVE = 20;

function list(ownerId) {
  return tokens.list(ownerId);
}

// ownerId null = any token the caller is allowed to reach
async function get(id, ownerId) {
  const row = await tokens.byId(id, ownerId);
  if (!row) fail(404, 'no such token');
  return row;
}

// always minted for the person asking. never on behalf of someone else
async function mint(actor, { name, days, email, applicationId, environmentId }) {
  if ((await tokens.liveCount(actor.id)) >= MAX_LIVE) fail(400, `you already have ${MAX_LIVE} live tokens, revoke a few first`);
  const made = auth.newToken();
  const result = await tokens.create({
    userId: actor.id, name, email: email || null, applicationId, environmentId, prefix: made.prefix, hash: made.hash, days
  });
  await audit(actor, 'token.create', name, days ? `expires in ${days} days` : 'no expiry',
    { after: { name, expires_in_days: days || null, application_id: applicationId || null, environment_id: environmentId || null } });
  return { id: result.insertId, token: made.token };
}

// sets: [[column, value]], done: the words for the audit trail
async function relabel(actor, row, sets, done) {
  if (!sets.length) fail(400, 'nothing to change');
  await tokens.update(row.id, sets);
  await audit(actor, 'token.update', row.name, done.join(', '));
}

async function revoke(actor, row) {
  await tokens.revoke(row.id);
  await audit(actor, 'token.revoke', row.name, row.user_id === actor.id ? 'own token' : `user ${row.user_id}`,
    { before: { status: 'live' }, after: { status: 'revoked' } });
}

module.exports = { list, get, mint, relabel, revoke };
