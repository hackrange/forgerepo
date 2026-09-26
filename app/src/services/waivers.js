// Waivers from the portal: the lists, what an advisory waiver can name, asking and deciding.
// Author: Tim Rice
// the rules about what a waiver may do live in waivers.js

const waivers = require('../policy/waivers');
const repo = require('../db/repositories/waivers');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const auth = require('../security/auth');
const { fail } = require('../lib/errors');

// staff who decide waivers see all of them. everyone else sees the waivers they asked for and nothing of anybody else's
function seesAll(user) {
  return auth.can(user, 'rules:write') && auth.can(user, 'requests:decide');
}

// ownerId: null for every waiver, a user id for that user's own
async function lists(ownerId) {
  return { pending: await repo.pending(ownerId), active: await repo.active(ownerId), history: await repo.history(ownerId) };
}

// the advisory ids on one exact version, so a waiver names what it waives
async function advisories(ecosystem, name, version) {
  const row = await vulnerabilities.findingForVersion(ecosystem, name, version);
  return { ids: row ? waivers.splitIds(row.advisories) : [], cves: row ? row.cves : '', severity: row ? row.severity : null, summary: row ? row.summary : null };
}

const who = (actor) => ({ user: actor.name, userId: actor.id, ip: actor.ip });

function create(actor, fields, grant) {
  return waivers.create(fields, { grant, ...who(actor) });
}

async function decide(actor, id, action, { note, days }) {
  try {
    return await waivers.decide(id, action, { ...who(actor), note, days });
  } catch (err) {
    fail(err.status || 500, err.status ? err.message : 'the waiver could not be changed');
  }
}

module.exports = { seesAll, lists, advisories, create, decide };
