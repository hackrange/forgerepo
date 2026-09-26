// The kill switch from the portal: what is killed, killing, lifting, and who already has it.
// Author: Tim Rice

const killswitch = require('../policy/killswitch');
const repo = require('../db/repositories/killswitch');
const { fail } = require('../lib/errors');

// a hash or advisory kill says what it reaches right now, so nobody has to guess from an id
async function withReach(entry) {
  if (!entry.kind || entry.kind === 'package') return entry;
  const files = await killswitch.coveredFiles(entry).catch(() => []);
  const seen = new Set();
  const reach = [];
  for (const f of files) {
    const k = `${f.ecosystem}\n${f.package_name}\n${f.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (reach.length < 20) reach.push({ ecosystem: f.ecosystem, package: f.package_name, version: f.version });
  }
  return { ...entry, covers: seen.size, reach };
}

async function lists() {
  const active = await repo.active();
  return { active: await Promise.all(active.map(withReach)), lifted: await repo.lifted() };
}

// fields are checked, purgeCache already knows whether this person may purge
async function kill(actor, fields) {
  try {
    return await killswitch.kill({ ...fields, user: actor.name, userId: actor.id, ip: actor.ip });
  } catch (err) {
    fail(err.status || 500, err.status ? err.message : 'the kill could not be saved');
  }
}

async function lift(actor, id, note) {
  try {
    return await killswitch.lift(id, actor.name, note, actor.ip, actor.id);
  } catch (err) {
    fail(err.status || 500, err.status ? err.message : 'the kill could not be lifted');
  }
}

async function get(id) {
  const entry = await repo.byId(id);
  if (!entry) fail(404, 'there is no such kill');
  return entry;
}

function impact(entry, days) {
  return killswitch.impact(entry, days);
}

module.exports = { lists, kill, lift, get, impact };
