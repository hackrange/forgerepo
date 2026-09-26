// Applications and environments: what a token is for and where it runs, and how rules and previews name them.
// Author: Tim Rice
// retire, don't delete. a label in use can't be deleted, since tokens and rules would quietly lose it

const labels = require('../db/repositories/labels');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { str, required, boolFlag } = require('../lib/validate');

// Each token points at one app + one env, so traffic can answer 'what runs this, and where?'
const LABELS = {
  applications: { key: 'applications', one: 'application' },
  // only environments carry a production tick
  environments: { key: 'environments', one: 'environment', flag: 'production' }
};

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;

async function list(key) {
  const flag = LABELS[key].flag;
  return (await labels.list(key)).map((r) => ({ ...r, retired: !!r.retired, live_tokens: Number(r.live_tokens), ...(flag ? { production: !!r.production } : {}) }));
}

async function create(actor, key, body) {
  const label = LABELS[key];
  const name = required(body.name, 128, 'name');
  if (!NAME_RE.test(name)) fail(400, 'a name is letters, numbers, and spaces or dashes in the middle');
  const note = str(body.note, 512, 'note');

  // unique key catches it too, but naming the existing spelling beats a driver error
  const clash = await labels.byName(key, name);
  if (clash) {
    fail(400, clash.name === name
      ? `there is already an ${label.one} by that name`
      : `there is already an ${label.one} called ${clash.name}, and these names ignore case`);
  }

  const production = label.flag && boolFlag(body.production, false) ? 1 : 0;
  const result = await labels.create(key, { name, note: note || null, production, createdBy: actor.name });
  await audit(actor, `${label.one}.create`, name, production ? 'production' : null);
  return result.insertId;
}

//rename, renote, retire, un-retire. history keeps the old name
async function update(actor, key, id, body) {
  const label = LABELS[key];
  const row = await labels.byId(key, id);
  if (!row) fail(404, `no such ${label.one}`);

  const sets = [];
  if (body.name !== undefined) {
    const name = required(body.name, 128, 'name');
    if (!NAME_RE.test(name)) fail(400, 'a name is letters, numbers, and spaces or dashes in the middle');
    if (await labels.nameTakenByAnother(key, name, id)) fail(400, `there is already a ${label.one} by that name`);
    sets.push(['name', name]);
  }
  if (body.note !== undefined) sets.push(['note', str(body.note, 512, 'note') || null]);
  if (body.retired !== undefined) sets.push(['retired', boolFlag(body.retired, false) ? 1 : 0]);
  const notes = [];
  if (body.retired !== undefined) notes.push(boolFlag(body.retired, false) ? 'retired' : 'back in use');
  if (label.flag && body.production !== undefined) {
    const on = boolFlag(body.production, false);
    sets.push(['production', on ? 1 : 0]);
    notes.push(on ? 'marked production' : 'no longer production');
  }
  if (!sets.length) fail(400, 'nothing to change');

  await labels.update(key, id, sets);
  await audit(actor, `${label.one}.update`, row.name, notes.length ? notes.join(', ') : null);
}

// no deleting while tokens (revoked too) point here, they'd show 'unassigned'. Retire instead
async function remove(actor, key, id) {
  const label = LABELS[key];
  const row = await labels.byId(key, id);
  if (!row) fail(404, `no such ${label.one}`);

  const { total, live } = await labels.tokenUse(key, id);
  if (total) {
    const many = total !== 1;
    const state = live
      ? (many ? `${live} of them still live` : 'and it is still live')
      : (many ? 'all of them revoked' : 'and it is revoked');
    fail(400,
      `${row.name} is on ${total} token${many ? 's' : ''}, ${state}. ` +
      (row.retired
        ? `It is already retired, so it is not offered for new tokens. Move ${many ? 'those tokens' : 'that token'} off it to delete it outright.`
        : `Retire it instead, which keeps ${many ? 'those tokens' : 'that token'} readable and stops it being offered for new ones.`));
  }

  // rules scoped to it would quietly stop matching anyone
  const scoped = await labels.ruleUse(key, id);
  if (scoped) {
    fail(400, `${scoped} rule${scoped === 1 ? ' is' : 's are'} scoped to ${row.name}. Delete ${scoped === 1 ? 'it' : 'them'} or make ${scoped === 1 ? 'it' : 'them'} cover everyone first, or retire ${row.name} instead.`);
  }

  await labels.remove(key, id);
  await audit(actor, `${label.one}.delete`, row.name, null);
}

// ---------------------------------------------------------------- naming a label from outside

// a token's label. missing/empty = unassigned, fine for old tokens
async function labelIdFor(raw, label) {
  if (raw === undefined || raw === null || raw === '' || raw === 0 || raw === '0') return null;
  const id = parseInt(raw, 10);
  if (!Number.isInteger(id) || id < 1) fail(400, `that is not an ${label.one}`);
  const row = await labels.byId(label.key, id);
  if (!row) fail(404, `there is no ${label.one} with that id`);
  if (row.retired) fail(400, `${row.name} has been retired, pick one that is still in use`);
  return row.id;
}

// a rule's scope. 0 = everyone. an id has to exist, and a retired one takes no new rules
async function ruleScope(body, existing) {
  const pick = async (raw, key, label, current) => {
    if (raw === undefined) return current === undefined ? 0 : Number(current) || 0;
    if (raw === null || raw === '' || raw === 0 || raw === '0') return 0;
    const text = String(raw).trim();
    if (!/^[1-9]\d{0,9}$/.test(text)) fail(400, `that is not an ${label}`);
    const id = Number(text);
    const row = await labels.byId(key, id);
    if (!row) fail(400, `there is no ${label} with that id`);
    if (row.retired && id !== Number(current)) fail(400, `${row.name} has been retired, pick one that is still in use`);
    return id;
  };
  return {
    app: await pick(body.application_id, 'applications', 'application', existing && existing.application_id),
    env: await pick(body.environment_id, 'environments', 'environment', existing && existing.environment_id)
  };
}

// for previews on Check a package: retired is fine, it is only a question
async function previewScope(source) {
  const one = async (raw, key) => {
    const text = raw === undefined || raw === null ? '' : String(raw).trim();
    if (!/^[1-9]\d{0,9}$/.test(text)) return { id: 0, name: null };
    const row = await labels.byId(key, Number(text));
    return row ? { id: row.id, name: row.name } : { id: 0, name: null };
  };
  const a = await one(source.application, 'applications');
  const e = await one(source.environment, 'environments');
  return { scope: { app: a.id, env: e.id }, names: { application: a.name, environment: e.name } };
}

module.exports = { LABELS, list, create, update, remove, labelIdFor, ruleScope, previewScope };
