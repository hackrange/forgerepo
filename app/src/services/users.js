// Portal accounts: creating, changing, deleting, and who may be impersonated.
// Author: Tim Rice
// the guard rails live here: never lose the last admin, never lock yourself out

const auth = require('../security/auth');
const users = require('../db/repositories/users');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { str, required, boolFlag, oneOf } = require('../lib/validate');

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    full_name: row.full_name,
    email: row.email,
    role: row.role,
    disabled: !!row.disabled,
    must_change_password: !!row.must_change_password,
    locked: !!(row.locked_until && new Date(row.locked_until) > new Date()),
    created_at: row.created_at,
    last_login_at: row.last_login_at
  };
}

// Emails are allowed on purpose: sso names accounts after the full address (refusing that was a weird self-own)
// case kept, column is _ci so dupes by case can't exist anyway
const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+@-]{1,63}$/;

function checkUsername(value) {
  const username = required(value, 64, 'username');
  if (!USERNAME_RE.test(username)) {
    fail(400, 'a username can hold letters, numbers, dots, dashes, underscores, plus signs and an at sign');
  }
  return username;
}

async function list() {
  return (await users.list()).map(publicUser);
}

async function create(actor, body) {
  const username = checkUsername(body.username);
  const role = oneOf(body.role, auth.ROLES, null);
  if (!role) fail(400, 'pick a role from the list');
  const password = String(body.password || '');
  const problem = auth.checkPasswordPolicy(password, username);
  if (problem) fail(400, problem);

  if (await users.nameTaken(username)) fail(409, 'that username is taken');

  const result = await users.create({
    username,
    full_name: str(body.full_name, 128, 'name'),
    email: str(body.email, 190, 'email'),
    password_hash: await auth.hashPassword(password),
    role,
    must_change_password: boolFlag(body.must_change_password, true) ? 1 : 0
  });
  await audit(actor, 'user.create', username, `role ${role}`);
  return publicUser(await users.byId(result.insertId));
}

async function update(actor, id, body) {
  const target = await users.byId(id);
  if (!target) fail(404, 'no such user');

  const admins = await users.activeAdmins();
  const patch = {};

  if (body.role !== undefined) {
    const role = oneOf(body.role, auth.ROLES, null);
    if (!role) fail(400, 'pick a role from the list');
    //the last admin demoting themselves = everyone locked out. no.
    if (target.role === 'admin' && role !== 'admin' && admins <= 1) {
      fail(400, 'that is the only admin left, promote someone else first');
    }
    if (target.id === actor.id && role !== 'admin') {
      fail(400, 'you cannot take away your own admin rights, ask another admin');
    }
    patch.role = role;
  }

  if (body.disabled !== undefined) {
    const disabled = boolFlag(body.disabled, false) ? 1 : 0;
    if (disabled && target.id === actor.id) fail(400, 'you cannot switch off your own account');
    if (disabled && target.role === 'admin' && admins <= 1) fail(400, 'that is the only admin left');
    patch.disabled = disabled;
  }

  // renames are safe, tokens hang off the id and history keeps the old name
  if (body.username !== undefined) {
    const username = checkUsername(body.username);
    if (username !== target.username) {
      if (await users.nameTaken(username, id)) fail(409, 'that username is taken');
      patch.username = username;
    }
  }

  if (body.full_name !== undefined) patch.full_name = str(body.full_name, 128, 'name');
  if (body.email !== undefined) patch.email = str(body.email, 190, 'email');
  if (body.unlock) {
    patch.locked_until = null;
    patch.failed_logins = 0;
  }

  if (body.password !== undefined && String(body.password).length) {
    const problem = auth.checkPasswordPolicy(String(body.password), target.username);
    if (problem) fail(400, problem);
    patch.password_hash = await auth.hashPassword(String(body.password));
    patch.must_change_password = boolFlag(body.must_change_password, true) ? 1 : 0;
    patch.password_changed_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  }

  if (!Object.keys(patch).length) fail(400, 'nothing to change');

  await users.update(id, patch);

  // role change, lockout or new password -> kick their sessions
  if (patch.role || patch.disabled || patch.password_hash) await auth.dropUserSessions(id, null);
  // target = OLD name so the rename gets recorded
  const changed = JSON.stringify(Object.keys(patch));
  await audit(actor, 'user.update', target.username,
    patch.username ? `${changed} ${target.username} is now ${patch.username}` : changed,
    { before: { ...Object.fromEntries((Object.keys(patch).filter((k) => k !== 'password_hash')).map((k) => [k, target[k]])), ...(patch.password_hash ? { password_hash: '(set)' } : {}) },
      after: { ...patch, ...(patch.password_hash ? { password_hash: '(new)' } : {}) } });

  return publicUser(await users.byId(id));
}

async function remove(actor, id) {
  const target = await users.byId(id);
  if (!target) fail(404, 'no such user');
  if (target.id === actor.id) fail(400, 'you cannot delete yourself');
  if (target.role === 'admin' && (await users.activeAdmins()) <= 1) fail(400, 'that is the only admin left');

  await users.remove(id);
  await audit(actor, 'user.delete', target.username, null, { before: Object.fromEntries((['username', 'full_name', 'email', 'role', 'disabled']).map((k) => [k, target[k]])) });
}

// act as someone for a while. never an admin, never yourself
async function impersonationTarget(actor, id) {
  const target = await users.byId(id);
  if (!target) fail(404, 'no such user');
  if (target.id === actor.id) fail(400, 'you are already you');
  if (target.role === 'admin') fail(400, 'an admin cannot be impersonated');
  if (target.disabled) fail(400, 'that account is switched off');
  return { id: target.id, username: target.username, role: target.role, disabled: target.disabled };
}

module.exports = { publicUser, checkUsername, list, create, update, remove, impersonationTarget };
