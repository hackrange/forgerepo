// Someone changing their own password.
// Author: Tim Rice
// login, logout and sso stay with auth.js and sso.js

const auth = require('../security/auth');
const users = require('../db/repositories/users');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

// sessionId is the one they are using, it stays signed in
async function changePassword(actor, sessionId, current, next) {
  const row = await users.byId(actor.id);
  if (!row || !(await auth.verifyPassword(current, row.password_hash))) {
    await audit(actor, 'password.change.failed', actor.name, 'current password was wrong');
    fail(400, 'your current password is wrong');
  }
  const problem = auth.checkPasswordPolicy(next, actor.name);
  if (problem) fail(400, problem);
  if (next === current) fail(400, 'pick a password you have not used here before');

  await users.setPassword(actor.id, await auth.hashPassword(next));
  // new password, old sessions get the door
  await auth.dropUserSessions(actor.id, sessionId);
  await audit(actor, 'password.change', actor.name, null);
}

module.exports = { changePassword };
