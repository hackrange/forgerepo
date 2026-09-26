// Roles and what each may do. checked server side, the UI guards nothing.
// Author: Tim Rice

// export sits with read, reading and downloading leak the same thing.
// settings:read is NOT harmless - allow list, break glass keys, grants etc are a
// map of the way in, so admin only
// traffic is admin only: who pulled what, from which address, with which token, and everything built from that
const VIEWER = ['rules:read', 'rules:export', 'packages:read', 'requests:read:own'];

const DEVELOPER = [
  ...VIEWER,
  'requests:create',
  'requests:withdraw:own',
  'tokens:read:own',
  'tokens:create:own',
  'tokens:revoke:own',
  'tools:resolve'
];

// a developer who may also publish packages under the reserved names, usually a CI account
const PUBLISHER = [
  ...DEVELOPER,
  'packages:publish'
];

const APPROVER = [
  ...PUBLISHER,
  'rules:write',
  'rules:import',
  'requests:read:all',
  'requests:decide',
  'packages:purge'
];

const ADMIN = [
  ...APPROVER,
  'settings:read',
  'settings:write',
  'users:read',
  'users:write',
  'tokens:read:all',
  'tokens:revoke:all',
  'audit:read',
  'logs:read',
  'cache:purge',
  'backup:export',
  'backup:import'
];

const ROLE_PERMS = {
  viewer: new Set(VIEWER),
  developer: new Set(DEVELOPER),
  publisher: new Set(PUBLISHER),
  approver: new Set(APPROVER),
  admin: new Set(ADMIN)
};

const ROLES = Object.keys(ROLE_PERMS);

function can(user, perm) {
  if (!user) return false;
  const set = ROLE_PERMS[user.role];
  return set ? set.has(perm) : false;
}

function permsFor(role) {
  return [...(ROLE_PERMS[role] || [])];
}

module.exports = { ROLES, can, permsFor };
