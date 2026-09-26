// Portal API, whose requests the caller may see.
// Author: Tim Rice

const auth = require('../../security/auth');

// staff see all (null), everyone else their own id
function ownerFor(req) {
  return auth.can(req.user, 'requests:read:all') ? null : req.user.id;
}

module.exports = { ownerFor };
