// Portal API, who may put a token in an application or environment.
// Author: Tim Rice

const auth = require('../../security/auth');
const { fail } = require('../../lib/errors');

// a developer who could label their own token could put a prod pipeline in dev and dodge prod's rules
function refuseLabelsUnlessAdmin(req) {
  if (auth.can(req.user, 'settings:write')) return;
  const wants = (v) => v !== undefined && v !== null && v !== '' && v !== 0 && v !== '0';
  if (wants(req.body.application_id) || wants(req.body.environment_id)) {
    fail(403, 'only an admin can put a token in an application or environment, since rules can be scoped by them');
  }
  // clearing is changing too, on an existing token
  if (req.method === 'PUT' && (req.body.application_id !== undefined || req.body.environment_id !== undefined)) {
    fail(403, 'only an admin can change which application or environment a token belongs to');
  }
}

module.exports = { refuseLabelsUnlessAdmin };
