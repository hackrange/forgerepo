// Quarantine from the portal: the holds list, holding a file by hand, releasing and rejecting.
// Author: Tim Rice
// the hold rules themselves live in quarantine.js

const artifacts = require('../storage/artifacts');
const quarantine = require('../policy/quarantine');
const dashboard = require('../dashboard');
const repo = require('../db/repositories/quarantine');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { resolving } = require('../lib/resolving');

// reasons end up in an npm-notice header and on pages, so plain printable text only
function plainText(value, label, needed) {
  const s = String(value === undefined || value === null ? '' : value).replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim();
  if (needed && !s) fail(400, `a ${label} is needed`);
  if (s.length > 1000) fail(400, `the ${label} is too long, 1000 characters at most`);
  return s;
}

async function list(filters, paging) {
  const { rows, total } = await repo.page(filters, paging);
  return { holds: rows, total, open: await repo.openCount(), mode: quarantine.mode() };
}

// the file has to exist before the reason is even read
async function holdArtifact(actor, id, rawReason) {
  const row = await artifacts.byId(id);
  if (!row) fail(404, 'there is no such artifact');
  const reason = plainText(rawReason, 'reason', true);
  const placed = await quarantine.hold(
    { ecosystem: row.ecosystem, packageName: row.package_name, version: row.version, filename: row.filename },
    { source: 'manual', reason, user: actor.name, sha256: row.sha256 }
  );
  await audit(actor, 'quarantine.hold.manual', `${row.ecosystem}:${row.package_name}:${row.filename}`, reason);
  dashboard.invalidate();
  return placed;
}

// action is release or reject
async function resolve(actor, id, action, note) {
  const h = await resolving(() => quarantine.resolve(id, action, actor.name, note));
  await audit(actor, `quarantine.${action}`, `${h.ecosystem}:${h.package_name}:${h.filename}`,
    `${h.source}: ${h.reason}${note ? ` (${note})` : ''}`, { before: { status: 'open' }, after: { status: h.status } });
  dashboard.invalidate();
  return h;
}

module.exports = { plainText, list, holdArtifact, resolve };
