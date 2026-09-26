// One line of the traffic log, explained: what happened, why it was stopped, who asked, what applied,
// what the box holds as evidence, what ForgeRepo did, and what to do about it.
// Author: Tim Rice
// read only. everything here is text for the page to show as text, nothing is trusted to be markup

const accessLog = require('../db/repositories/access-log');
const artifacts = require('../db/repositories/artifacts');
const rules = require('../db/repositories/rules');
const kills = require('../db/repositories/killswitch');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const detailRepo = require('../db/repositories/event-detail');
const { fail } = require('../lib/errors');

// what kind of event a row is. the check that refused it wins, then a rule, then what the row itself says
function kindOf(row) {
  if (row.blocked_by) return row.blocked_by;
  if (row.rule_id) return 'rule';
  const reason = String(row.reason || '');
  if (/registry is in lockdown|registry is in degraded mode/.test(reason)) return 'mode';
  if (row.action === 'deny') return 'policy';
  if (row.action === 'audit') return 'audit';
  if (row.action === 'error') return 'error';
  return 'served';
}

const WHAT = {
  killswitch: 'Refused by the kill switch.',
  typosquat: 'Refused because the name imitates a well known package.',
  malware: 'Refused because a malware scanner flagged the file.',
  quarantine: 'Refused because the file is held in quarantine.',
  scanning: 'Held back until a malware scan gives an answer.',
  rule: 'Refused by a rule.',
  resolution: 'Refused because the version has a known advisory at or above the safe resolution threshold.',
  cooloff: 'Refused because the version is still inside the cooling off period.',
  license: 'Refused because of the license policy.',
  mode: 'Refused because of the registry mode.',
  policy: 'Refused by policy: nothing approves it.',
  audit: 'Served in audit only mode, and would otherwise have been refused.',
  error: 'The request failed.',
  served: 'Served.'
};

const NEXT = {
  killswitch: 'Treat any copy already installed as compromised. The Kill switch page shows who pulled it recently. Lift the kill only once the package is known to be safe again.',
  typosquat: 'If the name was a typo, fix it where it was written (package.json, requirements.txt, a lockfile). If it is a real package, dismiss the finding on Lookalike packages.',
  malware: 'Do not release it on one opinion. Check who else pulled this version, and only release the hold on Quarantine once a person agrees the verdict is wrong.',
  quarantine: 'Review the hold on the Quarantine page: release it once the reason is understood, or reject it.',
  scanning: 'Try again in a minute. If it keeps happening, look at the scanner status under Settings, Malware.',
  rule: 'If the rule is still right, the answer stands. Otherwise change the rule on the Rules page, or approve a request for it.',
  resolution: 'Move to a patched version. If this version really has to be used for now, grant a waiver that names the advisory.',
  cooloff: 'Wait until the version is old enough, or pin it with an allow rule or a cooling off waiver once someone has looked at it.',
  license: 'Review the license under Artifacts. A license waiver covers it for a while if the license has been cleared.',
  mode: 'The registry is in degraded or lockdown mode for an incident. Wait for it to be lifted, or ask an admin.',
  policy: 'Ask for it on the Requests page, or approve the request that was opened for it. The dependency tree walk shows what else it brings in.',
  audit: 'Nothing was stopped. Approve it with a rule, or leave it, before audit only mode is switched off.',
  error: 'Look at the upstream registry and at other errors around the same time on this page.',
  served: 'Nothing to do.'
};

async function evidenceFor(row, kind, ownerId) {
  const eco = row.ecosystem || 'npm';
  const name = row.package_name;
  const out = { rule: null, killSwitches: [], lookalike: null, files: [], finding: null, requests: [], consumers: null, sameInstall: [] };
  if (!name) return out;

  if (row.rule_id) {
    const r = await rules.byId(row.rule_id);
    if (r) out.rule = { id: r.id, kind: r.kind, pattern: r.pattern, version_range: r.version_range || '', note: r.note || '', created_by: r.created_by || '', priority: r.priority };
  }
  if (kind === 'killswitch') {
    // a package kill by name, or a hash or advisory kill whose id the refusal quotes
    out.killSwitches = (await kills.active()).filter((k) => (k.kind || 'package') === 'package'
      ? k.ecosystem === eco && k.package_name === name
      : String(row.reason || '').includes(k.subject))
      .slice(0, 10)
      .map((k) => ({ id: k.id, kind: k.kind || 'package', subject: k.subject || '', version_range: k.version_range || '', reason: k.reason, created_by: k.created_by, created_at: k.created_at }));
  }
  const squat = await detailRepo.lookalike(eco, name);
  if (squat) out.lookalike = squat;

  if (row.version) {
    const files = await detailRepo.files(eco, name, row.version);
    for (const f of files.slice(0, 10)) {
      const [holds, scans, alerts, provenance] = await Promise.all([
        artifacts.holds(f), f.sha256 ? artifacts.scans(f.sha256) : [], artifacts.integrityAlerts(f), artifacts.provenanceFor(f)
      ]);
      out.files.push({
        filename: f.filename,
        sha256: f.sha256,
        size: f.size,
        license: f.license_verdict ? { verdict: f.license_verdict, expression: f.license_expression } : null,
        holds: holds.map((x) => ({ source: x.source, reason: x.reason, status: x.status, created_at: x.created_at })),
        scans: scans.map((x) => ({ scanner: x.scanner, status: x.status, signature: x.signature, scan_time: x.scan_time })),
        integrity: alerts.map((x) => ({ kind: x.kind, status: x.status, observed: x.observed, occurrences: x.occurrences, last_seen: x.last_seen })),
        provenance: provenance ? { status: provenance.status, reason: provenance.reason, source_repository: provenance.source_repository } : null
      });
    }
    const finding = await vulnerabilities.findingForVersion(eco, name, row.version);
    if (finding) out.finding = finding;
    // counts come back from the database as text, the page and the api want numbers
    const c = await detailRepo.consumers(eco, name, row.version);
    out.consumers = c
      ? { consumers: Number(c.consumers || 0), applications: Number(c.applications || 0), downloads: Number(c.downloads || 0), last_seen: c.last_seen || null }
      : null;
  }
  // requests are private to whoever asked, same as the Requests page. no scope given, no requests shown
  out.requests = ownerId === undefined ? [] : await detailRepo.pendingRequests(eco, name, ownerId);
  if (row.npm_session) out.sameInstall = await detailRepo.sameInstall(row.npm_session, row.id);
  return out;
}

// ownerId: null when the caller may see every request, their user id when only their own
async function detail(id, { ownerId } = {}) {
  const row = await accessLog.byId(id);
  if (!row) fail(404, 'there is no such line in the traffic log, it may have aged out');
  const kind = kindOf(row);
  return {
    id: row.id,
    kind,
    what: WHAT[kind] || WHAT.policy,
    why: row.reason || null,
    action: `${row.action} ${row.status}`,
    when: row.ts,
    ecosystem: row.ecosystem || 'npm',
    package: row.package_name,
    version: row.version,
    pulledVersion: row.pulled_exact ? row.pulled_version : null,
    request: { method: row.method, path: row.path },
    who: { user: row.username || null, token: row.token_name || null, ip: row.ip || null, ci: row.ci || null },
    application: row.application || null,
    environment: row.environment || null,
    evidence: await evidenceFor(row, kind, ownerId),
    next: NEXT[kind] || NEXT.policy
  };
}

module.exports = { kindOf, WHAT, NEXT, detail };
