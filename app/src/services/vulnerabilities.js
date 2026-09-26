// Vulnerability scans and what they found: block a finding, or live with it.
// Author: Tim Rice

const db = require('../db');
const policy = require('../policy');
const cvescan = require('../cvescan');
const rules = require('../db/repositories/rules');
const repo = require('../db/repositories/vulnerabilities');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

async function startScan(actor) {
  const job = cvescan.start(actor.name);
  await audit(actor, 'cve.scan', null, null);
  return job;
}

async function cancelScan(actor) {
  const job = cvescan.cancel();
  await audit(actor, 'cve.scan.cancel', null, null);
  return job;
}

async function scanStatus() {
  const history = await repo.scanHistory();
  return {
    ok: true,
    job: cvescan.status(),
    everyHours: db.settings.getInt('cve_scan_hours', 24),
    // only admins flip these
    reporting: {
      audit_answer: db.settings.getBool('audit_answer'),
      audit_warn_install: db.settings.getBool('audit_warn_install'),
      audit_log_downloads: db.settings.getBool('audit_log_downloads')
    },
    history
  };
}

// advisory versions somebody pulled anyway. the to-do list after a finding lands
function downloads(filters, paging) {
  return repo.downloadsPage(filters, paging);
}

async function findings(filters, paging) {
  const page = await repo.findingsPage(filters, paging);
  // KEV and EPSS per row, one query for the whole page
  return { ...page, rows: await require('../integrations/intel').annotate(page.rows) };
}

// the why goes in the note so it outlives whoever clicked
function blockNote(finding) {
  const bits = [
    'blocked, known vulnerable.',
    `severity ${finding.severity}.`,
    finding.summary ? `${finding.summary}.` : '',
    finding.cves ? `CVE: ${finding.cves}.` : `advisories: ${finding.advisories}.`,
    finding.fixed_in ? `patched in ${finding.fixed_in}.` : 'no patched release is listed.',
    `found by the scan on ${String(finding.first_seen).slice(0, 10)}`
  ].filter(Boolean);
  const note = bits.join(' ');
  return note.length > 512 ? `${note.slice(0, 509)}...` : note;
}

// finding -> deny rule. returns how the version was spelled
async function block(actor, id) {
  const finding = await repo.findingById(id);
  if (!finding) fail(404, 'no such finding');

  await rules.upsert(
    {
      ecosystem: finding.ecosystem || 'npm', pattern: finding.package_name, kind: 'deny', version_range: finding.version,
      note: blockNote(finding), priority: 1000, enabled: 1, created_by: actor.name
    },
    { note: 'values', priority: 1000, enabled: 1 }
  );
  policy.invalidate();
  const spelled = finding.ecosystem && finding.ecosystem !== 'npm'
    ? `${finding.package_name}==${finding.version}` : `${finding.package_name}@${finding.version}`;
  await audit(actor, 'cve.block', spelled, finding.cves || finding.advisories);
  return spelled;
}

// "yes we know, we're living with it". Finding stays on the list though.
async function acknowledge(actor, id, on) {
  if (!(await repo.setAcknowledged(id, on ? 1 : 0))) fail(404, 'no such finding');
  await audit(actor, 'cve.acknowledge', String(id), on ? 'acknowledged' : 'cleared');
}

module.exports = { startScan, cancelScan, scanStatus, downloads, findings, blockNote, block, acknowledge };
