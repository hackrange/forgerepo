// Safe Version Resolution. what a client was offered, what it wasn't, and why.
// Author: Tim Rice
// rules and quarantine always trim metadata. switched on, versions with a bad enough
// advisory go too, and the client picks normally from what's left. never swaps in a
// version outside what it asked for, it just can't see the bad ones.

const db = require('../db');
const audit = require('../audit');
const auth = require('../security/auth');
const log = require('../logger');
const resolutions = require('../db/repositories/resolutions');

const SEVERITIES = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'];
// per reason. packages with thousands of nightlies would make rows enormous, counts stay exact
const MAX_VERSIONS_PER_REASON = 100;
const MAX_REASONS = 50;

function enabled() {
  return db.settings.getBool('safe_resolution');
}

// logged while anything that leaves versions out for a reason is on
function logging() {
  return enabled() || require('./cooloff').enabled();
}

function threshold() {
  const s = String(db.settings.get('safe_resolution_severity') || 'HIGH').toUpperCase();
  return SEVERITIES.includes(s) ? s : 'HIGH';
}

function rank(severity) {
  return SEVERITIES.indexOf(String(severity || '').toUpperCase());
}

// exploited in the wild beats any severity label. on unless switched off
function kevOn() {
  return db.settings.get('safe_resolution_kev') !== '0';
}

// the EPSS score (0 to 1) from which a version goes, or null for off
function epssBar() {
  const v = parseFloat(db.settings.get('safe_resolution_epss'));
  return v > 0 && v <= 1 ? v : null;
}

// why a finding is too risky: its severity, CISA KEV, its EPSS score, or null. kev and epss are only there once
// withIntel has looked them up. unknown severity isn't proof of anything, so by itself it stays
function why(finding) {
  if (!finding) return null;
  if (rank(finding.severity) >= 0 && rank(finding.severity) >= rank(threshold())) return 'severity';
  if (kevOn() && finding.kev) return 'kev';
  const bar = epssBar();
  if (bar !== null && finding.epss !== null && finding.epss !== undefined && Number(finding.epss) >= bar) return 'epss';
  return null;
}

function reasonFor(finding) {
  const what = `${String(finding.severity).toLowerCase()} advisory${finding.cves ? ` (${finding.cves})` : ''}`;
  const w = why(finding);
  if (w === 'kev') return `${what}, exploited in the wild (CISA KEV), safe resolution leaves those out`;
  if (w === 'epss') return `${what}, a ${(Number(finding.epss) * 100).toFixed(1)}% chance of exploitation (EPSS), safe resolution leaves out ${(epssBar() * 100).toFixed(1)}% and up`;
  return `${what}, safe resolution leaves out ${threshold().toLowerCase()} and worse`;
}

function tooRisky(finding) {
  return !!why(finding);
}

// findings (a Map of version -> row, or one row) with what CISA KEV and FIRST EPSS say about their CVEs
async function withIntel(findings) {
  if (!findings) return findings;
  const one = !(findings instanceof Map);
  const keys = one ? [null] : [...findings.keys()];
  const rows = one ? [findings] : [...findings.values()];
  if (!rows.length) return findings;
  const done = await require('../integrations/intel').annotate(rows).catch(() => rows);
  if (one) return done[0];
  // same keys, same order, whatever the rows carry
  return new Map(keys.map((k, n) => [k, done[n] || rows[n]]));
}

// version -> reason for everything the security policy leaves out. empty when off
// scope = the token's application and environment, so a waiver for dev never opens production
async function securityExclusions(ecosystem, name, scope) {
  const out = new Map();
  if (!enabled()) return out;
  const findings = await withIntel(await audit.findingsForPackage(name, ecosystem));
  for (const [version, finding] of findings) {
    if (!tooRisky(finding)) continue;
    if (await waived(ecosystem, name, version, finding, scope)) continue;
    out.set(version, reasonFor(finding));
  }
  return out;
}

// a waiver naming every advisory on the version, or null
function waived(ecosystem, name, version, finding, scope) {
  return require('./waivers').advisoryWaived(ecosystem, name, version, finding, scope).catch(() => null);
}

// one exact version, for a download asked for directly (a lockfile does that)
async function securityReason(ecosystem, name, version, scope) {
  if (!enabled()) return null;
  const finding = await withIntel(await audit.findingFor(name, version, ecosystem).catch(() => null));
  if (!tooRisky(finding)) return null;
  return (await waived(ecosystem, name, version, finding, scope)) ? null : reasonFor(finding);
}

function sessionOf(req) {
  const id = req.get('npm-session');
  return id && /^[A-Za-z0-9._-]{4,64}$/.test(id) ? id : null;
}

function who(req) {
  const id = req.npmIdentity || {};
  return {
    application: id.application || null,
    environment: id.environment || null,
    tokenName: id.name || null,
    userId: id.userId || null,
    ip: auth.clientIp(req),
    session: sessionOf(req)
  };
}

// [{ version, kind, reason, filename? }] -> [{ kind, reason, versions: [...] }], one entry per reason
function group(excluded) {
  const byReason = new Map();
  for (const x of excluded) {
    const key = `${x.kind}\n${x.reason}`;
    if (!byReason.has(key)) byReason.set(key, { kind: x.kind, reason: String(x.reason || '').slice(0, 300), versions: [], total: 0 });
    const g = byReason.get(key);
    const label = x.filename ? `${x.version} (${x.filename})` : String(x.version);
    if (g.versions.includes(label)) continue;
    g.total += 1;
    if (g.versions.length < MAX_VERSIONS_PER_REASON) g.versions.push(label.slice(0, 300));
  }
  return [...byReason.values()].slice(0, MAX_REASONS);
}

// Fire and forget. Only while the feature is on, and only answers that left something out:
// in whitelist mode nearly every answer leaves most versions out, logging all of those forever is just noise
function record(req, { ecosystem, name, offered, latest, excluded }) {
  if (!logging() || !excluded || !excluded.length) return;
  const w = who(req);
  const grouped = group(excluded);
  resolutions.record({
    ecosystem, name, application: w.application, environment: w.environment, tokenName: w.tokenName, userId: w.userId, ip: w.ip, session: w.session,
    offered: offered || 0, excludedCount: grouped.reduce((n, g) => n + g.total, 0), excluded: JSON.stringify(grouped),
    latest: latest ? String(latest).slice(0, 64) : null
  }).catch((err) => log.error('could not record a resolution', err.message));
}

// the download that followed. npm sends a session id, pip doesn't, so pip matches on address + token, recently
function noteSelected(req, ecosystem, name, version) {
  if (!logging()) return;
  const w = who(req);
  resolutions.noteSelected({ version: String(version).slice(0, 64), ecosystem, name, session: w.session, ip: w.ip, tokenName: w.tokenName })
    .catch((err) => log.error('could not note the selected version', err.message));
}

module.exports = {
  SEVERITIES, enabled, threshold, rank, tooRisky, why, withIntel, kevOn, epssBar, securityExclusions, securityReason, waived, record, noteSelected, group
};
