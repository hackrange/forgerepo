// The dashboard's cards: what needs a look, and the packages behind each number.
// Author: Tim Rice

const db = require('../../db');
const { sevRank } = require('./severity');

// the checks that count as someone trying to get a bad package in. the rest (rules, cooling off) are just policy
const ATTACKS = ['malware', 'typosquat', 'killswitch'];
const LIST_LIMIT = 100;

function vulnerableCounts() {
  return db.one(
    `SELECT COUNT(*) AS versions, COUNT(DISTINCT ecosystem, package_name) AS packages,
            COALESCE(SUM(severity IN ('critical', 'high')), 0) AS serious,
            COALESCE(SUM(cves <> '' AND EXISTS (SELECT 1 FROM vuln_intel i WHERE i.kev = 1 AND FIND_IN_SET(i.cve, REPLACE(cves, ' ', '')))), 0) AS kev
       FROM cve_findings`
  );
}

function vulnerableList() {
  return db.query(
    `SELECT ecosystem, package_name, version, severity, cves, fixed_in, last_seen
       FROM cve_findings ORDER BY ${sevRank('severity')} DESC, last_seen DESC LIMIT ?`,
    [LIST_LIMIT]
  );
}

// refused by one of the attack checks, per check, in the last so many hours
function attemptCounts(hours) {
  return db.query(
    `SELECT blocked_by, COUNT(*) AS n FROM access_log
      WHERE blocked_by IN (?, ?, ?) AND ts > DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY blocked_by`,
    [...ATTACKS, hours]
  );
}

// the bad packages known right now, whether anyone has asked for them yet or not
async function standingCounts() {
  const [files, squats, kills] = await Promise.all([
    db.one(
      `SELECT COUNT(DISTINCT a.ecosystem, a.package_name) AS n
         FROM artifact_scans s JOIN artifacts a ON a.sha256 = s.sha256
        WHERE s.status IN ('MALICIOUS', 'SUSPICIOUS')`
    ),
    db.one("SELECT COUNT(*) AS n FROM typosquat_findings WHERE status = 'open' AND last_action = 'blocked'"),
    db.one("SELECT COUNT(*) AS n FROM kill_switches WHERE status = 'active'")
  ]);
  return { malware: Number(files.n), typosquat: Number(squats.n), killswitch: Number(kills.n) };
}

// flagged files, blocked lookalikes and kill switches, plus how often each was tried in the last so many days
async function maliciousList(days) {
  const [files, squats, kills, attempts] = await Promise.all([
    db.query(
      `SELECT a.ecosystem, a.package_name, a.version, s.status, s.scanner, s.signature, MAX(s.scan_time) AS seen
         FROM artifact_scans s JOIN artifacts a ON a.sha256 = s.sha256
        WHERE s.status IN ('MALICIOUS', 'SUSPICIOUS')
        GROUP BY a.ecosystem, a.package_name, a.version, s.status, s.scanner, s.signature
        ORDER BY seen DESC LIMIT ?`,
      [LIST_LIMIT]
    ),
    db.query(
      `SELECT ecosystem, package_name, looks_like, technique, last_seen FROM typosquat_findings
        WHERE status = 'open' AND last_action = 'blocked' ORDER BY last_seen DESC LIMIT ?`,
      [LIST_LIMIT]
    ),
    db.query(
      `SELECT kind, subject, ecosystem, package_name, version_range, reason, created_at FROM kill_switches
        WHERE status = 'active' ORDER BY created_at DESC LIMIT ?`,
      [LIST_LIMIT]
    ),
    db.query(
      `SELECT ecosystem, package_name, blocked_by, COUNT(*) AS attempts, MAX(ts) AS last_attempt
         FROM access_log
        WHERE blocked_by IN (?, ?, ?) AND package_name IS NOT NULL AND ts > DATE_SUB(NOW(), INTERVAL ? DAY)
        GROUP BY ecosystem, package_name, blocked_by`,
      [...ATTACKS, days]
    )
  ]);
  return { files, squats, kills, attempts };
}

function licenseCounts() {
  return db.query(
    `SELECT license_verdict AS verdict, COUNT(*) AS files, COUNT(DISTINCT ecosystem, package_name) AS packages
       FROM artifacts
      WHERE license_checked_at IS NOT NULL AND license_verdict IN ('blocked', 'review')
      GROUP BY license_verdict`
  );
}

function licenseList() {
  return db.query(
    `SELECT ecosystem, package_name, version, license_expression, license_verdict, license_note, last_seen
       FROM artifacts
      WHERE license_checked_at IS NOT NULL AND license_verdict IN ('blocked', 'review')
      ORDER BY license_verdict = 'blocked' DESC, last_seen DESC LIMIT ?`,
    [LIST_LIMIT]
  );
}

// served = bytes that went out to clients, fetched = the part an upstream had to send us first.
// the average only counts whole days, today is still going
// a publish or an upload is bytes coming in from a client, not bytes served or fetched
const PUSHED = "(method IN ('PUT', 'POST') AND COALESCE(reason, '') REGEXP '^(published|uploaded), held')";
const SUMS = `COALESCE(SUM(CASE WHEN NOT ${PUSHED} THEN bytes END), 0) AS served,
              COALESCE(SUM(CASE WHEN cache_hit = 0 AND NOT ${PUSHED} THEN bytes END), 0) AS fetched,
              COALESCE(SUM(CASE WHEN ${PUSHED} THEN bytes END), 0) AS pushed`;

async function bandwidth(windowDays) {
  const [last24, days] = await Promise.all([
    db.one(
      `SELECT ${SUMS}
         FROM access_log WHERE action IN ('allow', 'audit') AND ts > DATE_SUB(NOW(), INTERVAL 24 HOUR)`
    ),
    db.one(
      `SELECT ${SUMS},
              LEAST(?, COALESCE(DATEDIFF(CURDATE(), DATE(MIN(ts))), 0)) AS span
         FROM access_log
        WHERE action IN ('allow', 'audit') AND ts >= DATE_SUB(CURDATE(), INTERVAL ? DAY) AND ts < CURDATE()`,
      [windowDays, windowDays]
    )
  ]);
  return { last24, days };
}

// ---------------------------------------------------------------- what needs a decision

// open integrity alerts, and how many packages they sit on
function integrityCounts() {
  return db.one("SELECT COUNT(*) AS open, COUNT(DISTINCT ecosystem, package_name) AS packages FROM integrity_events WHERE status = 'open'");
}

function integrityList() {
  return db.query(
    `SELECT ecosystem, package_name, version, kind, expected, observed, occurrences, last_seen
       FROM integrity_events WHERE status = 'open' ORDER BY last_seen DESC LIMIT ?`,
    [LIST_LIMIT]
  );
}

// null = every waiver (staff who decide them), a user id = the ones that user asked for, anything else = none at all
function ownedBy(ownerId) {
  if (ownerId === null) return { sql: '', params: [] };
  if (Number.isSafeInteger(ownerId) && ownerId > 0) return { sql: ' AND w.requested_by_id = ?', params: [ownerId] };
  return { sql: ' AND 1 = 0', params: [] };
}

// active waivers ending within a week, and the ones that ran out in the last week
function waiverCounts(ownerId) {
  const o = ownedBy(ownerId);
  return db.one(
    `SELECT COALESCE(SUM(status = 'active' AND expires_at > NOW() AND expires_at <= DATE_ADD(NOW(), INTERVAL 7 DAY)), 0) AS ending,
            COALESCE(SUM(status IN ('active', 'expired') AND expires_at <= NOW() AND expires_at > DATE_SUB(NOW(), INTERVAL 7 DAY)), 0) AS expired
       FROM waivers w WHERE 1 = 1${o.sql}`,
    o.params
  );
}

function waiverList(ownerId) {
  const o = ownedBy(ownerId);
  return db.query(
    `SELECT kind, ecosystem, package_name, version_range, subject, reference, status, expires_at FROM waivers w
      WHERE status IN ('active', 'expired') AND expires_at > DATE_SUB(NOW(), INTERVAL 7 DAY) AND expires_at <= DATE_ADD(NOW(), INTERVAL 7 DAY)${o.sql}
      ORDER BY expires_at LIMIT ?`,
    [...o.params, LIST_LIMIT]
  );
}

// vulnerable versions somebody actually pulled lately: the ones worth fixing first
const RISKY_FROM = `FROM cve_findings f
       JOIN consumption c ON c.ecosystem = f.ecosystem AND c.package_name = f.package_name AND c.version = f.version
        AND c.last_seen > DATE_SUB(NOW(), INTERVAL ? DAY)`;

function riskyCounts(days) {
  return db.one(
    `SELECT COUNT(DISTINCT f.id) AS versions, COUNT(DISTINCT c.application) AS applications,
            COUNT(DISTINCT CASE WHEN f.cves <> '' AND EXISTS (SELECT 1 FROM vuln_intel i WHERE i.kev = 1 AND FIND_IN_SET(i.cve, REPLACE(f.cves, ' ', ''))) THEN f.id END) AS kev
       ${RISKY_FROM}`,
    [days]
  );
}

// a few hundred of the worst by severity, the dashboard ranks them with KEV and EPSS on top
function riskyList(days) {
  return db.query(
    `SELECT f.ecosystem, f.package_name, f.version, f.severity, f.cves, f.fixed_in,
            COALESCE(SUM(c.downloads), 0) AS downloads, COUNT(DISTINCT c.application) AS apps, MAX(c.last_seen) AS pulled_at
       ${RISKY_FROM}
      GROUP BY f.id, f.ecosystem, f.package_name, f.version, f.severity, f.cves, f.fixed_in
      ORDER BY ${sevRank('f.severity')} DESC, downloads DESC LIMIT 300`,
    [days]
  );
}

// by the application and environment on the token, the traffic log's own words
function topApplications(days) {
  return db.query(
    `SELECT application, environment, COUNT(*) AS requests, COUNT(DISTINCT package_name) AS packages, COALESCE(SUM(action = 'deny'), 0) AS blocked
       FROM access_log WHERE ts > DATE_SUB(NOW(), INTERVAL ? DAY) AND application IS NOT NULL
      GROUP BY application, environment ORDER BY requests DESC LIMIT 10`,
    [days]
  );
}

module.exports = {
  ATTACKS, LIST_LIMIT, vulnerableCounts, vulnerableList, attemptCounts, standingCounts, maliciousList,
  licenseCounts, licenseList, bandwidth, integrityCounts, integrityList, waiverCounts, waiverList, riskyCounts, riskyList, topApplications
};
