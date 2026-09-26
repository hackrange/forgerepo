// CVE intel for the portal and the scan: CISA KEV and FIRST EPSS per CVE, and how each feed last went.
// Author: Tim Rice

const db = require('../../db');

const CVE = /^CVE-\d{4}-\d{4,7}$/;

// every CVE the box has a reason to care about: named on a finding or on a stored advisory
async function knownCves(limit) {
  const rows = await db.query("SELECT cves FROM cve_findings WHERE cves <> '' UNION SELECT cves FROM cve_advisories WHERE cves <> ''");
  const out = new Set();
  for (const r of rows) {
    for (const part of String(r.cves || '').split(',')) {
      const cve = part.trim().toUpperCase();
      if (CVE.test(cve)) out.add(cve);
      if (out.size >= limit) return [...out];
    }
  }
  return [...out];
}

// the catalog replaces itself: listed ones marked, anything dropped from it unmarked. one transaction
async function replaceKev(rows) {
  await db.transaction(async (q) => {
    await q('UPDATE vuln_intel SET kev = 0, kev_added = NULL, kev_due = NULL, kev_ransomware = 0, kev_name = NULL WHERE kev = 1');
    for (let i = 0; i < rows.length; i += 500) {
      const batch = rows.slice(i, i + 500);
      await q(
        `INSERT INTO vuln_intel (cve, kev, kev_added, kev_due, kev_ransomware, kev_name)
         VALUES ${batch.map(() => '(?, 1, ?, ?, ?, ?)').join(',')}
         ON DUPLICATE KEY UPDATE kev = 1, kev_added = VALUES(kev_added), kev_due = VALUES(kev_due),
           kev_ransomware = VALUES(kev_ransomware), kev_name = VALUES(kev_name)`,
        batch.flatMap((r) => [r.cve, r.added, r.due, r.ransomware ? 1 : 0, r.name])
      );
    }
  });
}

async function saveEpss(rows) {
  for (let i = 0; i < rows.length; i += 500) {
    const batch = rows.slice(i, i + 500);
    await db.query(
      `INSERT INTO vuln_intel (cve, epss, epss_percentile, epss_date)
       VALUES ${batch.map(() => '(?, ?, ?, ?)').join(',')}
       ON DUPLICATE KEY UPDATE epss = VALUES(epss), epss_percentile = VALUES(epss_percentile), epss_date = VALUES(epss_date)`,
      batch.flatMap((r) => [r.cve, r.epss, r.percentile, r.date])
    );
  }
}

function forCves(cves) {
  if (!cves.length) return Promise.resolve([]);
  return db.query(
    `SELECT cve, kev, kev_added, kev_due, kev_ransomware, kev_name, epss, epss_percentile, epss_date
       FROM vuln_intel WHERE cve IN (${cves.map(() => '?').join(',')})`,
    cves
  );
}

function feedStates() {
  return db.query('SELECT feed, synced_at, checked_at, entries, error FROM intel_feeds');
}

// ok = synced now with that many entries, idle = checked with nothing to ask, otherwise only the check time and the error move
function noteFeed(feed, { ok, idle, entries, error }) {
  if (idle) {
    return db.query(
      'INSERT INTO intel_feeds (feed, checked_at, error) VALUES (?, NOW(), NULL) ON DUPLICATE KEY UPDATE checked_at = NOW(), error = NULL',
      [feed]
    );
  }
  return ok
    ? db.query(
      `INSERT INTO intel_feeds (feed, synced_at, checked_at, entries, error) VALUES (?, NOW(), NOW(), ?, NULL)
       ON DUPLICATE KEY UPDATE synced_at = NOW(), checked_at = NOW(), entries = VALUES(entries), error = NULL`,
      [feed, entries]
    )
    : db.query(
      `INSERT INTO intel_feeds (feed, checked_at, error) VALUES (?, NOW(), ?)
       ON DUPLICATE KEY UPDATE checked_at = NOW(), error = VALUES(error)`,
      [feed, String(error || 'failed').slice(0, 255)]
    );
}

async function counts() {
  const row = await db.one('SELECT COALESCE(SUM(kev = 1), 0) AS kev, COALESCE(SUM(epss IS NOT NULL), 0) AS epss FROM vuln_intel');
  const findings = await db.one(
    `SELECT COUNT(*) AS n FROM cve_findings f
      WHERE f.cves <> '' AND EXISTS (SELECT 1 FROM vuln_intel i WHERE i.kev = 1 AND FIND_IN_SET(i.cve, REPLACE(f.cves, ' ', '')))`
  );
  return { kev: Number(row.kev), epss: Number(row.epss), kevFindings: Number(findings.n) };
}

module.exports = { CVE, knownCves, replaceKev, saveEpss, forCves, feedStates, noteFeed, counts };
