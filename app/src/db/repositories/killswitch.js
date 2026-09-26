// Kill switches for the portal. making and lifting one lives in killswitch.js
// Author: Tim Rice

const db = require('../../db');

// what a name in an advisory feed can look like. anything else (like "and 3 more") is not a name
const ADVISORY_NAME = /^[A-Z][A-Z0-9]{1,15}-[A-Z0-9][A-Z0-9._:-]{1,62}$/;

function active() {
  return db.query("SELECT * FROM kill_switches WHERE status = 'active' ORDER BY created_at DESC");
}

function lifted() {
  return db.query("SELECT * FROM kill_switches WHERE status = 'lifted' ORDER BY lifted_at DESC LIMIT 100");
}

function byId(id) {
  return db.one('SELECT * FROM kill_switches WHERE id = ?', [id]);
}

// ---------------------------------------------------------------- what the gate reads, and the button

function liveEntries() {
  return db.query(
    "SELECT id, kind, ecosystem, package_name, version_range, subject, reason, created_by, created_at FROM kill_switches WHERE status = 'active' ORDER BY id"
  );
}

function activeDuplicate({ kind, ecosystem, name, range, subject }) {
  return db.one(
    "SELECT id FROM kill_switches WHERE status = 'active' AND kind = ? AND ecosystem = ? AND package_name = ? AND version_range = ? AND subject = ?",
    [kind, ecosystem, name, range, subject]
  );
}

// reason and user arrive already cleaned and cut to fit
function create({ kind, ecosystem, name, range, subject, reason, user }) {
  return db.query(
    'INSERT INTO kill_switches (kind, ecosystem, package_name, version_range, subject, reason, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [kind, ecosystem, name, range, subject, reason, user]
  );
}

// any kill of this, active or lifted
function everKilled(kind, subject) {
  return db.one('SELECT id FROM kill_switches WHERE kind = ? AND subject = ? LIMIT 1', [kind, subject]);
}

function setPurged(id, purged) {
  return db.query('UPDATE kill_switches SET purged_files = ? WHERE id = ?', [purged, id]);
}

// returns rows changed, 0 = someone lifted it first
async function lift(id, { user, note }) {
  return (await db.query(
    "UPDATE kill_switches SET status = 'lifted', lifted_by = ?, lifted_at = NOW(), lift_note = ? WHERE id = ? AND status = 'active'",
    [user, note, id]
  )).affectedRows;
}

// ---------------------------------------------------------------- what a hash or advisory kill reaches

// every file seen with these bytes, under whatever name and registry it came from
function filesWithDigest(sha256, limit) {
  return db.query('SELECT ecosystem, package_name, version, filename FROM artifacts WHERE sha256 = ? LIMIT ?', [sha256, limit]);
}

// every name one advisory goes by: its own id, its aliases and its CVEs. GHSA and PYSEC are often one bug
async function advisoryNames(id) {
  const rows = await db.query(
    `SELECT id, aliases, cves FROM cve_advisories
      WHERE id = ? OR FIND_IN_SET(?, REPLACE(COALESCE(aliases, ''), ' ', '')) OR FIND_IN_SET(?, REPLACE(cves, ' ', ''))
      LIMIT 50`,
    [id, id, id]
  );
  const names = new Set([String(id).toUpperCase()]);
  for (const r of rows) {
    for (const n of [r.id, ...String(r.aliases || '').split(','), ...String(r.cves || '').split(',')]) {
      const t = String(n || '').trim().toUpperCase();
      if (ADVISORY_NAME.test(t)) names.add(t);
    }
  }
  return [...names].slice(0, 60);
}

// the versions the vulnerability scan recorded under any of those names
function findingsNaming(names, limit) {
  if (!names.length) return Promise.resolve([]);
  const clause = names.map(() => "FIND_IN_SET(?, advisories) OR FIND_IN_SET(?, REPLACE(cves, ' ', ''))").join(' OR ');
  return db.query(
    `SELECT ecosystem, package_name, version FROM cve_findings WHERE ${clause} LIMIT ?`,
    [...names.flatMap((n) => [n, n]), limit]
  );
}

module.exports = {
  active, lifted, byId, liveEntries, activeDuplicate, create, everKilled, setPurged, lift, filesWithDigest, advisoryNames, findingsNaming
};
