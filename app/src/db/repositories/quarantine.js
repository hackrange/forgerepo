// Quarantine holds, for the portal. placing and resolving them lives in quarantine.js
// Author: Tim Rice

const db = require('../../db');

const COLUMNS = `q.id, q.ecosystem, q.package_name, q.version, q.filename, q.sha256, q.source, q.reason, q.status,
  q.created_by, q.created_at, q.resolved_by, q.resolved_at, q.note`;

// versions still held or already turned down
function heldVersions(ecosystem, name) {
  return db.query(
    "SELECT version, status FROM quarantine_holds WHERE ecosystem = ? AND package_name = ? AND status IN ('open', 'rejected')",
    [ecosystem, name]
  );
}

// search arrives already escaped for LIKE
async function page(f, { limit, offset }) {
  const where = [];
  const params = [];
  if (f.status) {
    where.push('q.status = ?');
    params.push(f.status);
  }
  if (f.ecosystem) {
    where.push('q.ecosystem = ?');
    params.push(f.ecosystem);
  }
  if (f.search) {
    where.push('(q.package_name LIKE ? OR q.filename LIKE ?)');
    params.push(f.search, f.search);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = await db.query(
    `SELECT ${COLUMNS}, a.id AS artifact_id FROM quarantine_holds q
       LEFT JOIN artifacts a ON a.ecosystem = q.ecosystem AND a.package_name = q.package_name
                            AND a.version = q.version AND a.filename = q.filename
      ${clause} ORDER BY q.created_at DESC, q.id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM quarantine_holds q ${clause}`, params);
  return { rows, total: Number(total.n) };
}

async function openCount() {
  return Number((await db.one("SELECT COUNT(*) AS n FROM quarantine_holds WHERE status = 'open'")).n);
}

// ---------------------------------------------------------------- the gate and the hold lifecycle

const HOLD_COLUMNS = `id, ecosystem, package_name, version, filename, sha256, source, reason, status,
  created_by, created_at, resolved_by, resolved_at, note`;

// one exact file. version is '' for files that have none
const FILE_WHERE = 'ecosystem = ? AND package_name = ? AND version = ? AND filename = ?';
const fileArgs = (f) => [f.ecosystem, f.packageName, f.version || '', f.filename];

function holdCounts(file) {
  return db.one(
    `SELECT COALESCE(SUM(status = 'rejected'), 0) AS rejected, COALESCE(SUM(status = 'open'), 0) AS open, COUNT(*) AS n
       FROM quarantine_holds WHERE ${FILE_WHERE}`,
    fileArgs(file)
  );
}

// artifacts.status is only the display copy, the gate reads the holds
function setArtifactStatus(file, status) {
  return db.query(`UPDATE artifacts SET status = ? WHERE ${FILE_WHERE}`, [status, ...fileArgs(file)]);
}

function openHoldFor(file, source) {
  return db.one(`SELECT id FROM quarantine_holds WHERE ${FILE_WHERE} AND source = ? AND status = 'open' LIMIT 1`, [...fileArgs(file), source]);
}

// an open hold that now knows more, like the finding for a push that was waiting on its first scan
function retellHold(id, reason, sha256) {
  return db.query("UPDATE quarantine_holds SET reason = ?, sha256 = COALESCE(?, sha256) WHERE id = ? AND status = 'open'", [reason, sha256 || null, id]);
}

// text arrives already cut to fit
function createHold(file, { sha256, source, reason, user }) {
  return db.query(
    `INSERT INTO quarantine_holds (ecosystem, package_name, version, filename, sha256, source, reason, status, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, NOW())`,
    [...fileArgs(file), sha256, source, reason, user]
  );
}

function holdById(id) {
  return db.one(`SELECT ${HOLD_COLUMNS} FROM quarantine_holds WHERE id = ?`, [id]);
}

// only moves it if nobody else did first. returns rows changed
async function settleHold(id, fromStatus, { status, user, note }) {
  return (await db.query(
    'UPDATE quarantine_holds SET status = ?, resolved_by = ?, resolved_at = NOW(), note = ? WHERE id = ? AND status = ?',
    [status, user, note, id, fromStatus]
  )).affectedRows;
}

async function releaseOpen(file, source, { user, note }) {
  return (await db.query(
    `UPDATE quarantine_holds SET status = 'released', resolved_by = ?, resolved_at = NOW(), note = ?
      WHERE ${FILE_WHERE} AND source = ? AND status = 'open'`,
    [user, note, ...fileArgs(file), source]
  )).affectedRows;
}

function liveHolds(file) {
  return db.query(`SELECT id, status, reason, source FROM quarantine_holds WHERE ${FILE_WHERE} AND status IN ('open', 'rejected') ORDER BY id`, fileArgs(file));
}

function liveForPackage(ecosystem, name) {
  return db.query(
    "SELECT version, filename, status, source FROM quarantine_holds WHERE ecosystem = ? AND package_name = ? AND status IN ('open', 'rejected')",
    [ecosystem, name]
  );
}

// ---------------------------------------------------------------- the holds malware scans placed

// still held or rejected because a scanner flagged them, newest first
function malwareHolds(limit) {
  return db.query(
    `SELECT ecosystem, package_name, version, filename, status, reason, created_at FROM quarantine_holds
      WHERE source = 'malware' AND status IN ('open', 'rejected')
      ORDER BY created_at DESC LIMIT ?`,
    [limit]
  );
}

async function malwareHoldCount() {
  return Number((await db.one("SELECT COUNT(*) AS n FROM quarantine_holds WHERE source = 'malware' AND status IN ('open', 'rejected')")).n);
}

// ---------------------------------------------------------------- the holds licenses placed

// open, or rejected by the system rather than by a person
const LICENSE_LIVE = "(status = 'open' OR (status = 'rejected' AND resolved_by = 'system'))";

function licenseHoldsToLift(file) {
  return db.query(`SELECT id FROM quarantine_holds WHERE ${FILE_WHERE} AND source = 'license' AND ${LICENSE_LIVE}`, fileArgs(file));
}

function licenseHoldsFor(file) {
  return db.query(`SELECT id, status, resolved_by FROM quarantine_holds WHERE ${FILE_WHERE} AND source = 'license' ORDER BY id DESC`, fileArgs(file));
}

// every file licenses still hold, or just the ones of one package
function licenseHeldFiles(pkg) {
  return pkg
    ? db.query(
      `SELECT DISTINCT ecosystem, package_name, version, filename FROM quarantine_holds
        WHERE source = 'license' AND ecosystem = ? AND package_name = ? AND ${LICENSE_LIVE}`,
      [pkg.ecosystem, pkg.name]
    )
    : db.query(`SELECT DISTINCT ecosystem, package_name, version, filename FROM quarantine_holds WHERE source = 'license' AND ${LICENSE_LIVE}`);
}

function licenseHoldCounts() {
  return db.one("SELECT COALESCE(SUM(status = 'open'), 0) AS open, COALESCE(SUM(status = 'rejected'), 0) AS rejected FROM quarantine_holds WHERE source = 'license'");
}

module.exports = {
  heldVersions, page, openCount,
  holdCounts, setArtifactStatus, openHoldFor, retellHold, createHold, holdById, settleHold, releaseOpen, liveHolds, liveForPackage,
  licenseHoldsToLift, licenseHoldsFor, licenseHeldFiles, licenseHoldCounts, malwareHolds, malwareHoldCount
};
