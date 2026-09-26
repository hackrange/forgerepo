// Integrity alerts for the portal list. recording and resolving them lives in integrity.js
// Author: Tim Rice

const db = require('../../db');

const COLUMNS = `e.id, e.kind, e.ecosystem, e.package_name, e.version, e.filename, e.upstream, e.expected,
  e.observed, e.held_sha256, e.held_size, e.status, e.occurrences, e.first_seen, e.last_seen,
  e.resolved_by, e.resolved_at, e.note`;

// search arrives already escaped for LIKE
async function page(f, { limit, offset }) {
  const where = [];
  const params = [];
  if (f.status) {
    where.push('e.status = ?');
    params.push(f.status);
  }
  if (f.ecosystem) {
    where.push('e.ecosystem = ?');
    params.push(f.ecosystem);
  }
  if (f.search) {
    where.push('(e.package_name LIKE ? OR e.filename LIKE ?)');
    params.push(f.search, f.search);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = await db.query(
    `SELECT ${COLUMNS} FROM integrity_events e ${clause} ORDER BY e.last_seen DESC, e.id DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  const total = await db.one(`SELECT COUNT(*) AS n FROM integrity_events e ${clause}`, params);
  return { rows, total: Number(total.n) };
}

async function openCount() {
  return Number((await db.one("SELECT COUNT(*) AS n FROM integrity_events WHERE status = 'open'")).n);
}

// ---------------------------------------------------------------- recording and settling

const EVENT_COLUMNS = `id, kind, ecosystem, package_name, version, filename, artifact_id, upstream, expected, observed,
  held_sha256, held_size, metadata, status, occurrences, first_seen, last_seen, resolved_by, resolved_at, note`;

// one row per distinct change, a repeat bumps the count. the raw result, affectedRows 1 = new
function record(e) {
  return db.query(
    `INSERT INTO integrity_events
       (fingerprint, kind, ecosystem, package_name, version, filename, artifact_id, upstream,
        expected, observed, held_sha256, held_size, metadata, status, occurrences, first_seen, last_seen)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, NOW(), NOW())
     ON DUPLICATE KEY UPDATE occurrences = occurrences + 1, last_seen = NOW(),
       held_sha256 = COALESCE(held_sha256, VALUES(held_sha256)), held_size = COALESCE(held_size, VALUES(held_size))`,
    [
      e.fingerprint, e.kind, e.ecosystem, e.packageName, e.version, e.filename, e.artifactId,
      e.upstream, e.expected, e.observed, e.heldSha256, e.heldSize, e.metadata
    ]
  );
}

function eventById(id) {
  return db.one(`SELECT ${EVENT_COLUMNS} FROM integrity_events WHERE id = ?`, [id]);
}

// only an open one. returns rows changed
async function settle(id, { status, user, note }) {
  return (await db.query(
    `UPDATE integrity_events SET status = ?, resolved_by = ?, resolved_at = NOW(), note = ?
      WHERE id = ? AND status = 'open'`,
    [status, user, note, id]
  )).affectedRows;
}

// open alerts first seen after a moment, for the digest
function openSince(since, limit) {
  return db.query(
    `SELECT kind, ecosystem, package_name, version, filename, first_seen FROM integrity_events
      WHERE status = 'open' AND first_seen > ? ORDER BY first_seen LIMIT ?`,
    [since, limit]
  );
}

// an open alert still holding these bytes counts as a user of them
async function holdsDigest(sha256) {
  return !!(await db.one("SELECT id FROM integrity_events WHERE held_sha256 = ? AND status = 'open' LIMIT 1", [sha256]));
}

module.exports = { page, openCount, record, eventById, settle, openSince, holdsDigest };
