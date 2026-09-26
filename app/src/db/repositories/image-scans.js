// Image scans: one row per image digest pulled through here, and the packages found inside it.
// Author: Tim Rice

const db = require('../../db');
const { sevRank } = require('./severity');

const COLUMNS = `id, repository, digest, status, os, feed, components, vulnerable, severity, fixable_severity, notes, error, attempts,
  created_at, started_at, scanned_at, checked_at, updated_at`;
const STATUSES = ['queued', 'scanning', 'done', 'skipped', 'failed'];
// a scan that has not finished in this long died with its node
const STALE_MINUTES = 60;
const MAX_ATTEMPTS = 5;
const CHUNK = 500;

async function ensure(repository, digest) {
  await db.query('INSERT IGNORE INTO image_scans (repository, digest) VALUES (?, ?)', [repository, digest]);
  return db.one(`SELECT ${COLUMNS} FROM image_scans WHERE repository = ? AND digest = ?`, [repository, digest]);
}

function byKey(repository, digest) {
  return db.one(`SELECT ${COLUMNS} FROM image_scans WHERE repository = ? AND digest = ?`, [repository, digest]);
}

// one node scans an image at a time. a claim on a row somebody else is still scanning fails
async function claim(id) {
  const result = await db.query(
    `UPDATE image_scans SET status = 'scanning', started_at = NOW(), attempts = attempts + 1, error = ''
      WHERE id = ? AND (status <> 'scanning' OR started_at < NOW() - INTERVAL ${STALE_MINUTES} MINUTE)`,
    [id]
  );
  return result.affectedRows === 1;
}

async function finish(id, f) {
  await db.query(
    `UPDATE image_scans SET status = ?, os = ?, feed = ?, components = ?, vulnerable = ?, severity = ?, fixable_severity = ?, notes = ?, error = ?,
            scanned_at = IF(? IN ('done', 'skipped'), NOW(), scanned_at), checked_at = IF(? = 'done', NOW(), checked_at)
      WHERE id = ?`,
    [
      f.status, String(f.os || '').slice(0, 128), String(f.feed || '').slice(0, 64), f.components || 0, f.vulnerable || 0,
      String(f.severity || '').slice(0, 16), String(f.fixable || '').slice(0, 16), JSON.stringify((f.notes || []).slice(0, 20).map((n) => String(n).slice(0, 300))),
      String(f.error || '').slice(0, 512), f.status, f.status, id
    ]
  );
}

async function checked(id, vulnerable, severity, fixable) {
  await db.query('UPDATE image_scans SET vulnerable = ?, severity = ?, fixable_severity = ?, checked_at = NOW() WHERE id = ?',
    [vulnerable, String(severity || '').slice(0, 16), String(fixable || '').slice(0, 16), id]);
}

// every package in the image, what was matched against it replaces what was there
async function saveComponents(scanId, components) {
  await db.transaction(async (query) => {
    await query('DELETE FROM image_components WHERE scan_id = ?', [scanId]);
    for (let i = 0; i < components.length; i += CHUNK) {
      const chunk = components.slice(i, i + CHUNK);
      await query(
        `INSERT INTO image_components (scan_id, type, name, version, ecosystem, binaries, advisories, cves, severity, fixable_severity, fixed_in, summary)
         VALUES ${chunk.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ')}`,
        chunk.flatMap((c) => [
          scanId, c.type, String(c.name).slice(0, 214), String(c.version).slice(0, 128), c.ecosystem ? String(c.ecosystem).slice(0, 64) : null,
          (c.binaries || []).join(',').slice(0, 1024), String(c.advisories || '').slice(0, 8000), String(c.cves || '').slice(0, 512),
          String(c.severity || '').slice(0, 16), String(c.fixable_severity || '').slice(0, 16),
          c.fixed_in ? String(c.fixed_in).slice(0, 128) : null, String(c.summary || '').slice(0, 512)
        ])
      );
    }
  });
}

async function components(scanId, { vulnerableOnly = false, limit = 60000 } = {}) {
  const rows = await db.query(
    `SELECT type, name, version, ecosystem, binaries, advisories, cves, severity, fixable_severity, fixed_in, summary
       FROM image_components WHERE scan_id = ? ${vulnerableOnly ? "AND advisories <> ''" : ''}
      ORDER BY ${sevRank('severity')} DESC, name ASC LIMIT ?`,
    [scanId, limit]
  );
  return rows.map((r) => ({ ...r, binaries: r.binaries ? r.binaries.split(',') : [] }));
}

// done images, newest first, for the scheduled recheck
function done(limit) {
  return db.query(`SELECT id, repository, digest FROM image_scans WHERE status = 'done' ORDER BY id DESC LIMIT ?`, [limit]);
}

// rows a node never got to, died on, or failed on a while ago
function resumable(limit) {
  return db.query(
    `SELECT repository, digest FROM image_scans
      WHERE attempts < ${MAX_ATTEMPTS}
        AND (status = 'queued'
          OR (status = 'scanning' AND started_at < NOW() - INTERVAL ${STALE_MINUTES} MINUTE)
          OR (status = 'failed' AND updated_at < NOW() - INTERVAL ${STALE_MINUTES} MINUTE))
      ORDER BY id LIMIT ?`,
    [limit]
  );
}

async function page(f, { limit, offset }) {
  const where = [];
  const params = [];
  if (f.status) { where.push('status = ?'); params.push(f.status); }
  if (f.search) { where.push('(repository LIKE ? OR digest LIKE ?)'); params.push(f.search, f.search); }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = await db.query(`SELECT ${COLUMNS} FROM image_scans ${clause} ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
  const total = await db.one(`SELECT COUNT(*) AS n FROM image_scans ${clause}`, params);
  const counts = await db.query('SELECT status, COUNT(*) AS n FROM image_scans GROUP BY status');
  return { rows: rows.map(withNotes), total: Number(total.n), counts };
}

function withNotes(row) {
  if (!row) return row;
  let notes = [];
  try {
    notes = JSON.parse(row.notes || '[]');
  } catch (err) {
    notes = [];
  }
  return { ...row, notes: Array.isArray(notes) ? notes : [] };
}

module.exports = { STATUSES, ensure, byKey, claim, finish, checked, saveComponents, components, done, resumable, page, withNotes };
