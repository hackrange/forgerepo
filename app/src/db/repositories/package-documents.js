// Package metadata for the ecosystems that came after npm and PyPI, one table for all of them.
// Author: Tim Rice
// a document is json, keyed by ecosystem, the folded package name and what kind of document it is (a summary, an index)

const db = require('../../db');

async function get(ecosystem, name, kind) {
  const row = await db.one(
    'SELECT body, source, fetched_at FROM package_documents WHERE ecosystem = ? AND name = ? AND kind = ?',
    [ecosystem, name, kind]
  );
  if (!row) return null;
  let doc;
  try {
    doc = JSON.parse(Buffer.isBuffer(row.body) ? row.body.toString('utf8') : String(row.body));
  } catch (err) {
    return null;
  }
  return { doc, source: row.source, fetchedAt: new Date(row.fetched_at) };
}

async function put(ecosystem, name, kind, doc, source) {
  const body = Buffer.from(JSON.stringify(doc), 'utf8');
  await db.query(
    `INSERT INTO package_documents (ecosystem, name, kind, body, bytes, source, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE body = VALUES(body), bytes = VALUES(bytes), source = VALUES(source), fetched_at = NOW()`,
    [ecosystem, name, kind, body, body.length, source ? String(source).slice(0, 64) : null]
  );
}

// the package names summed up for an ecosystem so far
async function names(ecosystem, limit = 100000) {
  // what was pushed here counts as a name this box has, the same as one it mirrors
  return (await db.query("SELECT DISTINCT name FROM package_documents WHERE ecosystem = ? AND kind IN ('summary', 'published') ORDER BY name LIMIT ?", [ecosystem, limit])).map((r) => r.name);
}

function forget(ecosystem, name) {
  return db.query('DELETE FROM package_documents WHERE ecosystem = ? AND name = ?', [ecosystem, name]);
}

module.exports = { get, put, names, forget };
