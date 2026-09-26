// The rpm database of an image (Rocky, Alma, RHEL 9 and later keep it in sqlite), read without rpm installed.
// Author: Tim Rice
//
// the database came out of somebody's image, so it is opened read only with the schema distrusted, the one table is
// checked to be a table (a view could call anything), and every header is bounds checked before a byte is read

const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const MAX_PACKAGES = 50000;
const MAX_HEADER = 16 * 1024 * 1024;

const TAG = { NAME: 1000, VERSION: 1001, RELEASE: 1002, EPOCH: 1003, ARCH: 1022, SOURCERPM: 1044 };
const TYPE_INT32 = 4;
const TYPE_STRING = 6;
const TYPE_I18N = 9;

/**
 * a header blob as rpmdb.sqlite stores it: index count, data length, the index, then the data
 * @returns {Record<number, string|number>|null}
 */
function parseHeader(blob) {
  if (!Buffer.isBuffer(blob) || blob.length < 8 || blob.length > MAX_HEADER) return null;
  const il = blob.readUInt32BE(0);
  const dl = blob.readUInt32BE(4);
  const start = 8 + il * 16;
  if (il < 1 || il > 100000 || start + dl > blob.length) return null;
  const wanted = new Set(Object.values(TAG));
  const out = {};
  for (let i = 0; i < il; i += 1) {
    const at = 8 + i * 16;
    const tag = blob.readUInt32BE(at);
    if (!wanted.has(tag)) continue;
    const type = blob.readUInt32BE(at + 4);
    const offset = blob.readUInt32BE(at + 8);
    const count = blob.readUInt32BE(at + 12);
    if (offset >= dl || count < 1) continue;
    const from = start + offset;
    const end = start + dl;
    if (type === TYPE_INT32) {
      if (from + 4 <= end) out[tag] = blob.readUInt32BE(from);
    } else if (type === TYPE_STRING || type === TYPE_I18N) {
      const nul = blob.indexOf(0, from);
      if (nul > from && nul < end && nul - from <= 1024) out[tag] = blob.toString('utf8', from, nul);
    }
  }
  return out;
}

const PART = /^[A-Za-z0-9._+~^-]{1,128}$/;

// openssl-3.0.7-24.el9.src.rpm -> openssl
function sourceName(srpm) {
  const m = /^(.+)-[^-]+-[^-]+\.src\.rpm$/.exec(String(srpm || ''));
  return m && PART.test(m[1]) ? m[1] : null;
}

function packageOf(h) {
  if (!h) return null;
  const name = h[TAG.NAME];
  const version = h[TAG.VERSION];
  const release = h[TAG.RELEASE];
  if (typeof name !== 'string' || !PART.test(name) || name === 'gpg-pubkey') return null;
  if (typeof version !== 'string' || !PART.test(version) || typeof release !== 'string' || !PART.test(release)) return null;
  const epoch = typeof h[TAG.EPOCH] === 'number' && h[TAG.EPOCH] > 0 && h[TAG.EPOCH] < 100000 ? h[TAG.EPOCH] : 0;
  // advisories for Rocky and Alma name binary packages and write the epoch into the version when there is one
  const full = `${epoch ? `${epoch}:` : ''}${version}-${release}`;
  return { type: 'rpm', name, version: full, source: sourceName(h[TAG.SOURCERPM]) || undefined };
}

// buffer in, packages out. the file only exists for as long as the read takes
async function readSqlite(buffer, workDir) {
  let sqlite;
  try {
    sqlite = require('node:sqlite');
  } catch (err) {
    throw new Error('this node has no sqlite support');
  }
  await fsp.mkdir(workDir, { recursive: true });
  const file = path.join(workDir, `rpmdb.${process.pid}.${crypto.randomBytes(8).toString('hex')}.sqlite`);
  await fsp.writeFile(file, buffer, { mode: 0o600 });
  let db;
  try {
    db = new sqlite.DatabaseSync(file, { readOnly: true, enableForeignKeyConstraints: false, allowExtension: false });
    db.exec('PRAGMA trusted_schema = OFF');
    db.exec('PRAGMA cell_size_check = ON');
    const table = db.prepare("SELECT type FROM sqlite_master WHERE name = 'Packages'").get();
    if (!table || table.type !== 'table') throw new Error('it has no Packages table');
    const rows = db.prepare(`SELECT blob FROM Packages LIMIT ${MAX_PACKAGES}`).all();
    const out = [];
    for (const row of rows) {
      const raw = row.blob;
      const blob = raw instanceof Uint8Array ? Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength) : null;
      const pkg = packageOf(parseHeader(blob));
      if (pkg) out.push(pkg);
    }
    return out;
  } finally {
    try {
      if (db) db.close();
    } catch (err) {
      // already closed
    }
    await fsp.unlink(file).catch(() => {});
    await fsp.unlink(`${file}-journal`).catch(() => {});
  }
}

// ---------------------------------------------------------------- Berkeley DB, Rocky and RHEL 8, CentOS 7

const HASH_MAGIC = 0x061561;
const PAGE_HEADER = 26;
const P_HASH_UNSORTED = 2;
const P_HASH = 13;
const H_OFFPAGE = 3;

/**
 * the Packages file is a Berkeley DB hash. every header is too big to sit inline, so each hash entry points at a chain
 * of overflow pages holding it. every page number, offset and length is checked against the file before it is used
 */
function readBdb(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 512) throw new Error('it is too short to be a Berkeley DB file');
  let le;
  if (buf.readUInt32LE(12) === HASH_MAGIC) le = true;
  else if (buf.readUInt32BE(12) === HASH_MAGIC) le = false;
  else throw new Error('it is not a Berkeley DB hash file');
  const u32 = (at) => (le ? buf.readUInt32LE(at) : buf.readUInt32BE(at));
  const u16 = (at) => (le ? buf.readUInt16LE(at) : buf.readUInt16BE(at));
  const pageSize = u32(20);
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1))) throw new Error('its page size makes no sense');
  if (buf[24]) throw new Error('it is encrypted');
  const pages = Math.floor(buf.length / pageSize);
  const lastPage = Math.min(u32(32), pages - 1);

  const chain = (first) => {
    const parts = [];
    let total = 0;
    const seen = new Set();
    let pgno = first;
    while (pgno) {
      if (pgno > lastPage || seen.has(pgno)) return null;
      seen.add(pgno);
      const at = pgno * pageSize;
      const next = u32(at + 16);
      const used = next ? pageSize - PAGE_HEADER : u16(at + 22);
      if (used > pageSize - PAGE_HEADER) return null;
      parts.push(buf.subarray(at + PAGE_HEADER, at + PAGE_HEADER + used));
      total += used;
      if (total > MAX_HEADER) return null;
      pgno = next;
    }
    return Buffer.concat(parts);
  };

  const out = [];
  for (let pgno = 1; pgno <= lastPage && out.length < MAX_PACKAGES; pgno += 1) {
    const at = pgno * pageSize;
    const type = buf[at + 25];
    if (type !== P_HASH && type !== P_HASH_UNSORTED) continue;
    const entries = u16(at + 20);
    if (entries % 2 || PAGE_HEADER + entries * 2 > pageSize) continue;
    // keys and values alternate, the value is the second of each pair
    for (let i = 1; i < entries; i += 2) {
      const offset = u16(at + PAGE_HEADER + i * 2);
      if (offset + 12 > pageSize || buf[at + offset] !== H_OFFPAGE) continue;
      const blob = chain(u32(at + offset + 4));
      const pkg = blob && packageOf(parseHeader(blob));
      if (pkg) out.push(pkg);
    }
  }
  return out;
}

// whichever format the image keeps its database in
function read(buffer, format, workDir) {
  return format === 'bdb' ? Promise.resolve().then(() => readBdb(buffer)) : readSqlite(buffer, workDir);
}

module.exports = { read, readSqlite, readBdb, parseHeader, packageOf, sourceName, TAG };
