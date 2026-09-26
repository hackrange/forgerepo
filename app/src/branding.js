// Branding. an admin's own header icon and favicon instead of the anvil.
// Author: Tim Rice
// the type is read off the bytes, never taken from the upload. no SVG, it can carry script

const crypto = require('crypto');
const db = require('./db');
const { httpError } = require('./lib/errors');

const KINDS = { icon: ['png', 'jpeg', 'gif', 'webp'], favicon: ['png', 'ico', 'gif', 'jpeg', 'webp'] };
const TYPES = { png: 'image/png', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', ico: 'image/x-icon' };
const MAX_BYTES = 256 * 1024;
const MIN_SIDE = 16;
const MAX_SIDE = 1024;
const CACHE_MS = 30000;
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

//hasOwnProperty, or "__proto__" counts as a kind
const isKind = (kind) => Object.prototype.hasOwnProperty.call(KINDS, kind);

// ---------------------------------------------------------------- what the bytes are

function jpegSize(buf) {
  let i = 2;
  while (i + 9 < buf.length) {
    if (buf[i] !== 0xff) return null;
    const marker = buf[i + 1];
    if (marker === 0xff) {
      i += 1;
    } else if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
      i += 2;
    } else {
      const len = buf.readUInt16BE(i + 2);
      if (len < 2) return null;
      // SOF markers, minus DHT/JPG/DAC which share the range
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { format: 'jpeg', height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
      }
      i += 2 + len;
    }
  }
  return null;
}

function webpSize(buf) {
  if (buf.length < 30) return null;
  const chunk = buf.toString('latin1', 12, 16);
  if (chunk === 'VP8 ') {
    if (buf[23] !== 0x9d || buf[24] !== 0x01 || buf[25] !== 0x2a) return null;
    return { format: 'webp', width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === 'VP8L') {
    if (buf[20] !== 0x2f) return null;
    const bits = buf.readUInt32LE(21);
    return { format: 'webp', width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
  }
  if (chunk === 'VP8X') return { format: 'webp', width: buf.readUIntLE(24, 3) + 1, height: buf.readUIntLE(27, 3) + 1 };
  return null;
}

// every entry has to point inside the file, or it isn't one
function icoSize(buf) {
  const count = buf.readUInt16LE(4);
  if (count < 1 || count > 64 || buf.length < 6 + 16 * count) return null;
  let width = 0;
  let height = 0;
  for (let n = 0; n < count; n += 1) {
    const at = 6 + 16 * n;
    const w = buf[at] || 256;
    const h = buf[at + 1] || 256;
    const size = buf.readUInt32LE(at + 8);
    const offset = buf.readUInt32LE(at + 12);
    if (!size || offset < 6 + 16 * count || offset + size > buf.length) return null;
    if (w * h > width * height) {
      width = w;
      height = h;
    }
  }
  return { format: 'ico', width, height };
}

function sniff(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf.subarray(0, 8).equals(PNG_SIG)) {
    if (buf.length < 24 || buf.toString('latin1', 12, 16) !== 'IHDR') return null;
    return { format: 'png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  }
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return jpegSize(buf);
  const six = buf.toString('latin1', 0, 6);
  if (six === 'GIF87a' || six === 'GIF89a') return { format: 'gif', width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
  if (buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return webpSize(buf);
  if (buf.readUInt16LE(0) === 0 && buf.readUInt16LE(2) === 1) return icoSize(buf);
  return null;
}

function decode(data) {
  const raw = String(data || '');
  if (raw.length > Math.ceil(MAX_BYTES / 3) * 4 + 100) throw httpError(400, `that image is too big, ${MAX_BYTES / 1024}KB at most`);
  const text = raw.replace(/^data:[\w.+-]+\/[\w.+-]+;base64,/, '');
  if (!text) throw httpError(400, 'no image came with that');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw httpError(400, 'the image did not arrive as base64');
  return Buffer.from(text, 'base64');
}

function check(kind, buf) {
  if (!isKind(kind)) throw httpError(404, 'there is no such image to set');
  if (!buf || !buf.length) throw httpError(400, 'that file is empty');
  if (buf.length > MAX_BYTES) throw httpError(400, `that image is too big, ${MAX_BYTES / 1024}KB at most`);
  const info = sniff(buf);
  if (!info) throw httpError(400, 'that is not a PNG, JPEG, GIF, WebP or ICO image. SVG is not accepted, it can carry script');
  if (!KINDS[kind].includes(info.format)) {
    throw httpError(400, `a ${info.format.toUpperCase()} cannot be the ${kind}, use ${KINDS[kind].map((f) => f.toUpperCase()).join(', ')}`);
  }
  if (info.width < MIN_SIDE || info.height < MIN_SIDE || info.width > MAX_SIDE || info.height > MAX_SIDE) {
    throw httpError(400, `the image has to be ${MIN_SIDE} to ${MAX_SIDE} pixels a side, this one is ${info.width}x${info.height}`);
  }
  return { ...info, type: TYPES[info.format] };
}

// ---------------------------------------------------------------- stored

let cached = null;
let cachedAt = 0;
const bodies = new Map();

function invalidate() {
  cached = null;
}

// { icon, favicon }, each null or { type, sha256, width, height, updatedBy, updatedAt }. no bytes
async function current() {
  if (cached && Date.now() - cachedAt < CACHE_MS) return cached;
  const rows = await db.query('SELECT kind, content_type, sha256, width, height, updated_by, updated_at FROM branding');
  const out = { icon: null, favicon: null };
  for (const r of rows) {
    if (!isKind(r.kind)) continue;
    out[r.kind] = { type: r.content_type, sha256: r.sha256, width: r.width, height: r.height, updatedBy: r.updated_by, updatedAt: r.updated_at };
  }
  cached = out;
  cachedAt = Date.now();
  return out;
}

async function body(kind) {
  if (!isKind(kind)) return null;
  const now = (await current())[kind];
  if (!now) return null;
  let buf = bodies.get(now.sha256);
  if (!buf) {
    const row = await db.one('SELECT body FROM branding WHERE kind = ? AND sha256 = ?', [kind, now.sha256]);
    if (!row) {
      invalidate();
      return null;
    }
    buf = row.body;
    if (bodies.size >= 8) bodies.clear();
    bodies.set(now.sha256, buf);
  }
  return { type: now.type, body: buf };
}

async function save(kind, data, user) {
  if (!isKind(kind)) throw httpError(404, 'there is no such image to set');
  const buf = decode(data);
  const info = check(kind, buf);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  await db.query(
    `INSERT INTO branding (kind, content_type, body, sha256, width, height, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE content_type = VALUES(content_type), body = VALUES(body), sha256 = VALUES(sha256),
       width = VALUES(width), height = VALUES(height), updated_by = VALUES(updated_by), updated_at = NOW()`,
    [kind, info.type, buf, sha256, info.width, info.height, user ? String(user).slice(0, 64) : null]
  );
  invalidate();
  return { kind, type: info.type, format: info.format, width: info.width, height: info.height, bytes: buf.length, sha256 };
}

async function reset(kind) {
  if (!isKind(kind)) throw httpError(404, 'there is no such image to reset');
  const done = await db.query('DELETE FROM branding WHERE kind = ?', [kind]);
  invalidate();
  return done.affectedRows;
}

module.exports = { KINDS, TYPES, MAX_BYTES, MIN_SIDE, MAX_SIDE, isKind, sniff, decode, check, current, body, save, reset, invalidate };
