// Reading a few small files out of a zip: the Package.swift of a Swift source archive, the .nuspec of a NuGet package.
// Author: Tim Rice
//
// the central directory is the zip's own table of contents. only stored and deflated entries are read, each with a
// ceiling on what it may inflate to, so a crafted archive can not blow up into gigabytes (a zip bomb)

const zlib = require('zlib');

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const MAX_ENTRIES = 200000;

// the table of contents: [{ name, method, compressed, size, offset }]
function entries(buf) {
  const from = Math.max(0, buf.length - 22 - 65535);
  let at = -1;
  for (let i = buf.length - 22; i >= from; i -= 1) {
    if (buf.readUInt32LE(i) === EOCD) {
      at = i;
      break;
    }
  }
  if (at === -1) throw new Error('not a zip archive');
  const count = buf.readUInt16LE(at + 10);
  let p = buf.readUInt32LE(at + 16);
  const out = [];
  for (let n = 0; n < Math.min(count, MAX_ENTRIES); n += 1) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CENTRAL) throw new Error('the zip table of contents is damaged');
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const offset = buf.readUInt32LE(p + 42);
    out.push({ name: buf.toString('utf8', p + 46, p + 46 + nameLen), method, compressed, size, offset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

// one entry's bytes, at most max of them
function read(buf, entry, max) {
  if (entry.size > max) throw new Error(`${entry.name} is larger than ${max} bytes`);
  const p = entry.offset;
  if (p + 30 > buf.length || buf.readUInt32LE(p) !== LOCAL) throw new Error('the zip is damaged');
  const start = p + 30 + buf.readUInt16LE(p + 26) + buf.readUInt16LE(p + 28);
  const data = buf.subarray(start, start + entry.compressed);
  if (entry.method === 0) return Buffer.from(data.subarray(0, max));
  if (entry.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: max });
  throw new Error(`${entry.name} is packed a way this reader does not know`);
}

// the archive's single top folder ("swift-log-1.6.1/"), or '' when the files sit at the top
function topFolder(list) {
  const firsts = new Set(list.map((e) => e.name.split('/')[0]));
  return firsts.size === 1 && list.every((e) => e.name.includes('/')) ? `${[...firsts][0]}/` : '';
}

module.exports = { entries, read, topFolder };
