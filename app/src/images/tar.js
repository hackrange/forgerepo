// Reads an image layer as it streams past, keeping only the few files that say what is installed.
// Author: Tim Rice
//
// a layer can be gigabytes and is somebody else's bytes. nothing here is written to disk under the name the tar gives,
// only kept in memory under a cap, so a path like ../../etc/passwd is just a string. gzip, zstd or plain tar

const fs = require('fs');
const zlib = require('zlib');
const { pipeline, PassThrough } = require('stream');

const BLOCK = 512;
const MAX_ENTRIES = 2000000;
const MAX_UNPACKED = 64 * 1024 * 1024 * 1024;
// pax headers and GNU long names are a few hundred bytes. anything bigger is not a name
const MAX_META = 1024 * 1024;

function layerError(message) {
  const err = new Error(message);
  err.code = 'ELAYER';
  return err;
}

const text = (buf, start, len) => {
  const raw = buf.subarray(start, start + len);
  const end = raw.indexOf(0);
  return raw.toString('utf8', 0, end < 0 ? raw.length : end);
};

// octal, or base-256 for a file past 8GB (high bit set on the first byte)
function number(buf, start, len) {
  if (buf[start] & 0x80) {
    let n = buf[start] & 0x7f;
    for (let i = start + 1; i < start + len; i += 1) n = n * 256 + buf[i];
    return n;
  }
  const s = text(buf, start, len).trim();
  if (!s) return 0;
  if (!/^[0-7]+$/.test(s)) return NaN;
  return parseInt(s, 8);
}

// the checksum is what tells a tar from random bytes
function checksumOk(header) {
  const want = number(header, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i += 1) sum += i >= 148 && i < 156 ? 32 : header[i];
  return want === sum;
}

// layer paths come as ./usr/lib, /usr/lib or usr/lib. one spelling, no empty or dot segments
function clean(name) {
  const parts = [];
  for (const part of String(name).split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') parts.pop();
    else parts.push(part);
  }
  return parts.join('/');
}

function paxRecords(buf) {
  // keys come from the layer, so no prototype for one called __proto__ to reach
  const out = Object.create(null);
  let p = 0;
  while (p < buf.length) {
    const space = buf.indexOf(0x20, p);
    if (space < 0) break;
    const len = parseInt(buf.toString('utf8', p, space), 10);
    if (!Number.isFinite(len) || len <= space - p || p + len > buf.length) break;
    const record = buf.toString('utf8', space + 1, p + len - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    p += len;
  }
  return out;
}

// the first bytes say how it was packed. the media type in a manifest is a claim, the bytes are not
function decompressorFor(head) {
  if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) return zlib.createGunzip();
  if (head.length >= 4 && head.readUInt32LE(0) === 0xfd2fb528) {
    if (typeof zlib.createZstdDecompress !== 'function') throw layerError('this layer is zstd compressed and this node cannot read zstd');
    return zlib.createZstdDecompress();
  }
  return null;
}

/**
 * walks a tar stream. options.want(path) says how many bytes of a regular file to keep (0 = skip it);
 * a file over that is reported with tooBig instead of its bytes
 * @returns {Promise<{ entries: number, bytes: number }>}
 */
function walk(source, options) {
  const { want, onFile, onLink, onWhiteout, onOpaque } = options;
  return new Promise((resolve, reject) => {
    let chunks = [];
    let have = 0;
    let state = 'header';
    let entry = null;
    let remaining = 0;
    let padding = 0;
    let kept = null;
    let entries = 0;
    let bytes = 0;
    let longName = null;
    let longLink = null;
    let pax = {};
    let done = false;

    const finish = (err) => {
      if (done) return;
      done = true;
      if (err) {
        source.destroy();
        reject(err);
      } else {
        resolve({ entries, bytes });
      }
    };

    const take = (n) => {
      const out = Buffer.allocUnsafe(n);
      let filled = 0;
      while (filled < n) {
        const first = chunks[0];
        const need = n - filled;
        if (first.length <= need) {
          first.copy(out, filled);
          filled += first.length;
          chunks.shift();
        } else {
          first.copy(out, filled, 0, need);
          chunks[0] = first.subarray(need);
          filled += need;
        }
      }
      have -= n;
      return out;
    };

    const skip = (n) => {
      let left = n;
      while (left > 0 && chunks.length) {
        const first = chunks[0];
        if (first.length <= left) {
          left -= first.length;
          chunks.shift();
        } else {
          chunks[0] = first.subarray(left);
          left = 0;
        }
      }
      have -= n - left;
      return n - left;
    };

    const startEntry = (header) => {
      const type = String.fromCharCode(header[156] || 48);
      const size = number(header, 124, 12);
      if (!Number.isFinite(size) || size < 0) throw layerError('a tar header in this layer is damaged');
      const prefix = header.toString('latin1', 257, 262) === 'ustar' ? text(header, 345, 155) : '';
      let name = longName || pax.path || ((prefix ? `${prefix}/` : '') + text(header, 0, 100));
      const linkName = longLink || pax.linkpath || text(header, 157, 100);
      const realSize = pax.size !== undefined && /^\d+$/.test(pax.size) ? Number(pax.size) : size;
      const meta = type === 'x' || type === 'g' || type === 'L' || type === 'K';
      if (!meta) {
        longName = null;
        longLink = null;
        pax = {};
      }
      name = clean(name);
      entries += 1;
      if (entries > MAX_ENTRIES) throw layerError(`this layer has more than ${MAX_ENTRIES} entries`);

      entry = { type, name, size: meta ? size : realSize };
      remaining = entry.size;
      padding = (BLOCK - (entry.size % BLOCK)) % BLOCK;
      kept = null;

      if (meta) {
        if (entry.size > MAX_META) throw layerError('a tar extended header in this layer is too large');
        kept = [];
        return;
      }
      const base = name.slice(name.lastIndexOf('/') + 1);
      const dir = name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '';
      if (base === '.wh..wh..opq') {
        if (onOpaque) onOpaque(dir);
      } else if (base.startsWith('.wh.')) {
        if (onWhiteout) onWhiteout(dir ? `${dir}/${base.slice(4)}` : base.slice(4));
      } else if (type === '1' || type === '2') {
        if (onLink) onLink(name, type === '1' ? clean(linkName) : linkName, type === '1' ? 'hard' : 'symbolic');
      } else if (type === '0' || type === '\0' || type === '7') {
        const cap = want(name);
        if (cap > 0) {
          if (entry.size > cap) onFile(name, null, { tooBig: true, size: entry.size });
          else kept = [];
        }
      }
    };

    const endEntry = () => {
      const { type } = entry;
      if (kept) {
        const data = Buffer.concat(kept);
        if (type === 'x') pax = { ...pax, ...paxRecords(data) };
        else if (type === 'L') longName = text(data, 0, data.length);
        else if (type === 'K') longLink = text(data, 0, data.length);
        else if (type !== 'g') onFile(entry.name, data, { size: data.length });
      }
      entry = null;
      kept = null;
    };

    const pump = () => {
      for (;;) {
        if (state === 'header') {
          if (have < BLOCK) return;
          const header = take(BLOCK);
          if (header.every((b) => b === 0)) {
            state = 'end';
            return;
          }
          if (!checksumOk(header)) throw layerError('this layer is not a tar archive, or it is damaged');
          startEntry(header);
          state = 'data';
        }
        if (state === 'data') {
          if (remaining > 0) {
            if (!have) return;
            if (kept) {
              const n = Math.min(remaining, have);
              kept.push(take(n));
              remaining -= n;
            } else {
              remaining -= skip(Math.min(remaining, have));
            }
            if (remaining > 0) return;
          }
          state = 'padding';
        }
        if (state === 'padding') {
          if (padding > 0) {
            padding -= skip(Math.min(padding, have));
            if (padding > 0) return;
          }
          endEntry();
          state = 'header';
        }
        if (state === 'end') return;
      }
    };

    source.on('data', (chunk) => {
      if (done) return;
      bytes += chunk.length;
      if (bytes > MAX_UNPACKED) {
        finish(layerError(`this layer unpacks to more than ${MAX_UNPACKED / 1073741824}GB`));
        return;
      }
      if (state === 'end') return;
      chunks.push(chunk);
      have += chunk.length;
      try {
        pump();
      } catch (err) {
        finish(err);
      }
    });
    source.on('error', (err) => finish(err.code === 'ELAYER' ? err : layerError(`this layer could not be read: ${err.message}`)));
    source.on('end', () => {
      if (state === 'end' || (state === 'header' && have === 0)) {
        chunks = [];
        finish();
      } else {
        finish(layerError('this layer ends in the middle of a file'));
      }
    });
  });
}

// a stored layer file, decompressed by what its bytes say it is
async function walkFile(filePath, options) {
  const head = Buffer.alloc(4);
  const fh = await fs.promises.open(filePath, 'r');
  let got;
  try {
    ({ bytesRead: got } = await fh.read(head, 0, 4, 0));
  } finally {
    await fh.close();
  }
  const inflate = decompressorFor(head.subarray(0, got));
  const raw = fs.createReadStream(filePath);
  if (!inflate) return walk(raw, options);
  const out = walk(inflate, options);
  pipeline(raw, inflate, () => {});
  return out;
}

// the same, from a stream (a stored blob, checked against its digest as it is read). the first chunk decides the format
async function walkStream(source, options) {
  const head = await new Promise((resolve, reject) => {
    const cleanup = () => {
      source.off('data', onData);
      source.off('end', onEnd);
      source.off('error', onError);
    };
    function onData(chunk) {
      cleanup();
      source.pause();
      resolve(chunk);
    }
    function onEnd() {
      cleanup();
      resolve(Buffer.alloc(0));
    }
    function onError(err) {
      cleanup();
      reject(layerError(`this layer could not be read: ${err.message}`));
    }
    source.on('data', onData);
    source.once('end', onEnd);
    source.once('error', onError);
  });
  const joined = new PassThrough();
  joined.write(head);
  source.on('error', (err) => joined.destroy(err));
  source.pipe(joined);
  const inflate = decompressorFor(head);
  let reading = joined;
  if (inflate) {
    joined.on('error', (err) => inflate.destroy(err));
    joined.pipe(inflate);
    reading = inflate;
  }
  try {
    return await walk(reading, options);
  } finally {
    // whatever happened, nothing is left reading the blob
    source.destroy();
  }
}

module.exports = { walk, walkFile, walkStream, clean, decompressorFor, MAX_ENTRIES, _internal: { number, checksumOk, paxRecords } };
