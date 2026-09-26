// The blob store on local disk. Same bytes, same file, forever.
// Author: Tim Rice
//
// <cache>/blobs/sha256/ab/cd/abcd1234... content addressed, written once, never edited.
// temp file gets hashed first then renamed in, so no half written blob under a real digest

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');

const HEX64 = /^[0-9a-f]{64}$/;

// errors that mean "hard links aren't happening here", so copy instead
const NO_LINKS = ['EXDEV', 'EPERM', 'ENOTSUP', 'EMLINK'];

let root = path.join(config.cacheDir, 'blobs', 'sha256');

// tests point this somewhere disposable
function useRoot(dir) {
  root = dir;
}

// only way a path gets made. not 64 lowercase hex = never touches the fs, no traversal
function blobPath(sha256) {
  if (!HEX64.test(String(sha256 || ''))) throw new Error('that is not a sha256 digest');
  return path.join(root, sha256.slice(0, 2), sha256.slice(2, 4), sha256);
}

function tmpDir() {
  return path.join(root, 'tmp');
}

async function init() {
  await fsp.mkdir(tmpDir(), { recursive: true });
}

function digest(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function has(sha256, size) {
  try {
    const stat = await fsp.stat(blobPath(sha256));
    return stat.isFile() && (size === undefined || size === null || stat.size === size);
  } catch (err) {
    return false;
  }
}

async function stat(sha256) {
  try {
    const s = await fsp.stat(blobPath(sha256));
    return s.isFile() ? { size: s.size, links: s.nlink } : null;
  } catch (err) {
    return null;
  }
}

function freshTmp() {
  return path.join(tmpDir(), `${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
}

function mismatch(expected, got) {
  const e = new Error(`the content hashed to ${got}, not the ${expected} it was supposed to be`);
  e.code = 'EDIGEST';
  e.expected = expected;
  e.actual = got;
  return e;
}

// if someone beat us to it the bytes are identical by definition, bin ours
async function place(tmp, sha256) {
  const dest = blobPath(sha256);
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  if (await has(sha256)) {
    await fsp.unlink(tmp).catch(() => {});
    return { path: dest, existed: true };
  }
  await fsp.chmod(tmp, 0o640).catch(() => {});
  try {
    await fsp.rename(tmp, dest);
  } catch (err) {
    if (err.code !== 'EXDEV') throw err;
    // the temp file is on a separate mount. copy it across, check the copy, then swap it in
    await init();
    const near = freshTmp();
    try {
      await fsp.copyFile(tmp, near);
      const again = await hashFile(near);
      if (again.sha256 !== sha256) throw mismatch(sha256, again.sha256);
      await fsp.rename(near, dest);
    } finally {
      await fsp.unlink(near).catch(() => {});
      await fsp.unlink(tmp).catch(() => {});
    }
  }
  return { path: dest, existed: false };
}

async function putBuffer(buffer, expected) {
  const sha256 = digest(buffer);
  if (expected && expected !== sha256) throw mismatch(expected, sha256);
  if (await has(sha256, buffer.length)) return { sha256, size: buffer.length, path: blobPath(sha256), existed: true };
  await init();
  const tmp = freshTmp();
  await fsp.writeFile(tmp, buffer, { mode: 0o640 });
  const placed = await place(tmp, sha256);
  return { sha256, size: buffer.length, ...placed };
}

async function hashFile(file) {
  const hash = crypto.createHash('sha256');
  let size = 0;
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on('data', (chunk) => {
      size += chunk.length;
      hash.update(chunk);
    });
    stream.on('error', reject);
    stream.on('end', resolve);
  });
  return { sha256: hash.digest('hex'), size };
}

// adopts a file on disk by hard link (no extra disk, old path keeps working), copy if cross-fs.
// known = a hashFile() result already paid for
async function putFile(file, expected, known) {
  const { sha256, size } = known || await hashFile(file);
  if (expected && expected !== sha256) throw mismatch(expected, sha256);
  const dest = blobPath(sha256);
  if (await has(sha256)) return { sha256, size, path: dest, existed: true };
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  try {
    await fsp.link(file, dest);
  } catch (err) {
    if (err.code === 'EEXIST') return { sha256, size, path: dest, existed: true };
    if (!NO_LINKS.includes(err.code)) throw err;
    await init();
    const tmp = freshTmp();
    await fsp.copyFile(file, tmp);
    const again = await hashFile(tmp);
    // paranoid, but the file could have changed between the two reads
    if (again.sha256 !== sha256) {
      await fsp.unlink(tmp).catch(() => {});
      throw mismatch(sha256, again.sha256);
    }
    return { sha256, size, ...(await place(tmp, sha256)) };
  }
  return { sha256, size, path: dest, existed: false };
}

// caller already hashed it while downloading, so the digest is trusted
async function adoptTmp(tmp, sha256) {
  const placed = await place(tmp, sha256);
  const s = await stat(sha256);
  return { sha256, size: s ? s.size : null, ...placed };
}

// hard link back to the legacy path so the old release still finds files after a rollback.
// replace: link next to it and rename over, never half a file
async function linkOut(sha256, target, options = {}) {
  const source = blobPath(sha256);
  await fsp.mkdir(path.dirname(target), { recursive: true });
  if (!options.replace) {
    try {
      await fsp.link(source, target);
      return;
    } catch (err) {
      if (err.code === 'EEXIST') return;
      if (!NO_LINKS.includes(err.code)) throw err;
    }
  }
  const tmp = `${target}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    try {
      await fsp.link(source, tmp);
    } catch (err) {
      if (!NO_LINKS.includes(err.code)) throw err;
      await fsp.copyFile(source, tmp);
    }
    await fsp.rename(tmp, target);
  } finally {
    // renaming a link over another link to the very same file is a no-op that
    // leaves tmp sitting there. thanks POSIX
    await fsp.unlink(tmp).catch(() => {});
  }
}

function open(sha256) {
  return fs.createReadStream(blobPath(sha256));
}

// reads the blob back and checks it still hashes to its own name
async function verify(sha256) {
  try {
    return (await hashFile(blobPath(sha256))).sha256 === sha256;
  } catch (err) {
    return false;
  }
}

async function remove(sha256) {
  await fsp.unlink(blobPath(sha256)).catch(() => {});
}

// every blob, gone. Only for emptying the whole cache
async function purgeAll() {
  await fsp.rm(root, { recursive: true, force: true });
  await init();
}

// old temp files only, a live download has a young one
async function sweepTmp(olderThanMs = 6 * 3600000) {
  let removed = 0;
  let entries = [];
  try {
    entries = await fsp.readdir(tmpDir());
  } catch (err) {
    return 0;
  }
  for (const name of entries) {
    const file = path.join(tmpDir(), name);
    try {
      const s = await fsp.stat(file);
      if (Date.now() - s.mtimeMs > olderThanMs) {
        await fsp.unlink(file);
        removed += 1;
      }
    } catch (err) {
      // gone already, which is fine
    }
  }
  return removed;
}

module.exports = {
  init,
  useRoot,
  blobPath,
  digest,
  has,
  stat,
  putBuffer,
  putFile,
  adoptTmp,
  linkOut,
  open,
  verify,
  remove,
  purgeAll,
  sweepTmp,
  hashFile,
  // the bucket driver downloads into the same temp folder, so a half written file never has a real name
  tmpFile: freshTmp
};
