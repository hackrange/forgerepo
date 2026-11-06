// @ts-check
// Every file path built from a name goes thru here, so there's one place that says it stays put.
// Author: Tim Rice
//
// callers mostly hand us hashes and random bytes already, this is the belt to their braces

const path = require('path');
const crypto = require('crypto');

const HEX = /^[0-9a-f]{40,128}$/;

/**
 * root + parts, or it throws when the result would land outside root
 * @param {string} root
 * @param {...string} parts
 * @returns {string}
 */
function inside(root, ...parts) {
  // the check below is the whole point, so semgrep can stop worrying here
  const base = path.resolve(root); // nosemgrep: path-join-resolve-traversal
  const full = path.join(root, ...parts); // nosemgrep: path-join-resolve-traversal
  const abs = path.resolve(full); // nosemgrep: path-join-resolve-traversal
  if (abs !== base && !abs.startsWith(base + path.sep)) throw new Error('that path is outside where it belongs');
  return full;
}

/**
 * <root>/ab/cd/abcd...<ext> for a hex digest. anything not hex never gets near the fs
 * @param {string} root
 * @param {string} hex
 * @param {string} [ext]
 * @returns {string}
 */
function sharded(root, hex, ext = '') {
  if (!HEX.test(String(hex || ''))) throw new Error('that is not a hex digest');
  return inside(root, hex.slice(0, 2), hex.slice(2, 4), `${hex}${ext}`);
}

/**
 * a temp name nobody else picks: <prefix>.<pid>.<random><ext>
 * @param {string} dir
 * @param {string} prefix
 * @param {string} [ext]
 * @returns {string}
 */
function tempFile(dir, prefix, ext = '.tmp') {
  return inside(dir, `${prefix}.${process.pid}.${crypto.randomBytes(8).toString('hex')}${ext}`);
}

module.exports = { inside, sharded, tempFile };
