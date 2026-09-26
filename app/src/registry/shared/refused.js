// Downloads a mirror just had refused, remembered for a while so the next request doesn't pull the whole
// package again only to refuse it again. keyed on what the index lists, so a fixed copy is never held back.
// Author: Tim Rice

const TTL_MS = 10 * 60000;
const MAX = 1000;
const seen = new Map();

function key(upstream, filename, checksum) {
  return `${upstream}\u0000${filename}\u0000${checksum}`;
}

// the error it was refused with, or null
function recall(upstream, filename, checksum) {
  const k = key(upstream, filename, checksum);
  const hit = seen.get(k);
  if (!hit) return null;
  if (Date.now() > hit.until) {
    seen.delete(k);
    return null;
  }
  return hit.err;
}

function remember(upstream, filename, checksum, err) {
  if (seen.size >= MAX) seen.delete(seen.keys().next().value);
  seen.set(key(upstream, filename, checksum), { err, until: Date.now() + TTL_MS });
}

module.exports = { recall, remember, TTL_MS };
