// Comparing Debian, Alpine and rpm package versions, for picking the newest fix when advisories name several.
// Author: Tim Rice
//
// dpkg's own rule: epoch first, then runs of digits compared as numbers and everything else by character, with ~
// sorting before anything, even the end. rpm and apk agree with it on the versions advisories actually use

function epochOf(v) {
  const m = /^(\d{1,9}):(.*)$/.exec(v);
  return m ? [Number(m[1]), m[2]] : [0, v];
}

function order(c) {
  if (c === undefined) return 0;
  if (c === '~') return -1;
  if (/[A-Za-z]/.test(c)) return c.charCodeAt(0);
  return c.charCodeAt(0) + 256;
}

function compareParts(a, b) {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    // the non digit prefix, character by character
    while ((i < a.length && !/\d/.test(a[i])) || (j < b.length && !/\d/.test(b[j]))) {
      const ca = i < a.length && !/\d/.test(a[i]) ? a[i] : undefined;
      const cb = j < b.length && !/\d/.test(b[j]) ? b[j] : undefined;
      const diff = order(ca) - order(cb);
      if (diff) return diff < 0 ? -1 : 1;
      if (ca !== undefined) i += 1;
      if (cb !== undefined) j += 1;
    }
    let na = '';
    let nb = '';
    while (i < a.length && /\d/.test(a[i])) na += a[i++];
    while (j < b.length && /\d/.test(b[j])) nb += b[j++];
    na = na.replace(/^0+/, '');
    nb = nb.replace(/^0+/, '');
    if (na.length !== nb.length) return na.length < nb.length ? -1 : 1;
    if (na !== nb) return na < nb ? -1 : 1;
  }
  return 0;
}

/** -1, 0 or 1. junk compares as text so it never throws */
function compare(a, b) {
  const [ea, ra] = epochOf(String(a || ''));
  const [eb, rb] = epochOf(String(b || ''));
  if (ea !== eb) return ea < eb ? -1 : 1;
  return compareParts(ra.slice(0, 256), rb.slice(0, 256));
}

module.exports = { compare };
