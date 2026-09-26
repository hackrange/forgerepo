// Debian package names, like libssl3 or python3-requests: lower case letters, digits, + - and dots, two or more.
// Author: Tim Rice

const MAX = 200;
const NAME_RE = /^[a-z0-9][a-z0-9+.-]+$/;

const valid = (text) => {
  const n = String(text || '').trim();
  return n.length <= MAX && NAME_RE.test(n);
};

module.exports = { MAX, valid };
