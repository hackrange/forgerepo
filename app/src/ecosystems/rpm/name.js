// RPM package names, like openssl-libs or python3.11-pip. names are compared exactly, the way rpm and dnf do.
// Author: Tim Rice

const MAX = 200;
const NAME_RE = /^[A-Za-z0-9_+][A-Za-z0-9._+-]*$/;

const valid = (text) => {
  const n = String(text || '').trim();
  return !!n && n.length <= MAX && NAME_RE.test(n);
};

module.exports = { MAX, valid };
