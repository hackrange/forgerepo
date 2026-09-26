// Pod names. The CDN files a pod under the md5 of its exact name, so the case is kept.
// Author: Tim Rice
// letters, digits, plus, dots, dashes and underscores. a subspec like GoogleUtilities/Environment is not a pod name

const crypto = require('crypto');

const MAX = 128;
const NAME_RE = /^[A-Za-z0-9_+][A-Za-z0-9_.+-]*$/;

const valid = (n) => {
  const s = String(n || '');
  return !!s && s.length <= MAX && NAME_RE.test(s) && !s.includes('..');
};

// the three one-character folders the CDN keeps a pod's files under: md5 of the name, first three hex digits
function shard(name) {
  return crypto.createHash('md5').update(String(name)).digest('hex').slice(0, 3).split('');
}

module.exports = { MAX, valid, shard };
