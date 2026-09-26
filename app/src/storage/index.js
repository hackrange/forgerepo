// The blob store, whichever kind is in use: local disk, or local disk in front of a bucket.
// Author: Tim Rice
//
// nothing outside storage/ gets a blob's path. bytes come out through open(), and the
// few things that really need a file (scanners) borrow one with withLocalCopy()

const db = require('../db');
const local = require('./local');

// pulled in when a bucket is first used, it brings the http client and the blobs table with it
let bucket = null;
function bucketDriver() {
  if (!bucket) bucket = require('./bucket');
  return bucket;
}

function inBucketMode() {
  return ['s3', 'azure'].includes(db.settings.get('storage_backend'));
}

const localDriver = {
  has: local.has,
  stat: local.stat,
  open: local.open,
  verify: local.verify,
  remove: local.remove,
  purgeAll: local.purgeAll,
  // fn(file) gets a file holding the blob while it runs. on local disk that is the blob itself, so read only
  withLocalCopy: async (sha256, fn) => fn(local.blobPath(sha256)),
  // hard link into the old cache folders so an older release still finds its files after a rollback
  keepLegacyCopy: (sha256, target, options) => local.linkOut(sha256, target, options)
};

const driver = () => (inBucketMode() ? bucketDriver() : localDriver);

module.exports = {
  get kind() {
    return inBucketMode() ? 'bucket' : 'local';
  },
  init: local.init,
  useRoot: local.useRoot,
  digest: local.digest,
  hashFile: local.hashFile,
  sweepTmp: local.sweepTmp,
  // new files always land on disk first. with a bucket the uploader takes them from there
  putBuffer: local.putBuffer,
  putFile: local.putFile,
  adoptTmp: local.adoptTmp,
  has: (sha256, size) => driver().has(sha256, size),
  stat: (sha256) => driver().stat(sha256),
  open: (sha256) => driver().open(sha256),
  verify: (sha256) => driver().verify(sha256),
  remove: (sha256) => driver().remove(sha256),
  purgeAll: () => driver().purgeAll(),
  withLocalCopy: (sha256, fn) => driver().withLocalCopy(sha256, fn),
  keepLegacyCopy: (sha256, target, options) => driver().keepLegacyCopy(sha256, target, options)
};
