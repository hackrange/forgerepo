// What the portal shows of image scans, and asking for one again.
// Author: Tim Rice
//
// images are shared the way packages are: anyone who can read the vulnerabilities list can read what is inside them.
// a scan can only be asked for again on an image that was already pulled through here, never on a name somebody types

const db = require('../db');
const ociName = require('../ecosystems/oci/name');
const scanner = require('../images/scanner');
const repo = require('../db/repositories/image-scans');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const MAX_LISTED = 5000;

function key(repository, digest) {
  const name = ociName.fold(repository);
  if (!ociName.valid(name)) fail(400, 'that is not a valid image repository name');
  if (!ociName.isDigest(digest)) fail(400, 'that is not an image digest');
  return { repository: name, digest: String(digest).trim() };
}

async function list(filters, paging) {
  const page = await repo.page(filters, paging);
  return {
    ...page,
    enabled: scanner.enabled(),
    waiting: scanner.pending(),
    settings: {
      oci_scan: db.settings.getBool('oci_scan'),
      oci_scan_max_gb: db.settings.getInt('oci_scan_max_gb', 16),
      oci_scan_before_serve: db.settings.getBool('oci_scan_before_serve'),
      oci_scan_ignore_unfixed: db.settings.getBool('oci_scan_ignore_unfixed'),
      safe_resolution: db.settings.getBool('safe_resolution'),
      safe_resolution_severity: db.settings.get('safe_resolution_severity') || 'HIGH'
    }
  };
}

async function detail(repository, digest, { all }) {
  const k = key(repository, digest);
  const image = repo.withNotes(await repo.byKey(k.repository, k.digest));
  if (!image) fail(404, 'that image has not been scanned here');
  const vulnerable = await repo.components(image.id, { vulnerableOnly: true, limit: MAX_LISTED });
  const everything = all ? await repo.components(image.id, { limit: MAX_LISTED }) : null;
  return { image, vulnerable, components: everything, listedUpTo: MAX_LISTED };
}

async function rescan(actor, repository, digest) {
  const k = key(repository, digest);
  const image = await repo.byKey(k.repository, k.digest);
  if (!image) fail(404, 'that image has not been pulled through here, so there is nothing to scan again');
  if (!scanner.enabled()) fail(409, 'image scanning is switched off');
  const queued = scanner.queue(k.repository, k.digest, { force: true });
  if (!queued) fail(503, 'the scan queue is full, try again in a few minutes');
  await audit(actor, 'image.scan', `${k.repository}@${k.digest}`, null);
  return { queued: true };
}

module.exports = { list, detail, rescan };
