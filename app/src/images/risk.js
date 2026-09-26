// Whether an image is too vulnerable to pull: the same Safe Version Resolution packages get, on the packages inside it.
// Author: Tim Rice
//
// on with safe resolution and its threshold. by default only advisories an upgrade already fixes count, since almost
// every base image carries something nobody has a fix for yet, and refusing those would refuse every image there is.
// a waiver for the image (its advisories, or every advisory with * for named tags or digests) lets it through

const db = require('../db');
const resolution = require('../policy/resolution');
const waivers = require('../policy/waivers');
const scans = require('../db/repositories/image-scans');
const vulnerabilities = require('../db/repositories/vulnerabilities');
const refs = require('../db/repositories/oci-refs');

function countsUnfixed() {
  return !db.settings.getBool('oci_scan_ignore_unfixed');
}

/** null = nothing against it, otherwise { reason } */
async function refusal(repository, digest, scope, tag) {
  if (!resolution.enabled()) return null;
  const row = await scans.byKey(repository, digest);
  if (!row || row.status !== 'done') return null;
  const worst = countsUnfixed() ? row.severity : row.fixable_severity;
  if (!worst || resolution.rank(worst) < 0 || resolution.rank(worst) < resolution.rank(resolution.threshold())) return null;
  const finding = await vulnerabilities.findingForVersion('oci', repository, digest);
  if (!finding) return null;
  // a waiver can name the digest, the tag it was pulled by, or any tag that points or pointed at it here. a layer
  // asked for on its own has no tag, and its image's waiver still has to count
  const refsNamed = [...new Set([digest, ...(tag ? [tag] : []), ...(await refs.tagsFor(repository, digest).catch(() => []))])];
  for (const ref of refsNamed) {
    if (await waivers.advisoryWaived('oci', repository, ref, finding, scope).catch(() => null)) return null;
  }
  const cves = String(finding.cves || '').split(', ').filter(Boolean);
  const named = cves.length ? ` (${cves.slice(0, 3).join(', ')}${cves.length > 3 ? ` and ${cves.length - 3} more` : ''})` : '';
  return {
    reason: `${worst.toLowerCase()} advisories in the packages inside it${named}${countsUnfixed() ? '' : ' that an upgrade fixes'}, `
      + `safe resolution leaves out ${resolution.threshold().toLowerCase()} and worse. The Vulnerabilities page lists what to upgrade`
  };
}

// scan before serve: an image nobody has looked inside yet is not served until it has been
async function unscanned(repository, digest) {
  if (!db.settings.getBool('oci_scan_before_serve')) return null;
  const scanner = require('./scanner');
  if (!scanner.enabled()) return null;
  const row = await scans.byKey(repository, digest);
  if (row && (row.status === 'done' || row.status === 'skipped')) return null;
  if (row && row.status === 'failed' && row.attempts >= 5) {
    return { status: 403, reason: `it could not be scanned for vulnerabilities (${row.error || 'no reason given'}), and scan before serve is on` };
  }
  scanner.queue(repository, digest, { force: !!row && row.status === 'failed' });
  return { status: 503, reason: 'it is being scanned for vulnerabilities before it is served, try again in a minute' };
}

module.exports = { refusal, unscanned, countsUnfixed };
