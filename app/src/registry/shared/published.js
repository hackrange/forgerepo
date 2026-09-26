// What was published here rather than fetched: the source label its files and documents carry, and the quarantine hold
// every published file starts under.
// Author: Tim Rice
// upstream names are letters, digits, spaces, dots, dashes and underscores, so a label with a colon can never be one

const quarantine = require('../../policy/quarantine');
const malware = require('../../malware');

const SOURCE = 'published:here';
// the document kind a type keeps what was pushed here under, next to the one it mirrors
const KIND = 'published';
// the words of the hold a push starts under while a scanner is on, so the image side can tell it from a finding
const WAITING_SCAN = 'waiting for its first malware scan';

const isPublished = (row) => !!row && row.source === SOURCE;

// held before the bytes are stored, because storing them starts the scan and a quick clean answer must find the hold there.
// with a scanner, the scan's own source, so a clean result releases it by itself; without one, a person releases it.
// bytes: what was pushed. an archive built to trick an unpacker is refused here, a likely secret gets a hold of its own
async function holdBeforeStore(file, user, bytes) {
  let secrets = [];
  if (bytes) {
    const hygiene = require('../../policy/push-hygiene');
    const seen = hygiene.inspect(bytes, file.filename);
    if (seen.refuse) {
      const e = new Error(seen.refuse);
      e.status = 400;
      throw e;
    }
    const how = hygiene.mode();
    if (seen.findings.length && how !== 'off') {
      secrets = seen.findings;
      if (how === 'hold') {
        await quarantine.hold(file, { source: 'hygiene', user, reason: `it looks like it carries a secret, ${secrets.slice(0, 5).join('; ')}. Rotate what leaked, and release it only if these are not real` });
      } else {
        require('../../logger').warn(`${file.ecosystem} ${file.packageName} ${file.filename} published by ${user} looks like it carries a secret: ${secrets.slice(0, 5).join('; ')}`);
      }
    }
  }
  const scanning = malware.enabled() && malware.activeScanners().length > 0;
  const source = scanning ? 'malware' : 'publish';
  const reason = scanning
    ? `published here, ${WAITING_SCAN}`
    : 'published here while malware scanning is off, an admin has to release it';
  const placed = await quarantine.hold(file, { source, reason, user });
  return { id: placed.id, source, scanning, secrets, note: secrets.length ? `SECRETS: ${secrets.slice(0, 3).join('; ')}${secrets.length > 3 ? ` and ${secrets.length - 3} more` : ''}` : null };
}

module.exports = { SOURCE, KIND, WAITING_SCAN, isPublished, holdBeforeStore };
