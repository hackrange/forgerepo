// The last checks before a file goes out, the same for every ecosystem.
// Author: Tim Rice

const db = require('../../db');
const auth = require('../../security/auth');
const artifacts = require('../../storage/artifacts');
const quarantine = require('../../policy/quarantine');
const malware = require('../../malware');
const killswitch = require('../../policy/killswitch');

// scan before serve: no answer yet means scan it now, and the verdict gets a say before the bytes go out.
// null = send it, otherwise the status and why
async function scanBeforeServe({ ecosystem, name, version, filename, artifactId }) {
  if (!artifactId || !malware.enabled() || !db.settings.getBool('malware_scan_before_serve')) return null;
  const row = await artifacts.byId(artifactId);
  const scanned = row ? await malware.ensureScanned(row.sha256, 60000) : 'ok';
  const after = await quarantine.verdict(ecosystem, name, version, filename);
  if (scanned === 'timeout' || scanned === 'error' || (after && after.refuse)) {
    const status = scanned === 'timeout' || scanned === 'error' ? 503 : 403;
    // too big for the scanner is not a wait-a-minute problem, it needs an admin, so the message says that
    const problem = scanned === 'error' && row ? await malware.scanProblem(row.sha256).catch(() => null) : null;
    const reason = scanned === 'timeout' ? 'still being scanned for malware, try again in a minute'
      : problem && problem.tooBig ? 'it is larger than the malware scanner accepts, so it is not served. An admin has to raise the scanner size limit'
        : scanned === 'error' ? 'a malware scanner could not give an answer, so it is not served yet' : after.reason;
    // a scan that hasn't answered isn't an attack, a malware hold is
    const by = status === 503 ? 'scanning' : after.source === 'malware' ? 'malware' : 'quarantine';
    return { status, reason, by };
  }
  return null;
}

// a kill on the file's own sha256, checked on the bytes about to go out whatever name they came under.
// catches a copy that only just arrived, before anything knew its hash
async function killedFile(artifactId) {
  if (!artifactId || !(await killswitch.anyHashKills())) return null;
  const row = await artifacts.byId(artifactId);
  return row ? killswitch.checkHash(row.sha256) : null;
}

// who pulled a file, for the vulnerable downloads list
function downloader(req, cacheHit) {
  return {
    ip: auth.clientIp(req),
    userId: (req.npmIdentity && req.npmIdentity.userId) || null,
    tokenName: (req.npmIdentity && req.npmIdentity.name) || null,
    application: (req.npmIdentity && req.npmIdentity.application) || null,
    environment: (req.npmIdentity && req.npmIdentity.environment) || null,
    cacheHit
  };
}

module.exports = { scanBeforeServe, killedFile, downloader };
