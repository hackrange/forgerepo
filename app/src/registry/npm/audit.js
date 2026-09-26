// npm audit, answered from our own cve_findings. the tree goes nowhere.
// Author: Tim Rice
// empty used to mean "found 0 vulnerabilities", a clean bill of health nobody checked

const express = require('express');
const zlib = require('zlib');
const db = require('../../db');
const audit = require('../../audit');
const log = require('../../logger');
const { record } = require('../shared/access');

const router = express.Router();

// gzipped, express.json won't unwrap it. capped
const MAX_AUDIT_BYTES = 8 * 1024 * 1024;
// and unpacked. zip bombs
const MAX_AUDIT_JSON_BYTES = 32 * 1024 * 1024;

function readAuditBody(req, res, next) {
  const chunks = [];
  let size = 0;
  let stopped = false;

  const finish = (buf) => {
    try {
      req.auditBody = buf && buf.length ? JSON.parse(buf.toString('utf8')) : {};
    } catch (err) {
      req.auditBody = {};
    }
    next();
  };

  req.on('data', (chunk) => {
    if (stopped) return;
    size += chunk.length;
    if (size > MAX_AUDIT_BYTES) {
      stopped = true;
      res.status(413).json({ error: 'that is a very large audit payload, this registry will not read it' });
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    if (stopped) return;
    const raw = Buffer.concat(chunks);
    if (/gzip/i.test(req.get('content-encoding') || '')) {
      return zlib.gunzip(raw, { maxOutputLength: MAX_AUDIT_JSON_BYTES }, (err, out) => {
        if (err && err.code === 'ERR_BUFFER_TOO_LARGE') {
          stopped = true;
          res.status(413).json({ error: 'that audit payload unpacks to more than this registry will read' });
          return;
        }
        finish(err ? null : out);
      });
    }
    return finish(raw);
  });

  req.on('error', () => {
    if (stopped) return;
    stopped = true;
    finish(null);
  });
}

const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

// breaks = empty report. an install that can't be audited is still definitely an install
function auditHandler(build, empty) {
  return async (req, res) => {
    if (!db.settings.getBool('audit_answer')) return res.json(empty);
    try {
      const wanted = audit.collect(req.auditBody);
      const entries = await audit.entriesFor(wanted);
      const worst = entries.reduce((acc, e) => (SEVERITY_RANK[e.severity] > SEVERITY_RANK[acc] ? e.severity : acc), 'info');
      record(req, {
        action: 'allow',
        reason: entries.length
          ? `audit: ${audit.versionCount(wanted)} version(s), ${entries.length} advisory hit(s), worst ${worst}`
          : `audit: ${audit.versionCount(wanted)} version(s), nothing known against them`
      });
      return res.json(build(entries, wanted));
    } catch (err) {
      log.error('could not answer an audit request', err.message);
      record(req, { action: 'error', status: 200, reason: `audit failed: ${err.message}` });
      return res.json(empty);
    }
  };
}

// npm 7+
router.post('/-/npm/v1/security/advisories/bulk', readAuditBody, auditHandler(
  (entries) => audit.bulkBody(entries),
  {}
));

// npm 6, same question but it sends a lock file
const quickEmpty = {
  actions: [],
  advisories: {},
  muted: [],
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
              dependencies: 0, devDependencies: 0, optionalDependencies: 0, totalDependencies: 0 }
};
router.post('/-/npm/v1/security/audits/quick', readAuditBody, auditHandler(
  (entries, wanted) => audit.quickBody(entries, wanted), quickEmpty));
router.post('/-/npm/v1/security/audits', readAuditBody, auditHandler(
  (entries, wanted) => audit.quickBody(entries, wanted), quickEmpty));

module.exports = router;
module.exports.readAuditBody = readAuditBody;
