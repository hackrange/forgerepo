// Provenance results, one row per file. the verifying lives in policy/provenance.js
// Author: Tim Rice

const db = require('../../db');

// values arrive already clipped to fit. a rerun overwrites the row, checked_at always moves
function save(v) {
  return db.query(
    `INSERT INTO provenance (ecosystem, package_name, version, filename, sha256, status, reason, registry_signature, source_repository, source_commit,
                             source_ref, builder, workflow, issuer, subject_digest, predicate_type, attestation, verified_at, checked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE sha256 = VALUES(sha256), status = VALUES(status), reason = VALUES(reason), registry_signature = VALUES(registry_signature),
       source_repository = VALUES(source_repository), source_commit = VALUES(source_commit), source_ref = VALUES(source_ref), builder = VALUES(builder),
       workflow = VALUES(workflow), issuer = VALUES(issuer), subject_digest = VALUES(subject_digest), predicate_type = VALUES(predicate_type),
       attestation = VALUES(attestation), verified_at = VALUES(verified_at), checked_at = NOW()`,
    [
      v.ecosystem, v.packageName, v.version, v.filename, v.sha256, v.status, v.reason, v.registrySignature,
      v.sourceRepository, v.sourceCommit, v.sourceRef, v.builder, v.workflow,
      v.issuer, v.subjectDigest, v.predicateType, v.attestation, v.verifiedAt
    ]
  );
}

// the versions of a package that came with verified provenance, and where each was built
function verifiedVersions(ecosystem, packageName) {
  return db.query(
    `SELECT version, MAX(source_repository) AS source_repository, MAX(workflow) AS workflow FROM provenance
      WHERE ecosystem = ? AND package_name = ? AND status = 'VERIFIED' AND version <> ''
      GROUP BY version ORDER BY MAX(verified_at) DESC LIMIT 500`,
    [ecosystem, packageName]
  );
}

module.exports = { save, verifiedVersions };
