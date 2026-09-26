// What the box already holds about a batch of packages, for judging a dependency tree in one pass.
// Author: Tim Rice

const db = require('../../db');

const inPairs = (pairs) => pairs.map(() => '(?, ?)').join(',');

// open and rejected holds per version, for [ecosystem, name] pairs. keep batches to a few hundred
function holdsFor(pairs) {
  if (!pairs.length) return Promise.resolve([]);
  return db.query(
    `SELECT ecosystem, package_name, version, status FROM quarantine_holds
      WHERE status IN ('open', 'rejected') AND (ecosystem, package_name) IN (${inPairs(pairs)})`,
    pairs.flat()
  );
}

// the versions this box has a file for, and what the license lists made of each file
function artifactsFor(pairs) {
  if (!pairs.length) return Promise.resolve([]);
  return db.query(
    `SELECT ecosystem, package_name, version, license_verdict FROM artifacts
      WHERE filename NOT LIKE '%.metadata' AND (ecosystem, package_name) IN (${inPairs(pairs)})`,
    pairs.flat()
  );
}

module.exports = { holdsFor, artifactsFor };
