// Ranking severity words in SQL, shared by the queries that sort findings.
// Author: Tim Rice

// severity is words, alphabet puts MODERATE above CRITICAL. rank it
const sevRank = (col) => `CASE ${col} WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                                      WHEN 'MODERATE' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END`;

// ---------------------------------------------------------------- vulnerability of a rule

module.exports = { sevRank };
