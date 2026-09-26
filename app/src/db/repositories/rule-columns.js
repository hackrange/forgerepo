// SQL for how cached and how vulnerable a rule is, used by the rules repository.
// Author: Tim Rice

const { sevRank } = require('./severity');
const kinds = require('../../registry/kinds');

// ---------------------------------------------------------------- cached-ness of a rule
// exact-version lists can be checked in sql. real semver ranges just get "anything cached for this package?"

//no comparison chars = all exact versions
const PIN_LIST = "rules.version_range <> '' AND rules.version_range NOT REGEXP '[<>=^~xX*]'";

// ' || ' is 4 chars, so separators + 1 = pins. fence-post math, the classic
const PIN_COUNT =
  "((LENGTH(rules.version_range) - LENGTH(REPLACE(rules.version_range, ' || ', ''))) / 4 + 1)";

// wrap in separators so LIKE doesn't decide 1.2.3 covers 1.2.30
const CACHED_PINS = `(SELECT COUNT(*) FROM tarballs t
     WHERE t.package_name = rules.pattern
       AND CONCAT(' || ', rules.version_range, ' || ') LIKE CONCAT('% || ', t.version, ' || %'))`;
const NPM_CACHED_ANY = 'EXISTS (SELECT 1 FROM tarballs t WHERE t.package_name = rules.pattern)';

// PyPI: cached = any real file of the release, not just its .metadata
const PYPI_FILES = "a.ecosystem = 'pypi' AND a.package_name = rules.pattern AND a.filename NOT LIKE '%.metadata'";
const PYPI_PINS = "REPLACE(REPLACE(rules.version_range, '==', ''), ' ', '')";
const PYPI_PIN_LIST = `rules.version_range <> '' AND ${PYPI_PINS} NOT REGEXP '[<>=!~*,]'`;
const PYPI_PIN_COUNT = `((LENGTH(${PYPI_PINS}) - LENGTH(REPLACE(${PYPI_PINS}, '||', ''))) / 2 + 1)`;
const PYPI_CACHED_PINS = `(SELECT COUNT(DISTINCT a.version) FROM artifacts a
     WHERE ${PYPI_FILES} AND LOCATE(CONCAT('||', a.version, '||'), CONCAT('||', ${PYPI_PINS}, '||')) > 0)`;
const PYPI_CACHED_ANY = `EXISTS (SELECT 1 FROM artifacts a WHERE ${PYPI_FILES})`;

// images: a pinned tag is cached when this box knows where it points and keeps that manifest, a digest when it keeps it
const OCI_PIN_LIST = "rules.version_range <> '' AND rules.version_range NOT LIKE '%*%'";
const OCI_WITHIN = (col) => `LOCATE(CONCAT(' || ', ${col}, ' || '), CONCAT(' || ', rules.version_range, ' || ')) > 0`;
const OCI_CACHED_PINS = `((SELECT COUNT(*) FROM oci_tags ot JOIN oci_manifests om ON om.repository = ot.repository AND om.digest = ot.digest
       WHERE ot.repository = rules.pattern AND ${OCI_WITHIN('ot.tag')})
     + (SELECT COUNT(*) FROM oci_manifests om WHERE om.repository = rules.pattern AND ${OCI_WITHIN('om.digest')}))`;
const OCI_CACHED_ANY = 'EXISTS (SELECT 1 FROM oci_manifests om WHERE om.repository = rules.pattern)';

// the newer types (NuGet, Maven): the files kept for the package (the collation ignores case, as NuGet does).
// a pin is 13.0.3 or [13.0.3]. the type ids are the box's own constants, never anything typed
const KINDS = kinds.ids().map((id) => `'${id}'`).join(', ');
const IS_KIND = `rules.ecosystem IN (${KINDS})`;
const KIND_FILES = 'a.ecosystem = rules.ecosystem AND a.package_name = rules.pattern';
const KIND_PINS = "REPLACE(REPLACE(REPLACE(rules.version_range, '[', ''), ']', ''), ' ', '')";
const KIND_PIN_LIST = `rules.version_range <> '' AND rules.version_range NOT REGEXP '[<>=*,()]'`;
const KIND_PIN_COUNT = `((LENGTH(${KIND_PINS}) - LENGTH(REPLACE(${KIND_PINS}, '||', ''))) / 2 + 1)`;
const KIND_CACHED_PINS = `(SELECT COUNT(DISTINCT a.version) FROM artifacts a
     WHERE ${KIND_FILES} AND LOCATE(CONCAT('||', a.version, '||'), CONCAT('||', ${KIND_PINS}, '||')) > 0)`;
const KIND_CACHED_ANY = `EXISTS (SELECT 1 FROM artifacts a WHERE ${KIND_FILES})`;
// every type whose cached-ness sql can work out. images are worked out from their layers, in the service
const CACHE_TYPES = `'npm', 'pypi', ${KINDS}`;

const CACHED_VERSIONS = `CASE
       WHEN rules.ecosystem = 'npm' THEN (SELECT COUNT(*) FROM tarballs t WHERE t.package_name = rules.pattern)
       WHEN rules.ecosystem = 'pypi' THEN (SELECT COUNT(DISTINCT a.version) FROM artifacts a WHERE ${PYPI_FILES})
       WHEN rules.ecosystem = 'oci' THEN (SELECT COUNT(*) FROM oci_tags ot WHERE ot.repository = rules.pattern)
       WHEN ${IS_KIND} THEN (SELECT COUNT(DISTINCT a.version) FROM artifacts a WHERE ${KIND_FILES})
       ELSE NULL END`;
const CACHED_PIN_COUNT = `CASE WHEN rules.ecosystem = 'npm' AND ${PIN_LIST} THEN ${CACHED_PINS}
       WHEN rules.ecosystem = 'pypi' AND ${PYPI_PIN_LIST} THEN ${PYPI_CACHED_PINS}
       WHEN rules.ecosystem = 'oci' AND ${OCI_PIN_LIST} THEN ${OCI_CACHED_PINS}
       WHEN ${IS_KIND} AND ${KIND_PIN_LIST} THEN ${KIND_CACHED_PINS} ELSE NULL END`;
const PINNED_COUNT = `CAST(CASE WHEN rules.ecosystem = 'npm' AND ${PIN_LIST} THEN ${PIN_COUNT}
       WHEN rules.ecosystem = 'pypi' AND ${PYPI_PIN_LIST} THEN ${PYPI_PIN_COUNT}
       WHEN rules.ecosystem = 'oci' AND ${OCI_PIN_LIST} THEN ${PIN_COUNT}
       WHEN ${IS_KIND} AND ${KIND_PIN_LIST} THEN ${KIND_PIN_COUNT} ELSE NULL END AS UNSIGNED)`;
const FULLY_CACHED = `CASE
       WHEN rules.ecosystem = 'npm' AND ${PIN_LIST} THEN ${CACHED_PINS} >= ${PIN_COUNT}
       WHEN rules.ecosystem = 'npm' THEN ${NPM_CACHED_ANY}
       WHEN rules.ecosystem = 'pypi' AND ${PYPI_PIN_LIST} THEN ${PYPI_CACHED_PINS} >= ${PYPI_PIN_COUNT}
       WHEN rules.ecosystem = 'pypi' THEN ${PYPI_CACHED_ANY}
       WHEN rules.ecosystem = 'oci' AND ${OCI_PIN_LIST} THEN ${OCI_CACHED_PINS} >= ${PIN_COUNT}
       WHEN rules.ecosystem = 'oci' THEN ${OCI_CACHED_ANY}
       WHEN ${IS_KIND} AND ${KIND_PIN_LIST} THEN ${KIND_CACHED_PINS} >= ${KIND_PIN_COUNT}
       WHEN ${IS_KIND} THEN ${KIND_CACHED_ANY}
       ELSE 0 END`;

// same split as the cache columns. pins judged on their own versions, ranges fall back to "any finding for this name".
// wildcards are n/a, and findings only count for their own ecosystem
const VULN_MATCH = `f.ecosystem = rules.ecosystem AND f.package_name = rules.pattern
       AND (NOT (${PIN_LIST})
            OR CONCAT(' || ', rules.version_range, ' || ') LIKE CONCAT('% || ', f.version, ' || %'))`;

const VULN_COUNT = `(SELECT COUNT(*) FROM cve_findings f WHERE ${VULN_MATCH})`;

const VULN_WORST = `(SELECT f.severity FROM cve_findings f WHERE ${VULN_MATCH}
     ORDER BY ${sevRank('f.severity')} DESC LIMIT 1)`;


module.exports = { CACHE_TYPES, PIN_LIST, PIN_COUNT, CACHED_PINS, NPM_CACHED_ANY, PYPI_FILES, PYPI_PINS, PYPI_PIN_LIST, PYPI_PIN_COUNT, PYPI_CACHED_PINS, PYPI_CACHED_ANY, CACHED_VERSIONS, CACHED_PIN_COUNT, PINNED_COUNT, FULLY_CACHED, VULN_MATCH, VULN_COUNT, VULN_WORST };
