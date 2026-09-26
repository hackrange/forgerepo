-- ForgeRepo schema
-- Author: Tim Rice
-- runs on every boot, all IF NOT EXISTS so 900 runs is fine.
--anything pointable by id has an owner column. trusting client ids is how you end up on the news

CREATE TABLE IF NOT EXISTS settings (
    k VARCHAR(64) NOT NULL PRIMARY KEY,
    v TEXT,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- roles, weakest to mightiest: viewer, developer, approver, admin (with great power etc)
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    email VARCHAR(190) NULL,
    full_name VARCHAR(128) NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('viewer','developer','publisher','approver','admin') NOT NULL DEFAULT 'developer',
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    disabled TINYINT(1) NOT NULL DEFAULT 0,
    failed_logins INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    password_changed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME NULL,
    UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--server side sessions. the cookie only ever holds a random id, nothing juicy
CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(64) NOT NULL PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    csrf CHAR(64) NOT NULL,
    ip VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    -- set when an admin is acting as this user, and the moment that stops
    impersonator_id INT UNSIGNED NULL,
    impersonation_ends_at DATETIME NULL,
    KEY idx_sessions_expiry (expires_at),
    KEY idx_sessions_user (user_id),
    KEY idx_sessions_impersonator (impersonator_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_sessions_impersonator FOREIGN KEY (impersonator_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- What a token is for and where it runs. fixed lists, so "Checkout API" and "checkoutapi" aren't two apps in a report
-- retire, don't delete, or old tokens lose their label
CREATE TABLE IF NOT EXISTS applications (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    note VARCHAR(512) NULL,
    retired TINYINT(1) NOT NULL DEFAULT 0,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_applications_name (name),
    KEY idx_applications_retired (retired, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS environments (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    note VARCHAR(512) NULL,
    -- ticked by an admin. dry runs count applications in production off it
    production TINYINT(1) NOT NULL DEFAULT 0,
    retired TINYINT(1) NOT NULL DEFAULT 0,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_environments_name (name),
    KEY idx_environments_retired (retired, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- registry tokens for .npmrc. every token has a user attached, no orphans
CREATE TABLE IF NOT EXISTS tokens (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    name VARCHAR(128) NOT NULL,
    -- both optional. no FK on purpose, a deleted row just reads as unassigned
    application_id INT UNSIGNED NULL,
    environment_id INT UNSIGNED NULL,
    -- blocked-install digest goes here if set, otherwise to the account behind teh token
    email VARCHAR(190) NULL,
    prefix VARCHAR(16) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    last_used_at DATETIME NULL,
    last_used_ip VARCHAR(45) NULL,
    UNIQUE KEY uq_tokens_hash (token_hash),
    KEY idx_tokens_user (user_id, revoked),
    CONSTRAINT fk_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- allow list and deny list share a table, `kind` says which is which
CREATE TABLE IF NOT EXISTS rules (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    --rules only apply to their own ecosystem, requests on npm is not requests on PyPI
    ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm',
    pattern VARCHAR(255) NOT NULL,
    kind ENUM('allow','deny') NOT NULL,
    -- empty string not NULL, NULLs never collide in a unique key and dupes breed like rabbits
    version_range VARCHAR(128) NOT NULL DEFAULT '',
    -- 0 = every application / environment. not NULL for the same unique key reason as version_range
    application_id INT UNSIGNED NOT NULL DEFAULT 0,
    environment_id INT UNSIGNED NOT NULL DEFAULT 0,
    note VARCHAR(512) NULL,
    priority INT NOT NULL DEFAULT 0,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_rules_scope (ecosystem, pattern, kind, version_range, application_id, environment_id),
    KEY idx_rules_enabled (enabled),
    KEY idx_rules_scope (application_id, environment_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS packages (
    name VARCHAR(214) NOT NULL PRIMARY KEY,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_access DATETIME NULL,
    hits INT UNSIGNED NOT NULL DEFAULT 0,
    blocked_hits INT UNSIGNED NOT NULL DEFAULT 0,
    KEY idx_packages_last_access (last_access)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- swept off the overview by hand. next real blocked install and it pops right back up
CREATE TABLE IF NOT EXISTS cleared_packages (
    name VARCHAR(214) NOT NULL,
    cleared_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cleared_by VARCHAR(64) NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- where packages come from. default row has no pattern, first match wins
CREATE TABLE IF NOT EXISTS upstreams (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    -- set when added, never changed
    ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm',
    url VARCHAR(512) NOT NULL,
    token VARCHAR(500) NOT NULL DEFAULT '',
    pattern VARCHAR(214) NOT NULL DEFAULT '',
    priority INT NOT NULL DEFAULT 100,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    is_default TINYINT(1) NOT NULL DEFAULT 0,
    -- ask the default on a 404. off, since that's exactly how dependency confusion works
    fallback TINYINT(1) NOT NULL DEFAULT 0,
    -- a mirror's own settings (RPM, APT): a filtered index, its advisory feed. json
    options VARCHAR(1000) NULL,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_upstreams_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- upstream metadata cache, gzipped (looking at you, big frameworks)
CREATE TABLE IF NOT EXISTS packuments (
    name VARCHAR(214) NOT NULL,
    variant ENUM('full','abbreviated') NOT NULL,
    body LONGBLOB NOT NULL,
    --stored so the overview doesn't read half a gig of blobs to add up sizes
    bytes INT UNSIGNED NOT NULL DEFAULT 0,
    -- upstream name. a copy from somewhere else gets refetched, not served
    source VARCHAR(64) NULL,
    etag VARCHAR(128) NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (name, variant),
    KEY idx_packuments_fetched (fetched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- tarballs live on disk, this just keeps track
CREATE TABLE IF NOT EXISTS tarballs (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL,
    path VARCHAR(512) NOT NULL,
    size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    integrity VARCHAR(255) NULL,
    --upstream it came from, same deal as packuments
    source VARCHAR(64) NULL,
    cached_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_access DATETIME NULL,
    hits INT UNSIGNED NOT NULL DEFAULT 0,
    UNIQUE KEY uq_tarballs_pkg_ver (package_name, version),
    KEY idx_tarballs_last_access (last_access)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- every registry request. this is the thing you dig through when a build breaks at 5pm on a Friday
CREATE TABLE IF NOT EXISTS access_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip VARCHAR(45) NULL,
    user_id INT UNSIGNED NULL,
    token_id INT UNSIGNED NULL,
    token_name VARCHAR(128) NULL,
    -- names not ids, so they survive the token being revoked or moved when the malware news lands
    application VARCHAR(128) NULL,
    environment VARCHAR(128) NULL,
    ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm',
    method VARCHAR(8) NOT NULL,
    path VARCHAR(512) NOT NULL,
    package_name VARCHAR(214) NULL,
    -- a tag can be 128 and an image digest is 71, so this holds either
    version VARCHAR(128) NULL,
    -- starts as a latest-tag guess, pulled_exact says whether the tarball confirmed it
    pulled_version VARCHAR(255) NULL,
    pulled_exact TINYINT(1) NOT NULL DEFAULT 0,
    npm_session VARCHAR(64) NULL,
    -- which CI the client said it runs in, off its user agent. a hint, clients can say anything
    ci VARCHAR(32) NULL,
    action ENUM('allow','deny','error','audit') NOT NULL,
    reason VARCHAR(255) NULL,
    -- which safety check refused it: killswitch, typosquat, malware, quarantine or scanning. empty for everything else
    blocked_by VARCHAR(16) NULL,
    rule_id INT UNSIGNED NULL,
    status SMALLINT UNSIGNED NOT NULL DEFAULT 200,
    bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    cache_hit TINYINT(1) NOT NULL DEFAULT 0,
    duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
    KEY idx_access_ts (ts),
    KEY idx_access_action (action, ts),
    KEY idx_access_pkg (package_name, ts),
    KEY idx_access_session (npm_session, package_name),
    KEY idx_access_app (application, ts),
    KEY idx_access_env (environment, ts),
    KEY idx_access_blocked (blocked_by, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- developer asks, approver says yes (or no). null user_id = blocked install, staff eyes only
CREATE TABLE IF NOT EXISTS requests (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm',
    package_name VARCHAR(214) NOT NULL,
    version_range VARCHAR(128) NULL,
    user_id INT UNSIGNED NULL,
    source ENUM('portal','blocked-install','learning') NOT NULL DEFAULT 'portal',
    requested_by VARCHAR(128) NULL,
    -- token the blocked install used, so there's someone to go ask
    token_name VARCHAR(128) NULL,
    ip VARCHAR(45) NULL,
    reason VARCHAR(1000) NULL,
    status ENUM('pending','approved','rejected','withdrawn','blocked') NOT NULL DEFAULT 'pending',
    hits INT UNSIGNED NOT NULL DEFAULT 1,
    decision_note VARCHAR(1000) NULL,
    -- what auto approve made of it: checking, waiting, left (for a person) or approved, and why
    auto_state VARCHAR(16) NULL,
    auto_note VARCHAR(500) NULL,
    auto_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    resolved_by INT UNSIGNED NULL,
    KEY idx_requests_status (status, created_at),
    KEY idx_requests_auto (status, auto_state, auto_at),
    KEY idx_requests_user (user_id, status),
    KEY idx_requests_pkg (package_name),
    KEY idx_requests_eco_pkg (ecosystem, package_name, status),
    CONSTRAINT fk_requests_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_requests_resolver FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- portal allow list. empty = wide open, and the api won't enable it empty. ask me how I know
CREATE TABLE IF NOT EXISTS ip_acl (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    cidr VARCHAR(64) NOT NULL,
    label VARCHAR(128) NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ip_acl_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- who can pull from the registry. Seperate from ip_acl on purpose
CREATE TABLE IF NOT EXISTS registry_acl (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    cidr VARCHAR(64) NOT NULL,
    label VARCHAR(128) NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_registry_acl_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- fetched ranges (GitHub runners, thousands of em). rewritten whole on each sync
CREATE TABLE IF NOT EXISTS registry_acl_feed (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    feed VARCHAR(32) NOT NULL,
    section VARCHAR(32) NOT NULL,
    cidr VARCHAR(64) NOT NULL,
    family TINYINT UNSIGNED NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_acl_feed_cidr (feed, section, cidr),
    KEY idx_acl_feed (feed)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- NOT in settings. an exported etag on an empty box = 304 and a cheerfully empty list
CREATE TABLE IF NOT EXISTS acl_feeds (
    feed VARCHAR(32) NOT NULL PRIMARY KEY,
    etag VARCHAR(128) NULL,
    synced_at DATETIME NULL,
    checked_at DATETIME NULL,
    ranges INT UNSIGNED NOT NULL DEFAULT 0,
    error VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- only the sha256 of the uuid, so a leaked dump isn't a free key to the building
CREATE TABLE IF NOT EXISTS breakglass_keys (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    label VARCHAR(128) NOT NULL,
    uuid_hash CHAR(64) NOT NULL,
    hint VARCHAR(12) NOT NULL,
    max_uses INT UNSIGNED NOT NULL DEFAULT 1,
    uses INT UNSIGNED NOT NULL DEFAULT 0,
    grant_minutes INT UNSIGNED NOT NULL DEFAULT 60,
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    created_by INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    last_used_at DATETIME NULL,
    last_used_ip VARCHAR(45) NULL,
    UNIQUE KEY uq_breakglass_hash (uuid_hash),
    KEY idx_breakglass_revoked (revoked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--a break glass unlock, pinned to the ip
CREATE TABLE IF NOT EXISTS bypass_grants (
    id CHAR(64) NOT NULL PRIMARY KEY,
    key_id INT UNSIGNED NULL,
    ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    KEY idx_bypass_expiry (expires_at),
    KEY idx_bypass_ip (ip),
    CONSTRAINT fk_bypass_key FOREIGN KEY (key_id) REFERENCES breakglass_keys(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- who did what in the portal. append only, as far as the app is concerned anyway
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id INT UNSIGNED NULL,
    username VARCHAR(64) NULL,
    ip VARCHAR(45) NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255) NULL,
    detail TEXT NULL,
    -- json of what changed, secrets already masked. empty for things that change nothing
    before_state TEXT NULL,
    after_state TEXT NULL,
    result ENUM('success','failure','denied') NOT NULL DEFAULT 'success',
    KEY idx_audit_ts (ts),
    KEY idx_audit_user (user_id, ts),
    KEY idx_audit_action (action, ts),
    KEY idx_audit_result (result, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS cve_scans (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME NULL,
    started_by VARCHAR(64) NOT NULL DEFAULT 'schedule',
    checked INT UNSIGNED NOT NULL DEFAULT 0,
    vulnerable INT UNSIGNED NOT NULL DEFAULT 0,
    fresh INT UNSIGNED NOT NULL DEFAULT 0,
    resolved INT UNSIGNED NOT NULL DEFAULT 0,
    failed INT UNSIGNED NOT NULL DEFAULT 0,
    status ENUM('running','done','failed','canceled') NOT NULL DEFAULT 'running',
    KEY idx_cve_scans_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- advisory text, fetched once and reused
CREATE TABLE IF NOT EXISTS cve_advisories (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    cves VARCHAR(512) NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL DEFAULT 'unrated',
    summary VARCHAR(512) NOT NULL DEFAULT '',
    -- other ids for it. GHSA + PYSEC is one bug with two names, not two bugs
    aliases TEXT NULL,
    fixes TEXT NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- every image digest pulled through here and what reading its layers found. one row per repository and digest
CREATE TABLE IF NOT EXISTS image_scans (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    repository VARCHAR(255) NOT NULL,
    digest VARCHAR(80) NOT NULL,
    -- queued, scanning, done, skipped (not a runnable image), failed
    status VARCHAR(16) NOT NULL DEFAULT 'queued',
    os VARCHAR(128) NOT NULL DEFAULT '',
    feed VARCHAR(64) NOT NULL DEFAULT '',
    components INT UNSIGNED NOT NULL DEFAULT 0,
    vulnerable INT UNSIGNED NOT NULL DEFAULT 0,
    severity VARCHAR(16) NOT NULL DEFAULT '',
    fixable_severity VARCHAR(16) NOT NULL DEFAULT '',
    notes TEXT NULL,
    error VARCHAR(512) NOT NULL DEFAULT '',
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME NULL,
    scanned_at DATETIME NULL,
    checked_at DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_image_scan (repository, digest),
    KEY idx_image_scans_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- the packages inside a scanned image, with what is known against each
CREATE TABLE IF NOT EXISTS image_components (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scan_id INT UNSIGNED NOT NULL,
    type VARCHAR(8) NOT NULL,
    name VARCHAR(214) NOT NULL,
    version VARCHAR(128) NOT NULL,
    ecosystem VARCHAR(64) NULL,
    binaries VARCHAR(1024) NOT NULL DEFAULT '',
    advisories TEXT NULL,
    cves VARCHAR(512) NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL DEFAULT '',
    fixable_severity VARCHAR(16) NOT NULL DEFAULT '',
    fixed_in VARCHAR(128) NULL,
    summary VARCHAR(512) NOT NULL DEFAULT '',
    KEY idx_image_components_scan (scan_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- allowed versions with a known advisory. recent first_seen = new since somebody last looked
CREATE TABLE IF NOT EXISTS cve_findings (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm',
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(128) NOT NULL,
    advisories TEXT NOT NULL,
    cves VARCHAR(512) NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL DEFAULT 'unrated',
    summary VARCHAR(512) NOT NULL DEFAULT '',
    fixed_in VARCHAR(64) NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged TINYINT(1) NOT NULL DEFAULT 0,
    UNIQUE KEY uq_cve_finding_eco (ecosystem, package_name, version),
    KEY idx_cve_findings_seen (first_seen),
    KEY idx_cve_findings_sev (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- someone pulled a vulnerable version. outlives the finding, so "who pulled that" works a year later
CREATE TABLE IF NOT EXISTS vuln_downloads (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL DEFAULT 'npm',
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'unrated',
    advisories VARCHAR(512) NOT NULL DEFAULT '',
    cves VARCHAR(512) NOT NULL DEFAULT '',
    ip VARCHAR(45) NULL,
    user_id INT UNSIGNED NULL,
    token_name VARCHAR(64) NULL,
    -- stamped at pull time, same reason as access_log
    application VARCHAR(128) NULL,
    environment VARCHAR(128) NULL,
    cache_hit TINYINT(1) NOT NULL DEFAULT 0,
    ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_vuln_dl_ts (ts),
    KEY idx_vuln_dl_app (application, ts),
    KEY idx_vuln_dl_pkg (package_name, version),
    KEY idx_vuln_dl_sev (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- throttle counters live in the db so bouncing the app doesn't reset login/break glass limits
CREATE TABLE IF NOT EXISTS rate_limits (
    k VARCHAR(190) NOT NULL PRIMARY KEY,
    hits INT UNSIGNED NOT NULL DEFAULT 0,
    reset_at DATETIME NOT NULL,
    KEY idx_rate_limits_reset (reset_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- per address digest mark, only moves once the mail actually left.
-- mail server down a day = one catch-up mail, not a day of spam
CREATE TABLE IF NOT EXISTS email_digest_state (
    user_id INT UNSIGNED NOT NULL,
    kind VARCHAR(32) NOT NULL,
    recipient VARCHAR(254) NOT NULL,
    mark DATETIME NOT NULL,
    last_sent_at DATETIME NULL,
    PRIMARY KEY (user_id, kind, recipient),
    CONSTRAINT fk_digest_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- every mail we tried to send, for "it never arrived". no bodies
CREATE TABLE IF NOT EXISTS email_log (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind VARCHAR(32) NOT NULL,
    to_address VARCHAR(254) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    transport VARCHAR(16) NOT NULL,
    ok TINYINT(1) NOT NULL DEFAULT 0,
    error VARCHAR(255) NULL,
    KEY idx_email_log_ts (ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- half finished SSO logins. verifier is the PKCE half that never leaves the box, used once then swept
CREATE TABLE IF NOT EXISTS sso_states (
    state CHAR(64) NOT NULL PRIMARY KEY,
    nonce CHAR(64) NOT NULL,
    verifier VARCHAR(128) NOT NULL,
    ip VARCHAR(45) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_sso_states_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- PyPI project pages and JSON api docs, as fetched
CREATE TABLE IF NOT EXISTS pypi_documents (
    project VARCHAR(214) NOT NULL,
    kind ENUM('simple','json') NOT NULL,
    -- empty = whole project, otherwise the release this JSON API doc is for
    version VARCHAR(64) NOT NULL DEFAULT '',
    body LONGBLOB NOT NULL,
    bytes INT UNSIGNED NOT NULL DEFAULT 0,
    source VARCHAR(64) NULL,
    etag VARCHAR(128) NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project, kind, version),
    KEY idx_pypi_documents_fetched (fetched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- basically tarballs wearing a python costume
CREATE TABLE IF NOT EXISTS pypi_files (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    project VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL DEFAULT '',
    filename VARCHAR(255) NOT NULL,
    path VARCHAR(512) NOT NULL,
    size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    sha256 CHAR(64) NULL,
    source VARCHAR(64) NULL,
    cached_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_access DATETIME NULL,
    hits INT UNSIGNED NOT NULL DEFAULT 0,
    UNIQUE KEY uq_pypi_files (project, filename),
    KEY idx_pypi_files_release (project, version),
    KEY idx_pypi_files_last_access (last_access)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- one row per exact file. first sha256 wins, a diffrent one later gets logged and ignored
CREATE TABLE IF NOT EXISTS artifacts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL DEFAULT '',
    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(64) NOT NULL DEFAULT 'application/octet-stream',
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    --registry it came down from
    upstream VARCHAR(64) NULL,
    -- small json, like the integrity npm published. Never anything a client sent
    metadata TEXT NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cached_at DATETIME NULL,
    last_access DATETIME NULL,
    download_count INT UNSIGNED NOT NULL DEFAULT 0,
    status ENUM('unknown','quarantined','approved','blocked') NOT NULL DEFAULT 'unknown',
    -- the license as read (SPDX where possible) and what the license lists made of it
    license_expression VARCHAR(512) NULL,
    license_verdict ENUM('allowed','review','blocked') NULL,
    license_note VARCHAR(255) NULL,
    license_checked_at DATETIME NULL,
    UNIQUE KEY uq_artifacts_file (ecosystem, package_name, version, filename),
    KEY idx_artifacts_license (license_verdict),
    KEY idx_artifacts_sha256 (sha256),
    KEY idx_artifacts_first_seen (first_seen),
    KEY idx_artifacts_last_access (last_access)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- the bytes themselves live on disk under blobs/sha256/, this is the ledger
CREATE TABLE IF NOT EXISTS blobs (
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at DATETIME NULL,
    -- 1 once the bucket holds it whole. until then the only copy is on a node's disk
    in_bucket TINYINT(1) NOT NULL DEFAULT 0,
    uploaded_at DATETIME NULL,
    upload_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    upload_error VARCHAR(255) NULL,
    KEY idx_blobs_bucket (in_bucket, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- a release we already hold, and the registry now sends or publishes something else.
-- content = different bytes came down (kept in held_sha256 for review), published = the
-- registry advertises a diffrent digest. fingerprint dedupes repeats of the same change
CREATE TABLE IF NOT EXISTS integrity_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    kind ENUM('content','published') NOT NULL,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL DEFAULT '',
    filename VARCHAR(255) NOT NULL,
    artifact_id BIGINT UNSIGNED NULL,
    upstream VARCHAR(64) NULL,
    expected VARCHAR(255) NOT NULL,
    observed VARCHAR(255) NOT NULL,
    held_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    held_size BIGINT UNSIGNED NULL,
    metadata TEXT NULL,
    status ENUM('open','accepted','dismissed') NOT NULL DEFAULT 'open',
    occurrences INT UNSIGNED NOT NULL DEFAULT 1,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_by VARCHAR(64) NULL,
    resolved_at DATETIME NULL,
    note VARCHAR(1000) NULL,
    UNIQUE KEY uq_integrity_fingerprint (fingerprint),
    KEY idx_integrity_status (status, last_seen),
    KEY idx_integrity_held (held_sha256),
    KEY idx_integrity_pkg (ecosystem, package_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- quarantine: exact files held back until a person decides. open = held, released = let go,
-- rejected = refused for good. source says who put it there (integrity, manual, a scanner later on)
CREATE TABLE IF NOT EXISTS quarantine_holds (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL DEFAULT '',
    filename VARCHAR(255) NOT NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    source VARCHAR(64) NOT NULL,
    reason VARCHAR(1000) NOT NULL,
    status ENUM('open','released','rejected') NOT NULL DEFAULT 'open',
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_by VARCHAR(64) NULL,
    resolved_at DATETIME NULL,
    note VARCHAR(1000) NULL,
    KEY idx_holds_file (ecosystem, package_name, version, filename, status),
    KEY idx_holds_status (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Safe Version Resolution log. one row per metadata answer that left versions out,
-- with why, and the version the client then pulled. no requested range, clients never send it
CREATE TABLE IF NOT EXISTS resolutions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    application VARCHAR(128) NULL,
    environment VARCHAR(128) NULL,
    token_name VARCHAR(128) NULL,
    user_id INT UNSIGNED NULL,
    ip VARCHAR(45) NULL,
    npm_session VARCHAR(64) NULL,
    offered_count INT UNSIGNED NOT NULL DEFAULT 0,
    excluded_count INT UNSIGNED NOT NULL DEFAULT 0,
    excluded MEDIUMTEXT NULL,
    latest_offered VARCHAR(64) NULL,
    selected_version VARCHAR(64) NULL,
    selected_at DATETIME NULL,
    KEY idx_resolutions_pkg (ecosystem, package_name, ts),
    KEY idx_resolutions_session (npm_session),
    KEY idx_resolutions_ts (ts),
    KEY idx_resolutions_app (application, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- malware scan results. keyed on the bytes, so a blob two packages share is scanned once.
-- one row per scanner, a rescan replaces it
CREATE TABLE IF NOT EXISTS artifact_scans (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scanner VARCHAR(64) NOT NULL,
    scanner_version VARCHAR(128) NULL,
    status ENUM('CLEAN','SUSPICIOUS','MALICIOUS','ERROR','NOT_SCANNED') NOT NULL,
    signature VARCHAR(255) NULL,
    findings TEXT NULL,
    scan_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
    UNIQUE KEY uq_scan_blob_scanner (sha256, scanner),
    KEY idx_scans_status (status, scan_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- utilization, one row a minute per node: averages for the minute, peaks where a spike matters.
-- kept 2 days for the live view, the 2 and 10 minute tables below hold the rest
CREATE TABLE IF NOT EXISTS utilization_minute (
    node VARCHAR(64) NOT NULL,
    ts DATETIME NOT NULL,
    host_cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
    host_cpu_max DECIMAL(5,2) NOT NULL DEFAULT 0,
    app_cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
    host_mem_used BIGINT UNSIGNED NOT NULL DEFAULT 0,
    host_mem_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
    app_mem BIGINT UNSIGNED NOT NULL DEFAULT 0,
    disk_used BIGINT UNSIGNED NOT NULL DEFAULT 0,
    disk_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_rx_bps BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_tx_bps BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_rx_max BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_tx_max BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (node, ts),
    KEY idx_util_minute_ts (ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2 minute averages of the minutes, kept a month
CREATE TABLE IF NOT EXISTS utilization_2min (
    node VARCHAR(64) NOT NULL,
    ts DATETIME NOT NULL,
    host_cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
    host_cpu_max DECIMAL(5,2) NOT NULL DEFAULT 0,
    app_cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
    host_mem_used BIGINT UNSIGNED NOT NULL DEFAULT 0,
    host_mem_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
    app_mem BIGINT UNSIGNED NOT NULL DEFAULT 0,
    disk_used BIGINT UNSIGNED NOT NULL DEFAULT 0,
    disk_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_rx_bps BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_tx_bps BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_rx_max BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_tx_max BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (node, ts),
    KEY idx_util_2min_ts (ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10 minute averages for the long view, kept a year and then gone
CREATE TABLE IF NOT EXISTS utilization_10min (
    node VARCHAR(64) NOT NULL,
    ts DATETIME NOT NULL,
    host_cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
    host_cpu_max DECIMAL(5,2) NOT NULL DEFAULT 0,
    app_cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
    host_mem_used BIGINT UNSIGNED NOT NULL DEFAULT 0,
    host_mem_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
    app_mem BIGINT UNSIGNED NOT NULL DEFAULT 0,
    disk_used BIGINT UNSIGNED NOT NULL DEFAULT 0,
    disk_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_rx_bps BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_tx_bps BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_rx_max BIGINT UNSIGNED NOT NULL DEFAULT 0,
    net_tx_max BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (node, ts),
    KEY idx_util_10min_ts (ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- the portal's own header icon and favicon, when an admin swaps the anvil out
CREATE TABLE IF NOT EXISTS branding (
    kind VARCHAR(16) NOT NULL PRIMARY KEY,
    content_type VARCHAR(32) NOT NULL,
    body MEDIUMBLOB NOT NULL,
    sha256 CHAR(64) NOT NULL,
    width SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    height SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    updated_by VARCHAR(64) NULL,
    updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- names that imitate a well known package. dismissed by a person = not a squat, stops being flagged
CREATE TABLE IF NOT EXISTS typosquat_findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    looks_like VARCHAR(214) NOT NULL,
    technique VARCHAR(64) NOT NULL,
    last_action ENUM('warned','blocked') NOT NULL,
    hits INT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('open','dismissed') NOT NULL DEFAULT 'open',
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dismissed_by VARCHAR(64) NULL,
    dismissed_at DATETIME NULL,
    UNIQUE KEY uq_typosquat_name (ecosystem, package_name),
    KEY idx_typosquat_status (status, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- the kill switch. active ones beat every rule, pin, scope and audit only mode until lifted
CREATE TABLE IF NOT EXISTS kill_switches (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- package, one file by its sha256, or everything an advisory is recorded against
    kind ENUM('package','hash','advisory') NOT NULL DEFAULT 'package',
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    -- empty = every version
    version_range VARCHAR(128) NOT NULL DEFAULT '',
    -- the sha256 or the advisory id. empty for a package, and ecosystem and package_name are empty for the others
    subject VARCHAR(128) NOT NULL DEFAULT '',
    reason VARCHAR(500) NOT NULL,
    status ENUM('active','lifted') NOT NULL DEFAULT 'active',
    purged_files INT UNSIGNED NOT NULL DEFAULT 0,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lifted_by VARCHAR(64) NULL,
    lifted_at DATETIME NULL,
    lift_note VARCHAR(500) NULL,
    KEY idx_kill_active (status, ecosystem, package_name),
    KEY idx_kill_subject (status, kind, subject)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- waivers: a time boxed "yes, we know" for one finding. only active ones not past expires_at count
CREATE TABLE IF NOT EXISTS waivers (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    kind ENUM('advisory','license','cooloff') NOT NULL,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version_range VARCHAR(128) NOT NULL DEFAULT '',
    -- advisory ids for advisory, the license expression for license, empty for cooloff
    subject VARCHAR(512) NOT NULL DEFAULT '',
    application_id INT UNSIGNED NOT NULL DEFAULT 0,
    environment_id INT UNSIGNED NOT NULL DEFAULT 0,
    reason VARCHAR(1000) NOT NULL,
    -- a ticket, change number or link. kept as text, the portal never turns it into a link
    reference VARCHAR(255) NOT NULL DEFAULT '',
    days SMALLINT UNSIGNED NOT NULL DEFAULT 30,
    status ENUM('pending','active','rejected','revoked','expired') NOT NULL DEFAULT 'pending',
    expires_at DATETIME NULL,
    requested_by VARCHAR(64) NULL,
    requested_by_id INT UNSIGNED NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_by VARCHAR(64) NULL,
    decided_at DATETIME NULL,
    decision_note VARCHAR(1000) NULL,
    KEY idx_waivers_lookup (status, kind, ecosystem, package_name),
    KEY idx_waivers_expiry (status, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- consumption: one row per version per consumer, rolled up from served downloads and kept far longer than
-- access_log. fingerprint is a sha256 of the consumer columns so the unique key stays small
CREATE TABLE IF NOT EXISTS consumption (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(128) NOT NULL,
    user_id INT UNSIGNED NULL,
    token_name VARCHAR(128) NULL,
    application VARCHAR(128) NULL,
    environment VARCHAR(128) NULL,
    ci VARCHAR(32) NULL,
    ip VARCHAR(45) NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    downloads INT UNSIGNED NOT NULL DEFAULT 1,
    UNIQUE KEY uq_consumption_fingerprint (fingerprint),
    KEY idx_consumption_version (ecosystem, package_name, version),
    KEY idx_consumption_app (application, environment),
    KEY idx_consumption_last (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- where security events go. secret is the webhook signing key or the Splunk HEC token, never sent back out by the api
CREATE TABLE IF NOT EXISTS integrations (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    kind ENUM('webhook','splunk_hec','syslog') NOT NULL,
    url VARCHAR(512) NULL,
    host VARCHAR(255) NULL,
    port SMALLINT UNSIGNED NULL,
    transport ENUM('udp','tcp','tls') NULL,
    format ENUM('json','cef') NOT NULL DEFAULT 'json',
    secret VARCHAR(512) NULL,
    -- json list of event names, or a star for all of them
    events TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    last_status VARCHAR(16) NULL,
    last_error VARCHAR(255) NULL,
    last_attempt_at DATETIME NULL,
    last_success_at DATETIME NULL,
    failures INT UNSIGNED NOT NULL DEFAULT 0,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_integrations_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- one row per event per integration. delivered with backoff, claimed so two nodes never send the same one
CREATE TABLE IF NOT EXISTS event_outbox (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    integration_id INT UNSIGNED NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload TEXT NOT NULL,
    status ENUM('pending','delivered','failed') NOT NULL DEFAULT 'pending',
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL,
    claim CHAR(32) NULL,
    claimed_at DATETIME NULL,
    delivered_at DATETIME NULL,
    response_status SMALLINT UNSIGNED NULL,
    last_error VARCHAR(255) NULL,
    created_at DATETIME NOT NULL,
    KEY idx_outbox_due (status, next_attempt_at),
    KEY idx_outbox_claim (claim),
    KEY idx_outbox_integration (integration_id, id),
    KEY idx_outbox_created (created_at),
    CONSTRAINT fk_outbox_integration FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- provenance per cached file, the same model for every ecosystem. VERIFIED means a Sigstore attestation checked out
-- against the pinned root and names these exact bytes. sha256 is what was checked, a different file gets checked again
CREATE TABLE IF NOT EXISTS provenance (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(64) NOT NULL DEFAULT '',
    filename VARCHAR(255) NOT NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status ENUM('VERIFIED','PRESENT_UNVERIFIED','MISSING','INVALID') NOT NULL,
    reason VARCHAR(255) NULL,
    registry_signature VARCHAR(24) NULL,
    source_repository VARCHAR(512) NULL,
    source_commit VARCHAR(128) NULL,
    source_ref VARCHAR(255) NULL,
    builder VARCHAR(512) NULL,
    workflow VARCHAR(512) NULL,
    issuer VARCHAR(255) NULL,
    subject_digest VARCHAR(200) NULL,
    predicate_type VARCHAR(255) NULL,
    -- the attestation as the registry published it, when small enough to keep
    attestation MEDIUMTEXT NULL,
    verified_at DATETIME NULL,
    checked_at DATETIME NOT NULL,
    UNIQUE KEY uq_provenance_file (ecosystem, package_name, version, filename),
    KEY idx_provenance_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- what the outside world says about a CVE: on CISA's known exploited list, and FIRST's EPSS score. refreshed daily
CREATE TABLE IF NOT EXISTS vuln_intel (
    cve VARCHAR(32) NOT NULL PRIMARY KEY,
    kev TINYINT(1) NOT NULL DEFAULT 0,
    kev_added DATE NULL,
    -- the date US federal agencies are told to have it fixed by
    kev_due DATE NULL,
    kev_ransomware TINYINT(1) NOT NULL DEFAULT 0,
    kev_name VARCHAR(255) NULL,
    epss DECIMAL(6,5) NULL,
    epss_percentile DECIMAL(6,5) NULL,
    epss_date DATE NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY idx_vuln_intel_kev (kev)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- how each intel feed last went. an error keeps the last good data and says why the refresh failed
CREATE TABLE IF NOT EXISTS intel_feeds (
    feed VARCHAR(16) NOT NULL PRIMARY KEY,
    synced_at DATETIME NULL,
    checked_at DATETIME NULL,
    entries INT UNSIGNED NOT NULL DEFAULT 0,
    error VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- key=value metadata people put on a package version, or on every version of a package (version empty)
CREATE TABLE IF NOT EXISTS artifact_properties (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(128) NOT NULL DEFAULT '',
    k VARCHAR(64) NOT NULL,
    v VARCHAR(255) NOT NULL,
    set_by VARCHAR(64) NULL,
    set_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_property (ecosystem, package_name, version, k),
    KEY idx_property_kv (k, v)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- where an exact version stands in its lifecycle. no row = no stage yet
CREATE TABLE IF NOT EXISTS lifecycle_stages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(128) NOT NULL,
    stage ENUM('quarantine','development','test','approved','production','blocked') NOT NULL,
    reason VARCHAR(500) NULL,
    set_by VARCHAR(64) NULL,
    set_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_lifecycle (ecosystem, package_name, version),
    KEY idx_lifecycle_stage (stage)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- every move, never updated or pruned
CREATE TABLE IF NOT EXISTS lifecycle_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    package_name VARCHAR(214) NOT NULL,
    version VARCHAR(128) NOT NULL,
    from_stage VARCHAR(16) NULL,
    to_stage VARCHAR(16) NOT NULL,
    reason VARCHAR(500) NULL,
    moved_by VARCHAR(64) NULL,
    moved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_lifecycle_history (ecosystem, package_name, version, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- which digest an image tag pointed at, and how often it has moved. the bytes live in artifacts, keyed by digest
CREATE TABLE IF NOT EXISTS oci_tags (
    repository VARCHAR(214) NOT NULL,
    tag VARCHAR(128) NOT NULL,
    digest CHAR(71) NOT NULL,
    upstream VARCHAR(64) NULL,
    moved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    moves INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (repository, tag),
    KEY idx_oci_tags_digest (digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- every digest a tag has pointed at while this box watched. an approved tag lets its own history through, so a pipeline
-- pinned to a digest it pulled by that tag keeps working after the tag moves on
CREATE TABLE IF NOT EXISTS oci_tag_digests (
    repository VARCHAR(214) NOT NULL,
    tag VARCHAR(128) NOT NULL,
    digest CHAR(71) NOT NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (repository, tag, digest),
    KEY idx_oci_tag_digests_digest (repository, digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- image manifests by digest, small json. kept so an image already pulled can be pulled again with the upstream off or down
CREATE TABLE IF NOT EXISTS oci_manifests (
    repository VARCHAR(214) NOT NULL,
    digest CHAR(71) NOT NULL,
    media_type VARCHAR(255) NOT NULL DEFAULT '',
    body MEDIUMBLOB NOT NULL,
    size INT UNSIGNED NOT NULL DEFAULT 0,
    upstream VARCHAR(64) NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (repository, digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- image layers on their way in from docker push. the bytes wait in the cache's tmp folder until the digest is named
CREATE TABLE IF NOT EXISTS oci_uploads (
    id CHAR(36) NOT NULL PRIMARY KEY,
    repository VARCHAR(214) NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    username VARCHAR(64) NOT NULL,
    size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_oci_uploads_user (user_id),
    KEY idx_oci_uploads_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- bearer tokens docker gets from /v2/token for the registry token it logged in with. five minutes, and only the hash
CREATE TABLE IF NOT EXISTS oci_bearers (
    hash CHAR(64) NOT NULL PRIMARY KEY,
    token_id INT UNSIGNED NOT NULL,
    expires_at DATETIME NOT NULL,
    KEY idx_oci_bearers_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- what a let through manifest names: its config and layers, or the platform images of a list
CREATE TABLE IF NOT EXISTS oci_refs (
    repository VARCHAR(214) NOT NULL,
    child CHAR(71) NOT NULL,
    parent CHAR(71) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (repository, child, parent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- who has to have signed the images of a repository: an exact name, acme/* or a prefix*. signers is json: public keys,
-- keyless identities (issuer and subject) and whether the transparency log is required
CREATE TABLE IF NOT EXISTS image_trust (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    pattern VARCHAR(255) NOT NULL,
    mode VARCHAR(8) NOT NULL,
    signers MEDIUMTEXT NOT NULL,
    note VARCHAR(255) NULL,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_image_trust (pattern)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- what a signature check found, per digest and per version of the policy it was checked against
CREATE TABLE IF NOT EXISTS image_signatures (
    repository VARCHAR(214) NOT NULL,
    digest CHAR(71) CHARACTER SET ascii NOT NULL,
    trust_hash CHAR(64) CHARACTER SET ascii NOT NULL,
    ok TINYINT(1) NOT NULL,
    signer VARCHAR(512) NULL,
    detail VARCHAR(1000) NULL,
    checked_at DATETIME NOT NULL,
    PRIMARY KEY (repository, digest, trust_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- package metadata for the ecosystems after npm and PyPI (NuGet first), one json document per package and kind
CREATE TABLE IF NOT EXISTS package_documents (
    ecosystem VARCHAR(16) NOT NULL,
    name VARCHAR(214) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    body MEDIUMBLOB NOT NULL,
    bytes INT UNSIGNED NOT NULL DEFAULT 0,
    source VARCHAR(64) NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ecosystem, name, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- names that belong to this organization. an exact name, an npm scope as @acme/*, or a prefix ending in *
CREATE TABLE IF NOT EXISTS private_names (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ecosystem VARCHAR(16) NOT NULL,
    pattern VARCHAR(214) NOT NULL,
    note VARCHAR(255) NULL,
    created_by VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_private_name (ecosystem, pattern)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
