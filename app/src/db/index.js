// db pool, schema loader, and the settings cache. The plumbing, basically.
// Author: Tim Rice

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const config = require('../config');
const log = require('../logger');
const { temporaryPassword } = require('../security/auth/temp-password');
const schema = require('./schema');

let pool = null;

//anything missing gets written on boot
const DEFAULT_SETTINGS = {
  policy_mode: 'whitelist',
  audit_mode: '0',
  require_auth: '0',
  upstream_registry: config.upstreamRegistry,
  upstream_token: '',
  // off = never phone out, cache only. big red button for a keyv compromise kind of day
  upstream_enabled: '1',
  //python packages. off until someone sets up a PyPI registry on purpose
  pypi_enabled: '0',
  // container images through /v2. off until an upstream registry is set up for them
  oci_enabled: '0',
  // .NET packages through /nuget. off until someone sets up a NuGet feed on purpose
  nuget_enabled: '0',
  // Java packages through /maven. off until someone sets up a Maven repository on purpose
  maven_enabled: '0',
  // Ruby gems through /rubygems. off until someone sets up a gem source on purpose
  rubygems_enabled: '0',
  // iOS and macOS pods through /cocoapods. off until someone sets up a CocoaPods CDN on purpose
  cocoapods_enabled: '0',
  // Swift packages through /swift, a package registry over a git host. off until someone sets one up on purpose
  swift_enabled: '0',
  // PHP packages through /composer. off until someone sets up a Composer repository on purpose
  composer_enabled: '0',
  // dnf and yum through /rpm/<mirror>/, mirrors of distro repositories. off until someone sets one up on purpose
  rpm_enabled: '0',
  // apt through /apt/<mirror>/, mirrors of Debian and Ubuntu archives. off until someone sets one up on purpose
  apt_enabled: '0',
  // look inside every image pulled for vulnerable packages. nothing leaves the box but package names and versions
  oci_scan: '1',
  oci_scan_max_gb: '16',
  // an image not scanned yet is not served until it is. off, the first pull goes out and the scan follows
  oci_scan_before_serve: '0',
  // safe resolution on images counts only advisories an upgrade fixes today
  oci_scan_ignore_unfixed: '1',
  packument_ttl: '300',
  stale_ok_seconds: '604800',
  cache_tarballs: '1',
  // an allow rule for every version of a package caches the version current when it is written, if nothing of it is yet
  cache_latest_on_allow: '1',
  quarantine_mode: 'permissive',
  // what a push that looks like it carries a secret gets: hold, warn or off
  push_secret_scan: 'hold',
  safe_resolution: '0',
  safe_resolution_severity: 'HIGH',
  // CISA says it is being exploited: left out whatever its severity says
  safe_resolution_kev: '1',
  // an EPSS score from 0 to 1, empty for off
  safe_resolution_epss: '',
  malware_scanning: '0',
  malware_scanners: 'blocklist,clamav,osv',
  // a MAL- advisory the vulnerability scan records goes on the kill switch by itself
  malicious_auto_kill: '1',
  malware_on_malicious: 'reject',
  malware_on_suspicious: 'hold',
  malware_scan_before_serve: '0',
  malware_hash_blocklist: '',
  malware_clamd_host: '',
  malware_clamd_port: '3310',
  malware_rest_url: '',
  malware_rest_token: '',
  email_malware_alerts: '1',
  email_malware_daily: '1',
  license_enforcement: 'off',
  license_allowed: 'MIT\nMIT-0\nISC\n0BSD\nApache-2.0\nBSD-2-Clause\nBSD-3-Clause\nZlib\nUnlicense\nCC0-1.0\nPSF-2.0\nPython-2.0\nBlueOak-1.0.0',
  license_review: 'GPL-*\nLGPL-*\nAGPL-*\nMPL-*\nEPL-*\nCDDL-*\nSSPL-1.0\nBUSL-1.1\nLicenseRef-*',
  license_blocked: '',
  license_unlisted: 'review',
  license_unknown: 'review',
  cooloff_hours: '0',
  cooloff_exempt: '',
  cooloff_unknown: 'allow',
  typosquat_mode: 'warn',
  typosquat_protected: '',
  typosquat_exempt: '',
  waiver_max_days: '90',
  auto_request: '1',
  // approving a request also writes pinned allow rules for its clean dependencies. off = approvers decide on each
  approve_clean_dependencies: '0',
  // Dashboard switch, admins only. clean scans and nothing High or Critical get approved without a person
  auto_approve: '0',
  auto_approve_reason: '',
  auto_approve_by: '',
  auto_approve_at: '',
  // blocked stage refused to everyone, production environments only get production. off = stages are information
  lifecycle_enforce: '0',
  // normal, degraded or lockdown, and who set it why. changed on the dashboard only, never by Settings save or an import
  registry_mode: 'normal',
  registry_mode_reason: '',
  registry_mode_by: '',
  registry_mode_at: '',
  show_help_url: '1',
  log_retention_days: '30',
  // who consumed what, one small row per version per consumer. 0 keeps it forever
  consumption_retention_days: '365',
  // provenance that is there but does not hold up. warn records it, hold quarantines the file
  provenance_invalid: 'warn',
  // a new version with less provenance than the ones before it: hold, warn or off
  provenance_downgrade: 'hold',
  // a release that starts running code when it is installed: warn, hold or off
  install_script_check: 'warn',
  // an npm listing that disagrees with its tarball: hold, warn or off
  manifest_confusion: 'hold',
  // a new publisher, a maintainer change or a package that lay still for a year: warn, hold or off
  takeover_signals: 'warn',

  // overview counts cached in memory. 0 = recount every page load (enjoy)
  dashboard_cache_minutes: '30',

  // overview ignores blocks before this. nothing deleted
  blocked_cleared_at: '',
  public_url: config.publicUrl,
  registry_name: 'ForgeRepo',

  min_password_length: '12',
  max_login_attempts: '5',
  lockout_minutes: '15',
  session_idle_minutes: '60',

  // portal ip allow list. off by default so nobody locks themselves out on day one
  acl_enabled: '0',

  // separate allow list for npm clients, unrelated to the portal one
  registry_acl_enabled: '0',

  // token holders skip the network filter. off, without required tokens that's a hole
  registry_acl_token_ok: '0',

  // GitHub runner ranges. shared by every GitHub user on the planet, read up first
  registry_acl_github: '0',
  registry_acl_github_sections: 'actions',
  registry_acl_github_hours: '24',

  // package managers only. breaks curl scripts, wordlist scanners get 404s
  npm_clients_only: '0',

  // 0 = off. reports only, never blocks
  cve_scan_hours: '24',
  // CISA KEV and FIRST EPSS. on by default, a box with no way out just shows them as not reachable
  intel_feeds_enabled: '1',
  intel_feed_hours: '24',

  // warn devs about what the scan knows, never block. blocking is a human's call
  audit_answer: '1',
  audit_warn_install: '1',
  audit_log_downloads: '1',
  breakglass_enabled: '1',
  breakglass_grant_minutes: '60',

  // email: smtp relay, or M365 over Graph for shops allergic to smtp auth
  email_enabled: '0',
  email_transport: 'smtp',
  email_from: '',
  email_from_name: '',
  smtp_host: '',
  smtp_port: '587',
  // tls = 465, starttls = 587 and what nearly everything wants
  smtp_security: 'starttls',
  smtp_user: '',
  smtp_password: '',
  smtp_allow_self_signed: '0',
  graph_tenant: '',
  graph_client_id: '',
  graph_client_secret: '',
  graph_sender: '',

  // OIDC. sso_only refuses passwords, so provider down = everyone locked out.
  // enable_local_login.sh flips it back to both
  sso_enabled: '0',
  sso_mode: 'both',
  sso_button_label: 'Sign in with SSO',
  sso_auto_create: '1',
  sso_default_role: 'developer',
  oidc_issuer: '',
  oidc_client_id: '',
  oidc_client_secret: '',
  oidc_scopes: 'openid profile email',
  oidc_redirect_url: '',
  // empty = roles managed here by hand
  sso_role_groups: '',
  sso_role_sync: '1',
  sso_require_role_group: '0',
  oidc_groups_claim: 'groups',

  // where cached files live. s3 = this disk in front of a bucket (S3, or anything that speaks it)
  storage_backend: 'local',
  s3_endpoint: '',
  s3_region: 'us-east-1',
  s3_bucket: '',
  s3_prefix: '',
  s3_path_style: '0',
  s3_access_key_id: '',
  s3_secret_access_key: '',
  // azure blob. endpoint empty = https://<account>.blob.core.windows.net
  az_endpoint: '',
  az_account: '',
  az_container: '',
  az_prefix: '',
  az_account_key: '',
  // local copies of files the bucket already holds, in MB. 0 keeps none
  storage_cache_mb: '20480'
};

// never returned by the api or exported, only replaced. new secrets go here
const SECRET_SETTINGS = new Set([
  'upstream_token', 'smtp_password', 'graph_client_secret', 'oidc_client_secret', 'malware_rest_token', 's3_secret_access_key', 'az_account_key'
]);

function makeConfig() {
  const base = {
    user: config.db.user,
    password: config.db.password,
    database: config.db.database,
    waitForConnections: true,
    connectionLimit: config.db.connectionLimit,
    queueLimit: 0,
    charset: 'utf8mb4_unicode_ci',
    dateStrings: true
  };
  // socket is the normal path, tcp is only for when someone points at an outside db
  if (config.db.host) {
    base.host = config.db.host;
    base.port = config.db.port;
    //no point encrypting a unix socket, so tls only matters out here
    if (config.db.ssl) base.ssl = config.db.ssl;
  } else {
    base.socketPath = config.db.socketPath;
  }
  return base;
}

async function connect() {
  pool = mysql.createPool(makeConfig());

  // mariadb in the container might still be yawning, keep knocking
  const deadline = Date.now() + 120000;
  for (;;) {
    try {
      const conn = await pool.getConnection();
      await conn.ping();
      conn.release();
      return pool;
    } catch (err) {
      if (Date.now() > deadline) throw err;
      log.info('waiting for the database', err.code || err.message);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

async function query(sql, params) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

async function one(sql, params) {
  const rows = await query(sql, params);
  return rows.length ? rows[0] : null;
}

function loadSchema() {
  return schema.load({ pool, query, one, log });
}

// settings get read on basically every request, so keep them in memory
const cache = new Map();
let cacheLoadedAt = 0;
let stamp = '';

async function loadSettings(force) {
  if (!force && Date.now() - cacheLoadedAt < 5000) return;
  const rows = await query('SELECT k, v FROM settings');
  cache.clear();
  for (const row of rows) cache.set(row.k, row.v);
  cacheLoadedAt = Date.now();
  stamp = await stampNow();
}

// what the settings table looks like right now, in one small read
async function stampNow() {
  const row = await one('SELECT COUNT(*) AS n, MAX(updated_at) AS at FROM settings');
  return row ? `${row.n}:${row.at ? new Date(row.at).getTime() : 0}` : '';
}

// another node changed a setting: cheap to ask, so it is asked often. a change in the same second as the last read
// could hide behind an unchanged stamp, so a fresh stamp is read again next time round
async function pollSettings() {
  const now = await stampNow();
  const changed = now !== stamp;
  const age = Number(String(now).split(':')[1] || 0);
  if (changed || Date.now() - age < 2000) await loadSettings(true);
  return changed;
}

function get(key, fallback) {
  if (cache.has(key)) {
    const v = cache.get(key);
    return v === null || v === undefined ? fallback : v;
  }
  return fallback !== undefined ? fallback : DEFAULT_SETTINGS[key];
}

function getInt(key, fallback) {
  const n = parseInt(get(key), 10);
  return Number.isFinite(n) ? n : fallback;
}

function getBool(key) {
  return String(get(key)) === '1';
}

async function set(key, value) {
  await query(
    'INSERT INTO settings (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)',
    [key, value === null || value === undefined ? '' : String(value)]
  );
  cache.set(key, String(value));
}

function allSettings() {
  const out = {};
  for (const [k, v] of cache.entries()) out[k] = v;
  return out;
}

// acl_covers_registry is gone. copy its networks to registry_acl first, or the upgrade
// ships an OPEN registry. only when acl_enabled was on, or we break every build
async function migrateCoversRegistry() {
  const row = await one("SELECT v FROM settings WHERE k = 'acl_covers_registry'");
  if (!row) return;

  const wasCovering = String(row.v) === '1';
  const aclOn = String((await one("SELECT v FROM settings WHERE k = 'acl_enabled'") || {}).v) === '1';

  if (wasCovering && aclOn) {
    await query(
      `INSERT IGNORE INTO registry_acl (cidr, label, enabled, created_by)
       SELECT cidr, LEFT(CONCAT('moved off the portal list. ', COALESCE(label, '')), 128), enabled, created_by
         FROM ip_acl`
    );
    await query(
      "INSERT INTO settings (k, v) VALUES ('registry_acl_enabled', '1') ON DUPLICATE KEY UPDATE v = '1'"
    );
    const moved = await one('SELECT COUNT(*) AS n FROM registry_acl');
    log.warn(
      `acl_covers_registry is gone. Its ${moved.n} network(s) now live on the client allow list, ` +
      'which is switched on. Check them under Whitelists, Whitelist Clients.'
    );
  }

  await query("DELETE FROM settings WHERE k = 'acl_covers_registry'");
}

async function seed() {
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    await query('INSERT IGNORE INTO settings (k, v) VALUES (?, ?)', [k, v]);
  }
  await migrateCoversRegistry();
  await loadSettings(true);

  const row = await one('SELECT COUNT(*) AS n FROM users');
  if (row.n === 0) {
    // no password given, or the old "changeme" default, gets a random one.
    // a known default lets whoever reaches the portal first claim the box
    let password = config.adminPassword;
    const generated = !password || password === 'changeme';
    if (generated) password = temporaryPassword();
    const hash = await bcrypt.hash(password, 12);
    // generated or short = one use only, the portal asks for a new one
    const weak = generated || password.length < 12 ? 1 : 0;
    await query(
      `INSERT INTO users (username, password_hash, role, must_change_password, password_changed_at)
       VALUES (?, ?, 'admin', ?, NOW())`,
      [config.adminUser, hash, weak]
    );
    log.info(`created the first admin account: ${config.adminUser}`);
    if (generated) {
      log.warn(`temporary password for ${config.adminUser}: ${password}`);
      log.warn('it works once, the portal asks for a new password at first sign in');
    } else if (weak) {
      log.info('that password is weak, the portal will make you change it at first login');
    }
  }

  //a brand new whitelist blocks everything, so seed a few harmless rules
  const rules = await one('SELECT COUNT(*) AS n FROM rules');
  if (rules.n === 0) {
    await query(
      `INSERT INTO rules (pattern, kind, note, priority, created_by) VALUES
        ('@types/*', 'allow', 'type definitions, generally safe', 0, 'system'),
        ('event-stream', 'deny', 'known bad, 2018 incident', 100, 'system'),
        ('flatmap-stream', 'deny', 'known bad, 2018 incident', 100, 'system')`
    );
    log.info('added the starter rule set');
  }
}

async function close() {
  if (pool) await pool.end();
}

// all or nothing, one connection, rolls back if work() throws
async function transaction(work) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await work(async (sql, params) => {
      const [rows] = await conn.query(sql, params);
      return rows;
    });
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback().catch(() => {});
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = {
  connect,
  transaction,
  loadSchema,
  query,
  one,
  seed,
  close,
  settings: {
    load: loadSettings, poll: pollSettings, get, getInt, getBool, set, all: allSettings,
    defaults: DEFAULT_SETTINGS, secrets: SECRET_SETTINGS
  },
  get pool() {
    return pool;
  }
};
