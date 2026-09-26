// What each writable setting may be. one case per key, checked before anything is saved.
// Author: Tim Rice

const db = require('../db');
const ipacl = require('../security/network/ipacl');
const ghmeta = require('../security/network/github-ranges');
const mail = require('../integrations/mail');
const sso = require('../security/sso');
const allowlists = require('../db/repositories/allowlists');
const storageValues = require('./storage-values');
const { fail } = require('../lib/errors');
const { str, required, boolFlag, intIn, oneOf } = require('../lib/validate');

const WRITABLE = new Set([
  'policy_mode',
  'audit_mode',
  'quarantine_mode',
  'push_secret_scan',
  'safe_resolution',
  'safe_resolution_severity',
  'safe_resolution_kev',
  'safe_resolution_epss',
  'malware_scanning',
  'malware_scanners',
  'malware_on_malicious',
  'malware_on_suspicious',
  'malware_scan_before_serve',
  'malicious_auto_kill',
  'malware_hash_blocklist',
  'malware_clamd_host',
  'malware_clamd_port',
  'malware_rest_url',
  'malware_rest_token',
  'email_malware_alerts',
  'email_malware_daily',
  'cooloff_hours',
  'waiver_max_days',
  'typosquat_mode',
  'typosquat_protected',
  'typosquat_exempt',
  'cooloff_exempt',
  'cooloff_unknown',
  'license_enforcement',
  'license_allowed',
  'license_review',
  'license_blocked',
  'license_unlisted',
  'license_unknown',
  'require_auth',
  // upstream settings moved to their own table
  'upstream_enabled',
  'pypi_enabled',
  'oci_enabled',
  'nuget_enabled',
  'maven_enabled',
  'rubygems_enabled',
  'cocoapods_enabled',
  'swift_enabled',
  'composer_enabled',
  'rpm_enabled',
  'apt_enabled',
  'oci_scan',
  'oci_scan_max_gb',
  'oci_scan_before_serve',
  'oci_scan_ignore_unfixed',
  'packument_ttl',
  'stale_ok_seconds',
  'cache_tarballs',
  'cache_latest_on_allow',
  'auto_request',
  'approve_clean_dependencies',
  'lifecycle_enforce',
  'show_help_url',
  'log_retention_days',
  'consumption_retention_days',
  'provenance_invalid',
  'provenance_downgrade',
  'install_script_check',
  'manifest_confusion',
  'takeover_signals',
  'dashboard_cache_minutes',
  'public_url',
  'registry_name',
  'min_password_length',
  'max_login_attempts',
  'lockout_minutes',
  'session_idle_minutes',
  'acl_enabled',
  'registry_acl_enabled',
  'registry_acl_token_ok',
  'registry_acl_github',
  'registry_acl_github_sections',
  'registry_acl_github_hours',
  'npm_clients_only',
  'cve_scan_hours',
  'intel_feeds_enabled',
  'intel_feed_hours',
  'audit_answer',
  'audit_warn_install',
  'audit_log_downloads',
  'breakglass_enabled',
  'breakglass_grant_minutes',
  'email_enabled',
  'email_transport',
  'email_from',
  'email_from_name',
  'smtp_host',
  'smtp_port',
  'smtp_security',
  'smtp_user',
  'smtp_password',
  'smtp_allow_self_signed',
  'graph_tenant',
  'graph_client_id',
  'graph_client_secret',
  'graph_sender',
  'sso_enabled',
  'sso_mode',
  'sso_button_label',
  'sso_auto_create',
  'sso_default_role',
  'oidc_issuer',
  'oidc_client_id',
  'oidc_client_secret',
  'oidc_scopes',
  'oidc_redirect_url',
  'sso_role_groups',
  'sso_role_sync',
  'sso_require_role_group',
  'oidc_groups_claim',
  ...storageValues.KEYS
]);

// a secret sent back as stars: leave the saved one alone
const UNCHANGED = Symbol('unchanged');

// package names or patterns, one per line or comma, # comments
function packageList(value, maxChars, maxEntries, tooLong, tooMany) {
  const text = String(value || '').replace(/\r\n?/g, '\n');
  if (text.length > maxChars) fail(400, tooLong);
  const entries = text.split(/[\n,]+/).map((s) => s.replace(/#.*$/, '').trim()).filter(Boolean);
  if (entries.length > maxEntries) fail(400, tooMany);
  for (const e of entries) {
    if (!/^[@A-Za-z0-9._*/~-]{1,214}$/.test(e)) fail(400, `"${e.slice(0, 60)}" is not a package name or a pattern with *`);
  }
  return text;
}

// ctx: { incoming, actor, githubAfter } - githubAfter gets set to 'sync' or 'clear' here, acted on after the save
async function checkValue(key, rawValue, ctx) {
  let value = rawValue;
  const { incoming, actor } = ctx;

  switch (key) {
    case 'policy_mode':
      value = oneOf(value, ['whitelist', 'blacklist'], null);
      if (!value) fail(400, 'the mode has to be whitelist or blacklist');
      break;
    case 'quarantine_mode':
      value = oneOf(value, ['permissive', 'strict'], null);
      if (!value) fail(400, 'quarantine has to be permissive or strict');
      break;
    case 'push_secret_scan':
      value = oneOf(value, ['hold', 'warn', 'off'], null);
      if (!value) fail(400, 'secrets in a push are held, warned about or off');
      break;
    case 'safe_resolution':
    case 'safe_resolution_kev':
      value = boolFlag(value, false) ? '1' : '0';
      break;
    case 'safe_resolution_epss': {
      const raw = String(value === undefined || value === null ? '' : value).trim().replace(/%$/, '');
      if (!raw) {
        value = '';
        break;
      }
      let n = Number(raw);
      // 10 and 10% both mean a tenth, 0.1 means it too
      if (/%$/.test(String(value).trim()) || n > 1) n /= 100;
      if (!Number.isFinite(n) || n <= 0 || n > 1) fail(400, 'the EPSS bar is a score from 0.001 to 1, or a percentage like 10%, or empty for off');
      value = String(Math.round(n * 10000) / 10000);
      break;
    }
    case 'safe_resolution_severity':
      value = oneOf(value, ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'], null);
      if (!value) fail(400, 'the severity has to be CRITICAL, HIGH, MODERATE or LOW');
      break;
    case 'malware_scanning':
    case 'malicious_auto_kill':
    case 'malware_scan_before_serve':
    case 'email_malware_alerts':
    case 'email_malware_daily':
      value = boolFlag(value, false) ? '1' : '0';
      break;
    case 'malware_scanners': {
      const known = new Set(['blocklist', 'clamav', 'rest', 'osv', 'secrets']);
      //a page from before eicar went away still sends it, just drop it
      const picked = [...new Set(String(value || '').split(',').map((s) => s.trim()).filter((s) => s && s !== 'eicar'))];
      for (const s of picked) if (!known.has(s)) fail(400, `"${s.slice(0, 40)}" is not a scanner this box knows about`);
      value = picked.join(',');
      break;
    }
    case 'malware_on_malicious':
      value = oneOf(value, ['reject', 'hold', 'warn'], null);
      if (!value) fail(400, 'a malicious verdict has to reject, hold or warn');
      break;
    case 'malware_on_suspicious':
      value = oneOf(value, ['hold', 'warn', 'ignore'], null);
      if (!value) fail(400, 'a suspicious verdict has to hold, warn or ignore');
      break;
    case 'malware_hash_blocklist':
      value = String(value || '');
      if (value.length > 200000) fail(400, 'the blocklist is too long, 200KB at most');
      break;
    case 'malware_clamd_host':
      value = String(value || '').trim();
      if (value && !/^[A-Za-z0-9.-]{1,253}$|^\[?[0-9A-Fa-f:.]{2,45}\]?$/.test(value)) fail(400, 'the clamd host has to be a hostname or an address');
      break;
    case 'malware_clamd_port': {
      const port = parseInt(value, 10);
      if (!(port > 0 && port < 65536)) fail(400, 'the clamd port has to be between 1 and 65535');
      value = String(port);
      break;
    }
    case 'malware_rest_url': {
      value = String(value || '').trim();
      if (value) {
        let u = null;
        try {
          u = new URL(value);
        } catch (err) {
          u = null;
        }
        if (!u) fail(400, 'the scanner url is not a url');
        if (u.protocol !== 'http:' && u.protocol !== 'https:') fail(400, 'the scanner url has to be http:// or https://');
        if (u.username || u.password) fail(400, 'put the credential in the token field, not in the url');
      }
      break;
    }
    case 'license_enforcement':
      value = oneOf(value, ['off', 'warn', 'enforce'], null);
      if (!value) fail(400, 'license enforcement has to be off, warn or enforce');
      break;
    case 'waiver_max_days': {
      const n = Number(String(value).trim());
      if (!Number.isInteger(n) || n < 1 || n > 365) fail(400, 'the longest waiver is a whole number of days, 1 to 365');
      value = String(n);
      break;
    }
    case 'typosquat_mode':
      value = oneOf(value, ['off', 'warn', 'block'], null);
      if (!value) fail(400, 'typosquat checks have to be off, warn or block');
      break;
    case 'typosquat_protected':
    case 'typosquat_exempt':
      value = packageList(value, 40000, 2000, 'that list is too long', 'that list can have 2000 entries at most');
      break;
    case 'cooloff_hours': {
      const n = Number(String(value).trim());
      if (!Number.isInteger(n) || n < 0 || n > 8760) fail(400, 'cooling off is a whole number of hours, 0 to 8760');
      value = String(n);
      break;
    }
    case 'cooloff_unknown':
      value = oneOf(value, ['allow', 'hold'], null);
      if (!value) fail(400, 'a version with no publish time has to be allow or hold');
      break;
    case 'cooloff_exempt':
      value = packageList(value, 20000, 500, 'that exempt list is too long', 'the exempt list can have 500 entries at most');
      break;
    case 'license_unlisted':
    case 'license_unknown':
      value = oneOf(value, ['allowed', 'review', 'blocked'], null);
      if (!value) fail(400, 'that has to be allowed, review or blocked');
      break;
    case 'license_allowed':
    case 'license_review':
    case 'license_blocked': {
      value = String(value || '').replace(/\r\n?/g, '\n');
      if (value.length > 20000) fail(400, 'that license list is too long');
      const entries = value.split(/[\n,]+/).map((s) => s.replace(/#.*$/, '').trim()).filter(Boolean);
      if (entries.length > 500) fail(400, 'a license list can have 500 entries at most');
      for (const e of entries) {
        if (!/^[A-Za-z0-9.*+:-]{1,100}( WITH [A-Za-z0-9.*+:-]{1,100})?$/.test(e)) {
          fail(400, `"${e.slice(0, 60)}" is not a license id, use SPDX ids like MIT or GPL-*`);
        }
      }
      break;
    }
    case 'public_url':
      if (String(value || '').trim()) {
        const u = String(value).trim();
        if (!/^https?:\/\//i.test(u)) fail(400, 'the public url has to start with http:// or https://');
        value = u.replace(/\/+$/, '');
      } else {
        value = '';
      }
      break;
    case 'acl_enabled':
      value = boolFlag(value, false) ? '1' : '0';
      if (value === '1') {
        // on + empty list = everyone locked out, including you
        if (!(await allowlists.enabledCount('portal'))) fail(400, 'add at least one network to the allow list before switching it on');
        const mine = await ipacl.ipAllowed(actor.ip);
        if (!mine) fail(400, 'your own address is not on that list, add it first or you will lock yourself out');
      }
      break;
    case 'registry_acl_enabled':
      value = boolFlag(value, false) ? '1' : '0';
      // on + empty list protects nothing, add a network first
      if (value === '1') {
        const counted = await ipacl.registryNetworkCount();
        if (!counted.total) {
          fail(400, 'add at least one client network, or fetch the GitHub ranges, before switching the filter on');
        }
      }
      break;
    case 'registry_acl_token_ok':
      value = boolFlag(value, false) ? '1' : '0';
      break;
    case 'registry_acl_github':
      value = boolFlag(value, false) ? '1' : '0';
      // runs after the save, github having a slow day shouldn't hang it
      if (value === '1') {
        ctx.githubAfter = 'sync';
      } else if (db.settings.getBool('registry_acl_github')) {
        // off empties the fetched ranges, same as removing the last network
        if (db.settings.getBool('registry_acl_enabled')) {
          const counted = await ipacl.registryNetworkCount();
          if (!counted.typed) {
            fail(400, 'the GitHub ranges are the only thing on the client list, turn the filter off first');
          }
        }
        //ranges go too, nobody's keeping them updated
        ctx.githubAfter = 'clear';
      }
      break;
    case 'registry_acl_github_sections': {
      const picked = String(value || '')
        .split(',')
        .map((part) => part.trim())
        .filter(Boolean);
      for (const part of picked) {
        if (!ghmeta.KNOWN.has(part)) fail(400, `"${part}" is not a part of the github list we know about`);
      }
      if (!picked.length) fail(400, 'pick at least one part of the github list');
      value = picked.join(',');
      if (value !== db.settings.get('registry_acl_github_sections') && db.settings.getBool('registry_acl_github')) {
        ctx.githubAfter = 'sync';
      }
      break;
    }
    case 'registry_acl_github_hours':
      value = String(intIn(value, 0, 168, 24));
      break;
    case 'audit_mode':
    case 'require_auth':
    case 'cache_tarballs':
    case 'cache_latest_on_allow':
    case 'upstream_enabled':
    case 'pypi_enabled':
    case 'oci_enabled':
    case 'nuget_enabled':
    case 'maven_enabled':
    case 'rubygems_enabled':
    case 'cocoapods_enabled':
    case 'swift_enabled':
    case 'composer_enabled':
    case 'rpm_enabled':
    case 'apt_enabled':
    case 'oci_scan':
    case 'oci_scan_before_serve':
    case 'oci_scan_ignore_unfixed':
    case 'auto_request':
    case 'approve_clean_dependencies':
    case 'lifecycle_enforce':
    case 'intel_feeds_enabled':
    case 'breakglass_enabled':
    case 'audit_answer':
    case 'audit_warn_install':
    case 'audit_log_downloads':
    case 'npm_clients_only':
    case 'smtp_allow_self_signed':
      value = boolFlag(value, false) ? '1' : '0';
      break;
    case 'email_enabled':
      value = boolFlag(value, false) ? '1' : '0';
      // half configured = digest silently failing every hour. complain now
      if (value === '1') {
        const problem = mail.unusable();
        if (problem) fail(400, `email cannot be switched on yet: ${problem}`);
      }
      break;
    case 'email_transport':
      value = oneOf(value, ['smtp', 'graph'], null);
      if (!value) fail(400, 'mail goes out over smtp or graph');
      break;
    case 'email_from':
    case 'graph_sender':
      value = String(value || '').trim();
      if (value && !mail.validAddress(value)) fail(400, `"${value}" is not an email address`);
      break;
    case 'smtp_security':
      value = oneOf(value, ['starttls', 'tls', 'none'], null);
      if (!value) fail(400, 'smtp security is starttls, tls or none');
      if (value === 'none') {
        // every send would fail on the password check anyway, better to hear it now than at digest time
        const pick = (k) => (incoming[k] !== undefined ? String(incoming[k]) : String(db.settings.get(k) || ''));
        const on = boolFlag(pick('email_enabled'), false) && pick('email_transport') !== 'graph';
        if (on && pick('smtp_user').trim()) {
          fail(400, 'a username and password cannot be sent with encryption set to none, pick starttls (usually port 587) or tls (usually 465)');
        }
      }
      break;
    case 'smtp_port':
      value = String(intIn(value, 1, 65535, 587));
      break;
    case 'sso_enabled':
      value = boolFlag(value, false) ? '1' : '0';
      if (value === '1') {
        const problem = sso.unusable();
        if (problem) fail(400, `single sign on cannot be switched on yet: ${problem}`);
      }
      break;
    case 'sso_auto_create':
    case 'sso_role_sync':
    case 'sso_require_role_group':
      value = boolFlag(value, false) ? '1' : '0';
      break;
    case 'oidc_groups_claim':
      value = String(value || '').trim() || 'groups';
      break;
    case 'sso_role_groups': {
      value = String(value || '').trim();
      // unparseable line looks granted when it definitely isn't, so say so
      const bad = sso.roleGroupProblems(value);
      if (bad.length) {
        fail(400, `each line is a role and the groups that grant it, like "admin = okta_npm_admins". This does not read as one: ${bad[0].slice(0, 80)}`);
      }
      break;
    }
    case 'sso_mode':
      value = oneOf(value, ['both', 'sso_only'], null);
      if (!value) fail(400, 'the mode is both or sso_only');
      break;
    case 'sso_default_role':
      value = oneOf(value, ['viewer', 'developer', 'publisher', 'approver'], null);
      // admin left out on purpose
      if (!value) fail(400, 'new accounts can come in as viewer, developer, publisher or approver');
      break;
    case 'oidc_issuer':
      value = String(value || '').trim().replace(/\/+$/, '');
      if (value && !/^https:\/\/[^\s]+$/i.test(value)) fail(400, 'the identity provider address has to be an https url');
      break;
    case 'oidc_redirect_url':
      value = String(value || '').trim();
      if (value && !/^https?:\/\/[^\s]+$/i.test(value)) fail(400, 'the redirect address has to be a url');
      break;
    case 'smtp_password':
    case 'graph_client_secret':
    case 'oidc_client_secret':
    case 'malware_rest_token':
    case 's3_secret_access_key':
    case 'az_account_key':
      // stars back mean leave it alone, NOT 'my password is ********'
      value = String(value == null ? '' : value);
      if (value === '********') return UNCHANGED;
      value = str(value, 500, key) || '';
      break;
    case 'packument_ttl':
      value = String(intIn(value, 0, 86400, 300));
      break;
    case 'oci_scan_max_gb':
      value = String(intIn(value, 1, 256, 16));
      break;
    // 0 = off, a week max
    case 'cve_scan_hours':
      value = String(intIn(value, 0, 168, 24));
      break;
    case 'intel_feed_hours':
      value = String(intIn(value, 1, 168, 24));
      break;
    case 'stale_ok_seconds':
      value = String(intIn(value, 0, 31536000, 604800));
      break;
    case 'log_retention_days':
      value = String(intIn(value, 0, 3650, 30));
      break;
    case 'consumption_retention_days':
      value = String(intIn(value, 0, 3650, 365));
      break;
    case 'provenance_invalid':
      if (!['warn', 'hold'].includes(String(value))) fail(400, 'invalid provenance is either warn or hold');
      value = String(value);
      break;
    case 'provenance_downgrade':
      if (!['hold', 'warn', 'off'].includes(String(value))) fail(400, 'a provenance downgrade is held, warned about or off');
      value = String(value);
      break;
    case 'install_script_check':
      if (!['warn', 'hold', 'off'].includes(String(value))) fail(400, 'new install-time code is warned about, held or off');
      value = String(value);
      break;
    case 'manifest_confusion':
      if (!['hold', 'warn', 'off'].includes(String(value))) fail(400, 'manifest confusion is held, warned about or off');
      value = String(value);
      break;
    case 'takeover_signals':
      if (!['warn', 'hold', 'off'].includes(String(value))) fail(400, 'takeover signals are warned about, held or off');
      value = String(value);
      break;
    case 'dashboard_cache_minutes':
      value = String(intIn(value, 0, 1440, 30));
      break;
    case 'min_password_length':
      value = String(intIn(value, 8, 128, 12));
      break;
    case 'max_login_attempts':
      value = String(intIn(value, 3, 50, 5));
      break;
    case 'lockout_minutes':
      value = String(intIn(value, 1, 1440, 15));
      break;
    case 'session_idle_minutes':
      value = String(intIn(value, 0, 10080, 60));
      break;
    case 'breakglass_grant_minutes':
      value = String(intIn(value, 5, 1440, 60));
      break;
    case 'registry_name':
      value = required(value, 64, 'registry name');
      break;
    // storage has its own checks, kept next to the rest of storage
    case 'storage_backend':
    case 's3_endpoint':
    case 's3_region':
    case 's3_bucket':
    case 's3_prefix':
    case 's3_path_style':
    case 's3_access_key_id':
    case 'az_endpoint':
    case 'az_account':
    case 'az_container':
    case 'az_prefix':
    case 'storage_cache_mb':
      value = await storageValues.check(key, value);
      break;
    default:
      value = str(value, 1000, key) || '';
  }
  return value;
}

// a stored secret belongs to the place it was set up for. if that place changes and the secret is not typed
// again in the same save, the old one would be handed to the new place, so the save is refused instead
const SECRET_DESTINATIONS = [
  { secret: 'smtp_password', keys: ['smtp_host', 'smtp_port'], message: 'the SMTP server changed, so enter the password again (or empty it to drop it)' },
  { secret: 'oidc_client_secret', keys: ['oidc_issuer'], message: 'the identity provider changed, so enter the client secret again (or empty it to drop it)' },
  { secret: 'malware_rest_token', keys: ['malware_rest_url'], message: 'the scanner url changed, so enter the token again (or empty it to drop it)' }
];

// runs before anything is written, so a refused save leaves nothing half done
// skip = an import, which can't send secrets at all. there the moved address is left as this box has it
// and the rest goes in, instead of the whole import failing. returns what was left alone
async function checkSecretDestinations(incoming, { skip = false } = {}) {
  const ctx = { incoming, actor: null, githubAfter: null };
  const kept = [];
  for (const pair of SECRET_DESTINATIONS) {
    if (!db.settings.get(pair.secret)) continue;
    const sent = incoming[pair.secret];
    if (sent !== undefined && (await checkValue(pair.secret, sent, ctx)) !== UNCHANGED) continue;
    let moved = false;
    for (const key of pair.keys) {
      if (incoming[key] === undefined) continue;
      const value = await checkValue(key, incoming[key], ctx);
      if (value === UNCHANGED) continue;
      const was = db.settings.get(key);
      if (String(was == null ? '' : was) !== String(value)) moved = true;
    }
    if (!moved) continue;
    if (!skip) fail(400, pair.message);
    // host and port together, never half moved
    for (const key of pair.keys) delete incoming[key];
    kept.push({ keys: pair.keys, secret: pair.secret });
  }
  return kept;
}

module.exports = { WRITABLE, UNCHANGED, checkValue, checkSecretDestinations };
