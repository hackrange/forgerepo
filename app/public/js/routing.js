// ForgeRepo portal: routing.
// Author: Tim Rice

import { state } from './state.js';
import { can, setTitle } from './ui.js';
import { api } from './api.js';
import { renderLogin, renderUnreachable, showLogin } from './login.js';
import { NAV, show, stopImpersonationTimer } from './frame.js';
import { viewDash } from './overview.js';
import { viewRules } from './rules.js';
import { viewRequests } from './requests.js';
import { viewPackages } from './packages.js';
import { viewArtifacts } from './artifacts.js';
import { viewUtilization } from './utilization.js';
import { viewIntegrations } from './integrations.js';
import { viewConsumers } from './consumers.js';
import { viewDryrun } from './dry-run.js';
import { viewWaivers } from './waivers.js';
import { viewKillswitch } from './kill-switch.js';
import { viewTyposquats } from './lookalikes.js';
import { viewResolutions } from './resolutions.js';
import { viewQuarantine } from './quarantine.js';
import { viewIntegrity } from './integrity.js';
import { viewCve } from './vulnerabilities.js';
import { viewTools } from './check.js';
import { viewLogs } from './traffic.js';
import { viewTransfer } from './transfer.js';
import { viewTokens } from './tokens.js';
import { viewAcl } from './access.js';
import { viewUsers } from './users.js';
import { openSettingsTab, viewSettings } from './settings.js';
import { viewAudit } from './audit.js';
import { viewAccount } from './account.js';
import { viewDocs } from './docs/index.js';

// External registries became a Settings tab. old links land on it, and back doesn't bounce
function openRegistries() {
  openSettingsTab('registries');
  window.location.replace('#settings');
}

var VIEWS = {
  dash: viewDash,
  rules: viewRules,
  requests: viewRequests,
  packages: viewPackages,
  artifacts: viewArtifacts,
  integrity: viewIntegrity,
  quarantine: viewQuarantine,
  waivers: viewWaivers,
  dryrun: viewDryrun,
  consumers: viewConsumers,
  integrations: viewIntegrations,
  killswitch: viewKillswitch,
  typosquats: viewTyposquats,
  resolutions: viewResolutions,
  utilization: viewUtilization,
  cve: viewCve,
  registries: openRegistries,
  tools: viewTools,
  logs: viewLogs,
  transfer: viewTransfer,
  tokens: viewTokens,
  acl: viewAcl,
  users: viewUsers,
  settings: viewSettings,
  audit: viewAudit,
  account: viewAccount,
  docs: viewDocs
};

function route() {
  if (!state.me) return showLogin();

  //a forced password change beats wherever they were trying to go
  if (state.me.mustChangePassword) {
    if (window.location.hash !== '#account') window.location.hash = '#account';
    return show('account', viewAccount);
  }

  // #docs/some-topic is the docs page open at a topic
  var name = (window.location.hash || '#dash').slice(1).split('?')[0].split('/')[0];
  var nav = NAV.filter(function (n) { return n.id === name; })[0];
  if (name !== 'account' && (!VIEWS[name] || (nav && !can(nav.perm)))) name = 'dash';
  if (!VIEWS[name]) name = 'dash';

  show(name, VIEWS[name]);
}

function boot(quiet) {
  return api('GET', '/me').then(function (d) {
    state.registryName = d.registryName;
    state.brandIcon = d.brandIcon;
    setTitle();
    state.impersonation = d.impersonation || null;
    if (!d.loggedIn) {
      state.sso = d.sso;
      stopImpersonationTimer();
      return renderLogin(null, d.sso);
    }
    state.sso = d.sso || state.sso;
    state.me = d.user;
    state.csrf = d.csrf;
    state.perms = d.permissions || [];
    state.policyMode = d.policyMode;
    state.auditMode = d.auditMode;
    state.registryMode = d.registryMode || 'normal';
    state.maxImportMB = d.maxImportMB || 64;
    state.version = d.version;
    state.ecosystems = d.ecosystems || [];
    state.ecosystemNames = d.ecosystemNames || {};
    if (!quiet) route();
    return d;
  }).catch(function (err) {
    renderUnreachable(err);
  });
}

export { boot, route };
