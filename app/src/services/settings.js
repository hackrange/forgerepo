// Settings from the portal: reading them without secrets, and saving a batch of changes.
// Author: Tim Rice

const db = require('../db');
const ipacl = require('../security/network/ipacl');
const ghmeta = require('../security/network/github-ranges');
const mail = require('../integrations/mail');
const sso = require('../security/sso');
const log = require('../logger');
const config = require('../config');
const ecosystems = require('../ecosystems');
const { audit } = require('../lib/actor');
const { WRITABLE, UNCHANGED, checkValue, checkSecretDestinations } = require('./setting-values');

function view(canWrite) {
  const out = {};
  for (const [k, v] of Object.entries(db.settings.all())) {
    // credentials never go back out, we only say whether one is set
    out[k] = db.settings.secrets.has(k) ? (v ? '********' : '') : v;
  }
  return {
    settings: out,
    writable: canWrite ? [...WRITABLE] : [],
    defaults: db.settings.defaults,
    // whatever's stopping mail, shown on the page
    emailProblem: mail.unusable(),
    ssoProblem: sso.unusable(),
    // redirect address for the provider, must match EXACTLY
    ssoRedirect: sso.redirectUri(),
    // bucket keys from the environment win, the page says so instead of showing an empty field
    storageEnv: {
      s3AccessKeyId: !!config.storage.s3AccessKeyId, s3SecretAccessKey: !!config.storage.s3SecretAccessKey, azureAccountKey: !!config.storage.azureAccountKey
    },
    // every type this box knows and the setting that switches it on. npm has none, it's always on
    ecosystems: ecosystems.ALL.map((e) => ({ id: e.id, name: e.name, label: e.label, setting: e.setting }))
  };
}

// unknown keys are skipped, a bad value stops the rest. returns what changed
async function save(actor, incoming, { skipMovedSecrets = false } = {}) {
  const changed = [];
  const ctx = { incoming, actor, githubAfter: null };
  const keptDestinations = await checkSecretDestinations(incoming, { skip: skipMovedSecrets });

  // switches go last, they get checked against the rest of the section
  const last = new Set(['email_enabled', 'sso_enabled', 'storage_backend']);
  const entries = Object.entries(incoming)
    .sort((a, b) => (last.has(a[0]) ? 1 : 0) - (last.has(b[0]) ? 1 : 0));

  const before = {};
  const after = {};
  // a secret is only ever recorded as set or not
  const shown = (key, v) => (db.settings.secrets.has(key) ? (v ? '********' : '') : v);
  for (const [key, rawValue] of entries) {
    if (!WRITABLE.has(key)) continue;
    const value = await checkValue(key, rawValue, ctx);
    if (value === UNCHANGED) continue;
    const was = db.settings.get(key);
    // the page sends every field. the same value again is not a change, and not an audit row
    if (was !== undefined && was !== null && String(was) === String(value)) continue;
    await db.settings.set(key, value);
    changed.push(key);
    before[key] = shown(key, was);
    after[key] = shown(key, value);
  }

  await db.settings.load(true);
  // cached discovery doc + keys may be from the old provider
  if (changed.some((k) => k.startsWith('oidc_') || k.startsWith('sso_'))) sso.invalidate();
  ipacl.invalidateFeeds();
  if (ctx.githubAfter === 'clear') {
    await ghmeta.clear();
  } else if (ctx.githubAfter === 'sync') {
    ghmeta.sync(actor.name).catch((err) => log.error('the github fetch failed', err.message));
  }
  if (changed.length) await audit(actor, 'settings.update', changed.join(','), null, { before, after });
  if (changed.some((k) => k.startsWith('license_') || k === 'audit_mode')) require('../policy/licenses').reevaluate();
  if (changed.some((k) => k.startsWith('typosquat_'))) require('../policy/typosquat').invalidate();
  return { changed, fetchingGithub: ctx.githubAfter === 'sync', keptDestinations };
}

module.exports = { view, save };
