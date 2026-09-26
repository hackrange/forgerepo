// Registry mode: normal, degraded or lockdown. the switch for a bad week in an ecosystem.
// Author: Tim Rice
// degraded: nothing new is fetched by name, what this box already holds can still refresh.
// lockdown: nothing is fetched from upstream at all, metadata only offers what is cached, and a file with any
// quarantine hold is refused, permissive mode or not. every change is audited and goes to the admins

const db = require('../db');
const auth = require('../security/auth');
const log = require('../logger');
const { httpError } = require('../lib/errors');

const MODES = ['normal', 'degraded', 'lockdown'];
const MAX_REASON = 500;

function current() {
  const m = db.settings.get('registry_mode');
  return MODES.includes(m) ? m : 'normal';
}

const lockdown = () => current() === 'lockdown';
// degraded or worse: no package this box has never held gets fetched
const noNewNames = () => current() !== 'normal';

// why upstream can't be asked, for the messages that used to only know about upstream_enabled
function offlineReason() {
  return lockdown() ? 'the registry is in lockdown' : 'the upstream registry is switched off';
}

function newName(what) {
  return httpError(503, lockdown()
    ? `the registry is in lockdown, only packages already cached are served, and ${what} is not one of them`
    : `the registry is in degraded mode, nothing new is fetched from upstream, and ${what} has never been fetched here`);
}

function describe() {
  return {
    mode: current(),
    reason: db.settings.get('registry_mode_reason') || '',
    by: db.settings.get('registry_mode_by') || '',
    at: db.settings.get('registry_mode_at') || ''
  };
}

async function tellAdmins(was, now, user, reason) {
  const mail = require('../integrations/mail');
  let who;
  try {
    who = await require('../integrations/mail/malware-alerts').recipients();
  } catch (err) {
    return;
  }
  const name = db.settings.get('registry_name') || 'ForgeRepo';
  const url = db.settings.get('public_url');
  const what = {
    normal: 'Everything is back to normal: packages are fetched from upstream as usual.',
    degraded: 'Nothing new is fetched from upstream by name. Packages already on the registry still refresh and install.',
    lockdown: 'Nothing is fetched from upstream at all. Only files already cached are offered and served, and any file with a quarantine hold is refused.'
  }[now];
  const text = [`${user || 'someone'} changed the registry from ${was} to ${now}.`, '', `Reason: ${reason}`, '', what, url ? `\n${url}/_admin/#dash` : ''].join('\n');
  for (const u of who) {
    await mail.send({ to: u.email, subject: `[${name}] Registry mode: ${now}`, text, kind: 'registry-mode' })
      .catch((err) => log.warn(`could not mail ${u.username} about the registry mode`, err.message));
  }
}

// canLower says whether this person may go back toward normal. raising is for anyone who can kill a package
async function set(next, { reason, user, userId, ip, canLower }) {
  if (!MODES.includes(next)) throw httpError(400, 'the mode is normal, degraded or lockdown');
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  const why = String(reason || '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim().slice(0, MAX_REASON);
  if (!why) throw httpError(400, 'say why, it goes to the admins and into the audit trail');
  const was = current();
  if (next === was) throw httpError(409, `the registry is already in ${was} mode`);
  if (MODES.indexOf(next) < MODES.indexOf(was) && !canLower) {
    throw httpError(403, `only an admin can take the registry from ${was} back to ${next}`);
  }
  const who = user ? String(user).slice(0, 64) : '';
  await db.settings.set('registry_mode_reason', why);
  await db.settings.set('registry_mode_by', who);
  await db.settings.set('registry_mode_at', new Date().toISOString().slice(0, 19).replace('T', ' '));
  await db.settings.set('registry_mode', next);
  const line = `registry mode: ${was} -> ${next} by ${who}: ${why}`;
  if (next === 'normal') log.warn(line);
  else log.error(line);
  await auth.audit(userId || null, who, ip, 'registry.mode', `${was} -> ${next}`, why, { before: { mode: was }, after: { mode: next } });
  tellAdmins(was, next, who, why).catch(() => {});
  return describe();
}

module.exports = { MODES, current, lockdown, noNewNames, offlineReason, newName, describe, set };
