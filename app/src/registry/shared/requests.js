// Blocked installs turning into approval requests, for every ecosystem.
// Author: Tim Rice

const db = require('../../db');
const auth = require('../../security/auth');
const requests = require('../../db/repositories/requests');
const log = require('../../logger');

// blocked? open a request so approvers see it.
// source 'learning' = audit mode served it anyway, and the request collects the exact versions pulled
// options.looksLikeClient: the caller's guess, scanner junk stays out of the queue
async function openRequest(req, name, version, reason, options = {}) {
  const learning = options.source === 'learning';
  // learning mode is there to fill the queue, so it doesn't wait on auto_request
  if (!learning && !db.settings.getBool('auto_request')) return;
  const ecosystem = options.ecosystem || 'npm';
  if (!options.looksLikeClient) return;
  // the pin approving it would write: 4.17.21 for npm, ==2.32.3 for PyPI
  const pin = version ? (ecosystem === 'pypi' ? `==${String(version).replace(/^==/, '')}` : String(version)) : null;
  try {
    const who = (req.npmIdentity && req.npmIdentity.username) || null;
    const existing = await requests.pendingFromRegistry(ecosystem, name, learning);
    const token = (req.npmIdentity && req.npmIdentity.name) || null;
    if (existing) {
      // repeats fold in. fill in who, if the first hit was anonymous. learning adds the version it saw
      let grown = null;
      if (learning && pin) {
        const pins = String(existing.version_range || '').split('||').map((s) => s.trim()).filter(Boolean);
        const next = [...pins, pin].join(' || ');
        if (!pins.includes(pin) && next.length <= 128) grown = next;
      }
      await requests.foldIn(existing.id, { range: grown, token, userId: (req.npmIdentity && req.npmIdentity.userId) || null, who });
      return;
    }
    await requests.createFromRegistry({
      ecosystem,
      name,
      range: learning ? pin : (version || null),
      userId: (req.npmIdentity && req.npmIdentity.userId) || null,
      source: learning ? 'learning' : 'blocked-install',
      who,
      token,
      ip: auth.clientIp(req),
      reason: (learning ? `learning mode, pulled without an allow rule: ${reason}` : `install was blocked: ${reason}`).slice(0, 1000)
    });
    require('../../services/auto-approve').nudge();
    const events = require('../../integrations/events');
    events.emit('package.requested', {
      ...events.who(req), ecosystem, package: name, version, reason, action: learning ? 'queued by learning mode' : 'queued after a blocked install'
    });
  } catch (err) {
    log.error('could not open a request for', name, err.message);
  }
}

module.exports = { openRequest };
