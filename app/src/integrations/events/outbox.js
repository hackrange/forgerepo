// The outbox worker: claims what is due, delivers it, backs off on failure, and a test send that skips the queue.
// Author: Tim Rice
// a slow or dead SIEM never holds up an install, it only ever slows its own retries

const crypto = require('crypto');
const log = require('../../logger');
const outbox = require('../../db/repositories/event-outbox');
const integrationsRepo = require('../../db/repositories/integrations');
const { clip, build } = require('./build');
const { deliver } = require('./transports');

const MAX_ATTEMPTS = 10;
const BATCH = 50;
const TICK_MS = 5000;

const backoffSeconds = (attempts) => Math.min(3600, 30 * 2 ** Math.max(0, attempts - 1));

async function note(id, ok, message) {
  await integrationsRepo.noteAttempt(id, { status: ok ? 'ok' : 'failed', error: ok ? null : clip(message, 255) });
}

let ticking = false;
async function tick() {
  if (ticking) return;
  ticking = true;
  const claim = crypto.randomBytes(16).toString('hex');
  try {
    // claimed by one node at a time, a claim older than five minutes is fair game again
    await outbox.claim(claim, BATCH);
    const rows = await outbox.claimed(claim);
    const broken = new Set();
    for (const r of rows) {
      if (!Number(r.enabled) || broken.has(r.integration_id)) {
        await outbox.deferClaim(r.id);
        continue;
      }
      try {
        const status = await deliver(r, r.payload);
        await outbox.delivered(r.id, status || null);
        await note(r.integration_id, true);
      } catch (err) {
        const message = err.delivery ? err.message : 'the event could not be sent';
        if (!err.delivery) log.error('event delivery failed', err.message);
        const attempts = Number(r.attempts) + 1;
        await outbox.failedAttempt(r.id, { attempts, error: clip(message, 255), maxAttempts: MAX_ATTEMPTS, retryIn: backoffSeconds(attempts) });
        await note(r.integration_id, false, message);
        // the rest for that integration waits for its own retry instead of hammering a dead SIEM
        broken.add(r.integration_id);
      }
    }
  } catch (err) {
    log.error('event worker failed', err.message);
  } finally {
    ticking = false;
  }
}

async function sweep() {
  await outbox.sweepSettled();
}

// a test send, straight away, bypassing the outbox. the caller sees whether it worked, never what came back
async function test(integration) {
  const event = build('integration.test', { reason: 'a test event from the ForgeRepo portal', action: 'test' });
  event.event_type = 'integration.test';
  try {
    await deliver(integration, event);
    await note(integration.id, true);
    return { ok: true };
  } catch (err) {
    const message = err.delivery ? err.message : 'the test event could not be sent';
    await note(integration.id, false, message);
    return { ok: false, error: message };
  }
}

module.exports = { MAX_ATTEMPTS, TICK_MS, backoffSeconds, tick, sweep, test };
