// The event outbox: security events waiting to go to webhooks, Splunk and syslog, and the claims the workers take.
// Author: Tim Rice

const db = require('../../db');

// which integrations are on, and what each wants to hear about
function enabledIntegrations() {
  return db.query('SELECT id, events FROM integrations WHERE enabled = 1');
}

// one row per integration that wants this event
function queue(integrationIds, type, body) {
  return db.query(
    `INSERT INTO event_outbox (integration_id, event_type, payload, status, attempts, next_attempt_at, created_at)
     VALUES ${integrationIds.map(() => "(?, ?, ?, 'pending', 0, NOW(), NOW())").join(', ')}`,
    integrationIds.flatMap((id) => [id, type, body])
  );
}

// claimed by one node at a time, a claim older than five minutes is fair game again
function claim(token, batch) {
  return db.query(
    `UPDATE event_outbox SET claim = ?, claimed_at = NOW()
      WHERE status = 'pending' AND next_attempt_at <= NOW() AND (claim IS NULL OR claimed_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE))
      ORDER BY id LIMIT ?`,
    [token, batch]
  );
}

// what this claim holds, with how to reach each destination. the secret stays server side
function claimed(token) {
  return db.query(
    `SELECT o.id, o.attempts, o.payload, i.id AS integration_id, i.kind, i.url, i.host, i.port, i.transport, i.format, i.secret, i.enabled
       FROM event_outbox o JOIN integrations i ON i.id = o.integration_id
      WHERE o.claim = ? ORDER BY o.id`,
    [token]
  );
}

// put back for later, the integration is off or already failing this round
function deferClaim(id) {
  return db.query('UPDATE event_outbox SET claim = NULL, next_attempt_at = DATE_ADD(NOW(), INTERVAL 30 SECOND) WHERE id = ?', [id]);
}

function delivered(id, responseStatus) {
  return db.query(
    "UPDATE event_outbox SET status = 'delivered', delivered_at = NOW(), attempts = attempts + 1, response_status = ?, last_error = NULL, claim = NULL WHERE id = ?",
    [responseStatus, id]
  );
}

// error arrives already cut to fit. past maxAttempts it stops being retried
function failedAttempt(id, { attempts, error, maxAttempts, retryIn }) {
  return db.query(
    `UPDATE event_outbox SET attempts = ?, last_error = ?, claim = NULL,
            status = IF(? >= ?, 'failed', 'pending'), next_attempt_at = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id = ?`,
    [attempts, error, attempts, maxAttempts, retryIn, id]
  );
}

// a week of history is plenty once an event is settled
function sweepSettled() {
  return db.query("DELETE FROM event_outbox WHERE status IN ('delivered', 'failed') AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
}

module.exports = { enabledIntegrations, queue, claim, claimed, deferClaim, delivered, failedAttempt, sweepSettled };
