// Security events out to webhooks, Splunk and syslog.
// Author: Tim Rice
// emit() drops an event in the outbox for every integration that wants it, a worker delivers with backoff.
// the pieces live next door, this is who wants what plus the one list everything else requires

const log = require('../../logger');
const outboxRows = require('../../db/repositories/event-outbox');
const { EVENTS, build, who } = require('./build');
const { toCef, toSyslog, toHec, signature } = require('./formats');
const { vetted, deliver } = require('./transports');
const { MAX_ATTEMPTS, TICK_MS, backoffSeconds, tick, sweep, test } = require('./outbox');

const KINDS = ['webhook', 'splunk_hec', 'syslog'];
const FORMATS = ['json', 'cef'];
const TRANSPORTS = ['udp', 'tcp', 'tls'];
const CACHE_MS = 5000;

// ---------------------------------------------------------------- who wants what

let cache = null;
let cachedAt = 0;

function invalidate() {
  cache = null;
}

function parseEvents(text) {
  try {
    const list = JSON.parse(text || '[]');
    return Array.isArray(list) ? list.filter((e) => e === '*' || EVENTS.includes(e)) : [];
  } catch (err) {
    return [];
  }
}

async function integrations() {
  if (cache && Date.now() - cachedAt < CACHE_MS) return cache;
  const rows = await outboxRows.enabledIntegrations();
  cache = rows.map((r) => ({ id: Number(r.id), events: parseEvents(r.events) }));
  cachedAt = Date.now();
  return cache;
}

const wants = (integration, type) => integration.events.includes('*') || integration.events.includes(type);

// a blocked install retries a lot. one event per thing per consumer per minute is plenty
const recent = new Map();
const QUIET_MS = 60000;
function noisy(type, e) {
  if (type !== 'package.blocked' && type !== 'package.requested' && type !== 'policy.violation') return false;
  const key = [type, e.ecosystem, e.package, e.version, e.token, e.source_ip, e.reason].join('\n');
  const now = Date.now();
  const last = recent.get(key);
  if (last && now - last < QUIET_MS) return true;
  if (recent.size > 10000) recent.clear();
  recent.set(key, now);
  return false;
}

// never throws, never waits on the network
function emit(type, fields) {
  if (!EVENTS.includes(type)) return;
  (async () => {
    const targets = (await integrations()).filter((i) => wants(i, type));
    if (!targets.length) return;
    const event = build(type, fields);
    if (noisy(type, event)) return;
    const body = JSON.stringify(event);
    await outboxRows.queue(targets.map((t) => t.id), type, body);
  })().catch((err) => log.error(`could not queue a ${type} event`, err.message));
}

module.exports = {
  EVENTS, KINDS, FORMATS, TRANSPORTS, MAX_ATTEMPTS, build, who, emit, invalidate, parseEvents,
  TICK_MS, toCef, toSyslog, toHec, signature, backoffSeconds, vetted, deliver, tick, sweep, test
};
