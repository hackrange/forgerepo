// Integrations: where security events go. what one may point at is checked here, and again on every send.
// Author: Tim Rice
// a secret is only ever written. it never comes back out of here

const auth = require('../security/auth');
const events = require('../integrations/events');
const safefetch = require('../security/safefetch');
const integrations = require('../db/repositories/integrations');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');
const { idParam, boolFlag, oneOf } = require('../lib/validate');

const shape = (r) => ({ ...r, events: events.parseEvents(r.events), enabled: !!r.enabled, has_secret: !!Number(r.has_secret), pending: Number(r.pending), failed: Number(r.failed) });

// what an integration may point at
function fields(body, existing) {
  const kind = existing ? existing.kind : oneOf(body.kind, events.KINDS, null);
  if (!kind) fail(400, 'an integration is a webhook, Splunk HEC or syslog');
  const out = { kind };
  const pick = (k) => (body[k] !== undefined ? body[k] : existing ? existing[k] : undefined);

  const name = String(pick('name') || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name)) fail(400, 'a name is letters, numbers, and spaces, dots or dashes in the middle, up to 64');
  out.name = name;

  if (kind === 'syslog') {
    const host = String(pick('host') || '').trim();
    if (!host || host.length > 255 || !/^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+|[0-9a-fA-F:]+)$/.test(host)) fail(400, 'the syslog host is a hostname or an address');
    const port = Number(String(pick('port') === undefined ? 514 : pick('port')).trim());
    if (!Number.isInteger(port) || port < 1 || port > 65535) fail(400, 'the port is 1 to 65535');
    const transport = oneOf(pick('transport') || 'tcp', events.TRANSPORTS, null);
    if (!transport) fail(400, 'syslog goes over udp, tcp or tls');
    const format = oneOf(pick('format') || 'json', events.FORMATS, null);
    if (!format) fail(400, 'syslog messages are json or cef');
    if (body.secret) fail(400, 'syslog has no secret, use tls to protect it on the wire');
    Object.assign(out, { host, port, transport, format, url: null, secret: null });
  } else {
    let url;
    try {
      url = new URL(String(pick('url') || '').trim());
    } catch (err) {
      fail(400, 'that is not an address');
    }
    // signing keys and HEC tokens don't go over plain http
    if (url.protocol !== 'https:') fail(400, 'the address has to be https');
    if (url.username || url.password) fail(400, 'no user or password in the address, use the secret instead');
    if (url.href.length > 512) fail(400, 'that address is too long');
    if (safefetch.forbiddenAddress(url.hostname) && require('net').isIP(url.hostname.replace(/^\[|\]$/g, ''))) fail(400, 'that is an address this box will not send to');
    Object.assign(out, { url: url.href, host: null, port: null, transport: null, format: 'json' });
    if (body.secret !== undefined) {
      const secret = String(body.secret);
      if (secret === '') out.secret = null;
      // eslint-disable-next-line no-control-regex -- stripping control characters is the point
      else if (secret.length < 16 || secret.length > 512 || /[\s\u0000-\u001f]/.test(secret)) fail(400, 'a secret is 16 to 512 characters with no spaces');
      else out.secret = secret;
    }
    if (kind === 'splunk_hec' && !(out.secret || (existing && existing.secret && body.secret === undefined))) fail(400, 'Splunk HEC needs its token as the secret');
  }

  const list = pick('events');
  const wanted = Array.isArray(list) ? list : typeof list === 'string' ? events.parseEvents(list) : [];
  const clean = wanted.includes('*') ? ['*'] : [...new Set(wanted.filter((e) => events.EVENTS.includes(e)))];
  if (!clean.length || clean.length !== (wanted.includes('*') ? 1 : new Set(wanted).size)) fail(400, 'pick at least one event, and only ones on the list');
  out.events = JSON.stringify(clean);
  if (body.enabled !== undefined) out.enabled = boolFlag(body.enabled, true) ? 1 : 0;
  return out;
}

async function list() {
  return (await integrations.list()).map(shape);
}

async function get(id) {
  const row = await integrations.byId(id);
  if (!row) fail(404, 'there is no such integration');
  return row;
}

async function create(actor, body) {
  const f = fields(body, null);
  if (await integrations.nameTaken(f.name)) fail(400, 'there is already an integration by that name');
  const result = await integrations.create({ ...f, secret: f.secret || null, enabled: f.enabled === undefined ? 1 : f.enabled }, actor.name);
  events.invalidate();
  await audit(actor, 'integration.create', f.name, `${f.kind} ${f.url || `${f.transport}://${f.host}:${f.port}`}`);
  return Number(result.insertId);
}

async function update(actor, row, body) {
  const f = fields(body, row);
  if (await integrations.nameTaken(f.name, row.id)) fail(400, 'there is already an integration by that name');
  const secret = f.secret === undefined ? row.secret : f.secret;
  // a new destination never inherits the old one's secret by accident
  const moved = (f.url || '') !== (row.url || '') || (f.host || '') !== (row.host || '');
  if (moved && f.secret === undefined && row.secret) fail(400, 'the address changed, so send the secret again (or an empty one to drop it)');
  await integrations.update(row.id, {
    name: f.name, url: f.url, host: f.host, port: f.port, transport: f.transport, format: f.format,
    secret: secret || null, events: f.events, enabled: f.enabled === undefined ? row.enabled : f.enabled
  });
  events.invalidate();
  const what = [];
  if (moved) what.push('destination changed');
  if (f.secret !== undefined) what.push(f.secret ? 'secret replaced' : 'secret removed');
  if (f.enabled !== undefined && f.enabled !== Number(row.enabled)) what.push(f.enabled ? 'enabled' : 'disabled');
  const fieldsNow = {
    name: f.name, url: f.url, host: f.host, port: f.port, transport: f.transport, format: f.format,
    secret: secret ? '(set)' : null, events: f.events, enabled: f.enabled === undefined ? row.enabled : f.enabled
  };
  await audit(actor, 'integration.update', f.name, what.join(', ') || null,
    { before: { ...Object.fromEntries((Object.keys(fieldsNow)).map((k) => [k, row[k]])), secret: row.secret ? '(set)' : null }, after: fieldsNow });
}

async function remove(actor, row) {
  await integrations.remove(row.id);
  events.invalidate();
  await audit(actor, 'integration.delete', row.name, null, { before: { ...Object.fromEntries((['name', 'kind', 'url', 'host', 'port', 'transport', 'format', 'events', 'enabled']).map((k) => [k, row[k]])), secret: row.secret ? '(set)' : null } });
}

// throttled before anything is looked up, so a flood of tests costs nothing
async function sendTest(actor, rawId) {
  const limited = await auth.rateLimit(`integration-test:${actor.id}`, 10, 60000);
  if (!limited.ok) fail(429, 'that is a lot of tests, give it a minute');
  const row = await get(idParam(rawId));
  const result = await events.test(row);
  await audit(actor, 'integration.test', row.name, result.ok ? 'delivered' : result.error);
  return result;
}

function deliveries(row) {
  return integrations.deliveries(row.id);
}

async function retry(actor, row) {
  const retried = await integrations.retryFailed(row.id);
  await audit(actor, 'integration.retry', row.name, `${retried} event(s)`);
  return retried;
}

module.exports = { fields, list, get, create, update, remove, sendTest, deliveries, retry };
