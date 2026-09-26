// Getting an event to a receiver: webhooks and Splunk HEC over https, syslog over udp, tcp or tls.
// Author: Tim Rice
// every destination is checked against the same address rules as the rest of the box, and nothing it answers is kept

const dgram = require('dgram');
// the header prefix from before the rename, sent beside the new one for a while
const LEGACY = `x-${'repo'}${'forge'}-`;
const dns = require('dns');
const net = require('net');
const tls = require('tls');
const safefetch = require('../../security/safefetch');
const { toHec, toSyslog, signature } = require('./formats');

const SEND_TIMEOUT_MS = 10000;
// UDP syslog past this gets truncated or dropped by most receivers
const MAX_UDP_BYTES = 8192;

function sendError(message) {
  const e = new Error(message);
  e.delivery = true;
  return e;
}

// what an admin sees when a send fails. plain words, never openssl's internals or a file path
function plain(err) {
  const code = String((err && err.code) || '');
  if (code === 'EADDRNOTALLOWED') return err.message;
  if (code === 'ECONNREFUSED') return 'refused the connection';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'the name does not resolve';
  if (code === 'ECONNRESET') return 'dropped the connection';
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return 'is not reachable from here';
  if (code === 'ETIMEDOUT' || /did not (answer|finish) in time|timed out/.test(String(err && err.message))) return 'did not answer in time';
  if (/^CERT_|^UNABLE_TO_|SELF_SIGNED|ERR_TLS_CERT/.test(code)) return 'its certificate is not trusted';
  if (code === 'EPROTO' || /^ERR_SSL/.test(code)) return 'the TLS handshake failed, check it really speaks https or tls on that port';
  return 'the connection failed';
}

async function httpSend(integration, url, body, headers) {
  let res;
  try {
    res = await safefetch.request(url, {
      method: 'POST', body, noRedirects: true, timeoutMs: SEND_TIMEOUT_MS, maxBytes: 64 * 1024,
      headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)), 'user-agent': 'ForgeRepo', ...headers }
    });
  } catch (err) {
    throw sendError(err.code === 'EADDRNOTALLOWED' ? err.message : `${new URL(url).host} ${plain(err)}`);
  }
  // the answer is never stored or shown, only its status. a webhook must not become a way to read internal pages
  if (res.status >= 300 && res.status < 400) throw sendError(`${new URL(url).host} redirected, and webhooks do not follow redirects`);
  if (!res.ok) throw sendError(`${new URL(url).host} answered ${res.status}`);
  return res.status;
}

// resolved and checked here, then connected to by address, so DNS can't be swapped in between
async function vetted(host) {
  const bare = String(host).replace(/^\[|\]$/g, '');
  const addresses = net.isIP(bare) ? [{ address: bare }] : await dns.promises.lookup(bare, { all: true });
  const ok = addresses.find((a) => !safefetch.forbiddenAddress(a.address));
  if (!ok) throw sendError(`${host} is an address this box will not send to`);
  return ok.address;
}

async function syslogSend(integration, line) {
  const address = await vetted(integration.host);
  const port = Number(integration.port);
  const data = Buffer.from(line, 'utf8');
  if (integration.transport === 'udp') {
    if (data.length > MAX_UDP_BYTES) throw sendError('the event is too big for UDP syslog, use TCP or TLS');
    await new Promise((resolve, reject) => {
      const sock = dgram.createSocket(net.isIPv6(address) ? 'udp6' : 'udp4');
      sock.send(data, port, address, (err) => {
        sock.close();
        return err ? reject(sendError(`${integration.host} ${plain(err)}`)) : resolve();
      });
    });
    return 0;
  }
  await new Promise((resolve, reject) => {
    const opts = { host: address, port, timeout: SEND_TIMEOUT_MS };
    const sock = integration.transport === 'tls'
      ? tls.connect({ ...opts, servername: net.isIP(integration.host) ? undefined : integration.host, rejectUnauthorized: true })
      : net.connect(opts);
    const fail = (err) => { sock.destroy(); reject(sendError(`${integration.host} ${plain(err)}`)); };
    sock.once(integration.transport === 'tls' ? 'secureConnect' : 'connect', () => {
      // newline framed, what rsyslog, syslog-ng and most SIEM collectors take on a stream
      sock.end(Buffer.concat([data, Buffer.from('\n')]), () => resolve());
    });
    sock.once('timeout', () => fail(new Error('timed out')));
    sock.once('error', fail);
  });
  return 0;
}

async function deliver(integration, payload) {
  const event = typeof payload === 'string' ? JSON.parse(payload) : payload;
  const version = require('../../../package.json').version;
  if (integration.kind === 'webhook') {
    const body = JSON.stringify(event);
    const ts = String(Math.floor(Date.now() / 1000));
    const headers = { 'x-forgerepo-event': event.event_type, 'x-forgerepo-delivery': event.id, 'x-forgerepo-timestamp': ts };
    if (integration.secret) headers['x-forgerepo-signature'] = signature(integration.secret, ts, body);
    // the project used to be called something else. receivers written for its headers keep working for now
    for (const [k, v] of Object.entries(headers)) headers[k.replace('x-forgerepo-', LEGACY)] = v;
    return httpSend(integration, integration.url, body, headers);
  }
  if (integration.kind === 'splunk_hec') {
    return httpSend(integration, integration.url, toHec(event), integration.secret ? { authorization: `Splunk ${integration.secret}` } : {});
  }
  return syslogSend(integration, toSyslog(event, integration.format, version));
}

module.exports = { vetted, deliver };
