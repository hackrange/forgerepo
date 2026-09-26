// SMTP, vintage 1982: starttls or implicit tls, and never a password over plaintext.
// Author: Tim Rice
// no mail library - a box that decides which libraries get in pulling one in would be a bit rich

const net = require('net');
const tls = require('tls');
const os = require('os');
const { addressOnly } = require('./message');

const SMTP_TIMEOUT_MS = 30000;

// errors keep the server's own words, "550 relay denied" beats "send failed"
class SmtpSession {
  constructor(socket, host, ms = SMTP_TIMEOUT_MS) {
    this.socket = socket;
    this.host = host;
    this.buffer = '';
    this.waiting = null;
    this.closed = null;

    socket.setEncoding('utf8');
    socket.setTimeout(ms);
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('timeout', () => this.fail(new Error(`${host} stopped answering`)));
    socket.on('error', (err) => this.fail(err));
    socket.on('close', () => this.fail(new Error(`${host} closed the connection`)));
  }

  fail(err) {
    this.closed = err;
    if (this.waiting) {
      const { reject } = this.waiting;
      this.waiting = null;
      reject(err);
    }
  }

  onData(chunk) {
    this.buffer += chunk;
    if (!this.waiting) return;
    // done when the last line has "250 " not "250-"
    const lines = this.buffer.split('\r\n').filter((l) => l.length);
    if (!lines.length) return;
    const last = lines[lines.length - 1];
    if (!/^\d{3} /.test(last)) return;

    const reply = { code: parseInt(last.slice(0, 3), 10), lines, text: lines.join(' ') };
    this.buffer = '';
    const { resolve } = this.waiting;
    this.waiting = null;
    resolve(reply);
  }

  read() {
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => {
      this.waiting = { resolve, reject };
      if (this.buffer) this.onData('');
    });
  }

  async say(line, expect) {
    if (this.closed) throw this.closed;
    this.socket.write(`${line}\r\n`);
    const reply = await this.read();
    if (expect && !expect.includes(reply.code)) {
      const spoken = line.startsWith('AUTH') ? 'AUTH' : line.split(' ')[0];
      throw new Error(`the mail server refused ${spoken}: ${reply.text}`);
    }
    return reply;
  }

  end() {
    try {
      this.socket.removeAllListeners('close');
      this.socket.removeAllListeners('error');
      this.socket.end();
    } catch (err) {
      // mail's already delivered by now. shrug
    }
  }
}

function connect(options) {
  return new Promise((resolve, reject) => {
    const done = (err, socket) => (err ? reject(err) : resolve(socket));
    const socket = options.tls
      ? tls.connect({ host: options.host, port: options.port, servername: options.host, rejectUnauthorized: options.verify })
      : net.connect({ host: options.host, port: options.port });
    const ready = options.tls ? 'secureConnect' : 'connect';
    const onError = (err) => done(new Error(`could not reach ${options.host}:${options.port}, ${err.message}`));
    socket.once(ready, () => {
      socket.removeListener('error', onError);
      done(null, socket);
    });
    socket.once('error', onError);
    socket.setTimeout(SMTP_TIMEOUT_MS, () => {
      socket.destroy();
      done(new Error(`${options.host}:${options.port} did not answer`));
    });
  });
}

// a handshake that never finishes used to hang the digest forever
function upgrade(socket, host, verify, ms = SMTP_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: verify });
    const timer = setTimeout(() => {
      secure.destroy();
      reject(new Error(`starttls against ${host} did not finish`));
    }, ms);
    secure.once('secureConnect', () => {
      clearTimeout(timer);
      resolve(secure);
    });
    secure.once('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`starttls failed against ${host}, ${err.message}`));
    });
  });
}

function capabilities(reply) {
  const out = new Set();
  for (const line of reply.lines) out.add(line.slice(4).trim().toUpperCase());
  return out;
}

function authMechanisms(caps) {
  for (const cap of caps) {
    if (cap.startsWith('AUTH ')) return cap.slice(5).split(/\s+/);
  }
  return [];
}

async function sendSmtp(message, to, settings) {
  const host = settings.smtp_host;
  const port = Number(settings.smtp_port) || 587;
  const security = settings.smtp_security;
  const verify = settings.smtp_verify;
  if (!host) throw new Error('no smtp server is set');

  const socket = await connect({ host, port, tls: security === 'tls', verify });
  let session = new SmtpSession(socket, host, settings.timeoutMs);
  const me = os.hostname() || 'forgerepo';

  try {
    const greeting = await session.read();
    if (greeting.code !== 220) throw new Error(`${host} did not greet us: ${greeting.text}`);

    let caps = capabilities(await session.say(`EHLO ${me}`, [250]));

    if (security === 'starttls') {
      if (!caps.has('STARTTLS')) throw new Error(`${host} does not offer starttls`);
      await session.say('STARTTLS', [220]);
      // anything past the 220 arrived in plaintext, where anyone in the middle could have put it
      if (session.buffer) throw new Error(`${host} sent more after agreeing to starttls, refusing to carry on`);
      const plain = session.socket;
      for (const ev of ['close', 'error', 'data', 'timeout']) plain.removeAllListeners(ev);
      plain.setTimeout(0);
      const secure = await upgrade(plain, host, verify, settings.timeoutMs);
      session = new SmtpSession(secure, host, settings.timeoutMs);
      // pre-tls caps could be tampered with, ask again
      caps = capabilities(await session.say(`EHLO ${me}`, [250]));
    }

    if (settings.smtp_user) {
      // no cleartext passwords, ever
      if (security === 'none') throw new Error('refusing to send a password over a connection with no tls');
      const offered = authMechanisms(caps).map((m) => m.toUpperCase());
      const user = settings.smtp_user;
      const pass = settings.smtp_password;
      if (offered.includes('PLAIN') || !offered.length) {
        const token = Buffer.from(`\0${user}\0${pass}`, 'utf8').toString('base64');
        await session.say(`AUTH PLAIN ${token}`, [235]);
      } else if (offered.includes('LOGIN')) {
        await session.say('AUTH LOGIN', [334]);
        await session.say(Buffer.from(user, 'utf8').toString('base64'), [334]);
        await session.say(Buffer.from(pass, 'utf8').toString('base64'), [235]);
      } else {
        throw new Error(`${host} offers no login this understands (${offered.join(', ') || 'none'})`);
      }
    }

    await session.say(`MAIL FROM:<${addressOnly(settings.email_from)}>`, [250]);
    await session.say(`RCPT TO:<${addressOnly(to)}>`, [250, 251]);
    await session.say('DATA', [354]);
    await session.say(`${message}\r\n.`, [250]);
    await session.say('QUIT', [221, 250]).catch(() => null);
  } finally {
    session.end();
  }
}

module.exports = { sendSmtp };
