// Every request this box makes to a package registry goes through here.
// Author: Tim Rice
//
// urls and redirects come from other people, plain fetch would happily hit localhost or
// cloud metadata. so: address checked inside the connection's own lookup (no DNS rebinding),
// redirects vetted (no https->http, no creds, 5 hops, auth dropped cross-origin), size capped
// after decompression. private ranges are ok, the box itself and link local are not.

const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const zlib = require('zlib');
const { Transform } = require('stream');

const MAX_REDIRECTS = 5;
const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;
//how long a whole exchange gets, no matter how steadily the bytes trickle in
const DEADLINE_MS = 15 * 60 * 1000;

function forbiddenV4(address) {
  const [a, b] = address.split('.').map(Number);
  if (a === 0) return true;                        // this network
  if (a === 127) return true;                      // loopback, aka ourselves
  if (a === 169 && b === 254) return true;         // link local, where the metadata service hides
  if (address === '100.100.100.200') return true;  // alibaba's metadata service
  if (a >= 224) return true;                       // multicast, reserved, broadcast
  return false;
}

// an ipv6 address as its eight groups, however it was spelled. null if it isn't one
function groupsV6(address) {
  let a = String(address).toLowerCase().replace(/%.*$/, '');
  const dotted = a.match(/^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (dotted) {
    const [p, q, r, s] = dotted.slice(2).map(Number);
    a = `${dotted[1]}${((p << 8) | q).toString(16)}:${((r << 8) | s).toString(16)}`;
  }
  const halves = a.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const gap = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (gap < 0) return null;
  const groups = [...head, ...Array(gap).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

const v4From = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');

// the ipv4 address some ipv6 forms carry, so it gets judged as the address it really is.
// mapped ::ffff:0:0/96, translated ::ffff:0:0:0/96, compatible ::/96, nat64 64:ff9b::/96 and 64:ff9b:1::/48, 6to4 2002::/16
function carriedV4(address) {
  const g = groupsV6(address);
  if (!g) return null;
  const zero = (from, to) => g.slice(from, to).every((n) => n === 0);
  if (zero(0, 5) && g[5] === 0xffff) return v4From(g[6], g[7]);
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) return v4From(g[6], g[7]);
  // :: and ::1 are their own things, handled before this
  if (zero(0, 6) && (g[6] !== 0 || g[7] > 1)) return v4From(g[6], g[7]);
  if (g[0] === 0x64 && g[1] === 0xff9b && (zero(2, 6) || g[2] === 1)) return v4From(g[6], g[7]);
  if (g[0] === 0x2002) return v4From(g[1], g[2]);
  return null;
}

function forbiddenV6(address) {
  const g = groupsV6(address);
  if (!g) return true;
  if (g.slice(0, 7).every((n) => n === 0) && g[7] <= 1) return true;  // :: and ::1
  const inside = carriedV4(address);
  if (inside) return forbiddenV4(inside);
  if ((g[0] & 0xffc0) === 0xfe80) return true;       // link local
  if ((g[0] & 0xff00) === 0xff00) return true;       // multicast
  // aws's metadata service over ipv6, fd00:ec2::254 in any spelling
  if (g[0] === 0xfd00 && g[1] === 0x0ec2 && g.slice(2, 7).every((n) => n === 0) && g[7] === 0x254) return true;
  return false;
}

// private nets. fine for a configured registry, not when a document sends us there (publicOnly)
function privateV4(address) {
  const [a, b] = address.split('.').map(Number);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  return false;
}

function privateAddress(address) {
  const bare = String(address || '').replace(/^\[|\]$/g, '').toLowerCase();
  const kind = net.isIP(bare);
  if (kind === 4) return privateV4(bare);
  if (kind !== 6) return false;
  const inside = carriedV4(bare);
  if (inside) return privateV4(inside);
  const g = groupsV6(bare);
  // unique local fc00::/7, and the old site local fec0::/10 some networks still hand out
  return !!g && ((g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xffc0) === 0xfec0);
}

function forbiddenAddress(address) {
  const bare = String(address || '').replace(/^\[|\]$/g, '');
  const kind = net.isIP(bare);
  if (kind === 4) return forbiddenV4(bare);
  if (kind === 6) return forbiddenV6(bare);
  return true;
}

let policy = forbiddenAddress;

function notAllowed(what) {
  const e = new Error(`${what} is an address this box will not fetch from`);
  e.code = 'EADDRNOTALLOWED';
  return e;
}

// node calls this with or without options, sometimes wants all addresses, because of course it does
function lookupWith(publicOnly) {
  return function lookup(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    dns.lookup(hostname, { ...(options || {}), all: true }, (err, addresses) => {
      if (err) return callback(err);
      const allowed = addresses.filter((a) => !policy(a.address) && !(publicOnly && privateAddress(a.address)));
      if (!allowed.length) return callback(notAllowed(hostname));
      if (options && options.all) return callback(null, allowed);
      return callback(null, allowed[0].address, allowed[0].family);
    });
  };
}

const agents = {
  'http:': new http.Agent({ keepAlive: true, lookup: lookupWith(false) }),
  'https:': new https.Agent({ keepAlive: true, lookup: lookupWith(false) })
};

// separate pool so a private connection never gets reused by a public only request
const publicAgents = {
  'http:': new http.Agent({ keepAlive: true, lookup: lookupWith(true) }),
  'https:': new https.Agent({ keepAlive: true, lookup: lookupWith(true) })
};

function nextHop(from, location) {
  let to;
  try {
    to = new URL(location, from);
  } catch (err) {
    return { error: 'the registry redirected to something that is not an address' };
  }
  if (to.protocol !== 'http:' && to.protocol !== 'https:') {
    return { error: `the registry redirected to ${to.protocol}, which is not http` };
  }
  if (from.protocol === 'https:' && to.protocol === 'http:') {
    return { error: 'the registry redirected from https down to plain http' };
  }
  if (to.username || to.password) {
    return { error: 'the registry redirected to an address with credentials in it' };
  }
  return { url: to, sameOrigin: to.origin === from.origin };
}

function withoutCredentials(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!['authorization', 'proxy-authorization', 'cookie'].includes(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function once(url, headers, timeoutMs, maxBytes, streamMode, publicOnly, method, body, bodyStream, bodyLength) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      fn(value);
    };
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(url, {
      method: method || 'GET',
      agent: (publicOnly ? publicAgents : agents)[url.protocol],
      headers: { 'accept-encoding': 'gzip, deflate, br', ...headers }
    }, (res) => {
      const status = res.statusCode;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        return settle(resolve, { status, headers: res.headers, redirect: res.headers.location });
      }

      let stream = res;
      const encoding = String(res.headers['content-encoding'] || '').trim().toLowerCase();
      if (encoding === 'gzip' || encoding === 'x-gzip') stream = res.pipe(zlib.createGunzip());
      else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());
      else if (encoding === 'br') stream = res.pipe(zlib.createBrotliDecompress());

      // streamed for big downloads, cap still counted on the way past
      if (streamMode) {
        let passed = 0;
        const capped = new Transform({
          transform(chunk, enc, done) {
            passed += chunk.length;
            if (passed > maxBytes) {
              const e = new Error(`the answer from ${url.host} is larger than ${Math.round(maxBytes / 1048576)}MB`);
              e.code = 'ETOOLARGE';
              req.destroy();
              return done(e);
            }
            return done(null, chunk);
          }
        });
        if (stream !== res) stream.on('error', (err) => capped.destroy(new Error(`the answer from ${url.host} could not be read: ${err.message}`)));
        res.on('aborted', () => capped.destroy(new Error(`${url.host} stopped part way through`)));
        req.on('error', (err) => capped.destroy(err));
        return settle(resolve, { status, headers: res.headers, stream: stream.pipe(capped) });
      }

      const chunks = [];
      let size = 0;
      const fail = (err) => {
        req.destroy();
        settle(reject, err);
      };
      stream.on('data', (chunk) => {
        if (settled) return;
        size += chunk.length;
        if (size > maxBytes) {
          const e = new Error(`the answer from ${url.host} is larger than ${Math.round(maxBytes / 1048576)}MB`);
          e.code = 'ETOOLARGE';
          return fail(e);
        }
        chunks.push(chunk);
      });
      stream.on('end', () => settle(resolve, { status, headers: res.headers, body: Buffer.concat(chunks) }));
      stream.on('error', (err) => fail(new Error(`the answer from ${url.host} could not be read: ${err.message}`)));
      res.on('aborted', () => fail(new Error(`${url.host} stopped part way through`)));
    });

    const deadline = setTimeout(() => req.destroy(new Error(`${url.host} did not finish in time`)), DEADLINE_MS);
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`${url.host} did not answer in time`)));
    req.on('error', (err) => settle(reject, err));
    if (!bodyStream) return req.end(body);
    // counted on the way through. more than was declared is a broken file, not a bigger upload
    let sent = 0;
    const counted = new Transform({
      transform(chunk, enc, done) {
        sent += chunk.length;
        if (sent > bodyLength) return done(new Error(`the upload to ${url.host} was longer than the ${bodyLength} bytes it said`));
        done(null, chunk);
      },
      flush(done) {
        done(sent === bodyLength ? null : new Error(`the upload to ${url.host} ended after ${sent} of ${bodyLength} bytes`));
      }
    });
    bodyStream.on('error', (err) => req.destroy(new Error(`the file being sent to ${url.host} could not be read: ${err.message}`)));
    counted.on('error', (err) => req.destroy(err));
    bodyStream.pipe(counted).pipe(req);
  });
}

function respond(res, url) {
  return {
    status: res.status,
    ok: res.status >= 200 && res.status < 300,
    url: url.toString(),
    headers: {
      get(name) {
        const v = res.headers[String(name).toLowerCase()];
        if (v === undefined) return null;
        return Array.isArray(v) ? v.join(', ') : String(v);
      }
    },
    async json() { return JSON.parse((res.body || Buffer.alloc(0)).toString('utf8')); },
    async text() { return (res.body || Buffer.alloc(0)).toString('utf8'); },
    async arrayBuffer() { return res.body || Buffer.alloc(0); },
    //only there when the request asked for { stream: true }
    stream: res.stream || null
  };
}

async function request(input, options = {}) {
  let url;
  try {
    url = new URL(input);
  } catch (err) {
    throw new Error('that is not an address');
  }
  const timeoutMs = options.timeoutMs || 30000;
  const maxBytes = options.maxBytes || DEFAULT_MAX_BYTES;
  let headers = { ...(options.headers || {}) };
  if (options.bodyStream) {
    // a stream is read once, so it can't follow a redirect, and it needs its length up front
    if (!options.noRedirects) throw new Error('a streamed body cannot follow redirects');
    if (!Number.isSafeInteger(options.bodyLength) || options.bodyLength < 0) throw new Error('a streamed body needs its length');
    const declared = Object.entries(headers).find(([k]) => k.toLowerCase() === 'content-length');
    if (!declared || Number(declared[1]) !== options.bodyLength) throw new Error('a streamed body needs a content-length that matches its length');
  }

  for (let hop = 0; ; hop += 1) {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error(`${url.protocol} is not http`);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host) && (policy(host) || (options.publicOnly && privateAddress(host)))) throw notAllowed(url.host);

    const res = await once(url, headers, timeoutMs, maxBytes, !!options.stream, !!options.publicOnly, options.method, options.body,
      options.bodyStream, options.bodyLength);
    if (res.redirect === undefined) return respond(res, url);
    // a webhook that redirects gets told no, the body is never replayed somewhere else
    if (options.noRedirects) return respond(res, url);

    if (hop >= MAX_REDIRECTS) throw new Error('the registry redirected too many times');
    const next = nextHop(url, res.redirect);
    if (next.error) throw new Error(next.error);
    if (!next.sameOrigin) headers = withoutCredentials(headers);
    url = next.url;
  }
}

// tests talk to localhost. refused in production, definitely not the open door
function setPolicyForTests(fn) {
  if (process.env.NODE_ENV === 'production') throw new Error('the address policy cannot be changed in production');
  policy = fn || forbiddenAddress;
}

function closeIdleConnections() {
  for (const pool of [agents, publicAgents]) {
    pool['http:'].destroy();
    pool['https:'].destroy();
  }
}

module.exports = { request, forbiddenAddress, privateAddress, nextHop, setPolicyForTests, closeIdleConnections, MAX_REDIRECTS };
