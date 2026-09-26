// What an upstream registry address may be. the server fetches it, so no private networks
// Author: Tim Rice

const ipacl = require('../security/network/ipacl');
const { fail } = require('./errors');

// the server fetches this url, so check it (SSRF)
function checkUpstreamUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch (err) {
    fail(400, 'that upstream address is not a url');
  }
  if (!['http:', 'https:'].includes(url.protocol)) fail(400, 'the upstream has to be http or https');
  if (url.username || url.password) fail(400, 'put credentials in the token field, not the url');
  const host = url.hostname.toLowerCase();
  const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'metadata.google.internal', '169.254.169.254'];
  if (blocked.includes(host)) fail(400, 'that host is not allowed as an upstream');
  const ip = ipacl.parseIp(host);
  if (ip) {
    //no pointing it at the private network, the oldest ssrf trick in the book
    const priv = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', 'fc00::/7', '::1/128'];
    for (const range of priv) {
      const cidr = ipacl.parseCidr(range);
      if (cidr && ipacl.cidrContains(cidr, ip)) fail(400, 'the upstream cannot be an address on a private network');
    }
  }
  return url.toString().replace(/\/+$/, '');
}

module.exports = { checkUpstreamUrl };
