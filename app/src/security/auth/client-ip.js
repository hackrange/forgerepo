// The client address, as express worked it out (TRUST_PROXY decides whose forwarded header counts).
// Author: Tim Rice

function clientIp(req) {
  return String((req && (req.ip || (req.connection && req.connection.remoteAddress))) || '').slice(0, 45);
}

module.exports = { clientIp };
