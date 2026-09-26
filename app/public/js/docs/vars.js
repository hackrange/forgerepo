// ForgeRepo portal: the addresses and names documentation examples use, taken from the site the reader is on.
// Author: Tim Rice
//
// nobody should have to translate registry.example.com into their own address. if they reached the portal at
// npm.acme.com, every example says npm.acme.com

// ctx: { origin, host, protocol, publicUrl, registryName, username, portalPath }
function build(ctx) {
  var origin = String(ctx.publicUrl || ctx.origin || '').replace(/\/+$/, '');
  var host = origin.replace(/^https?:\/\//, '');
  var scheme = /^http:/.test(origin) ? 'http' : 'https';
  return {
    name: ctx.registryName || 'ForgeRepo',
    origin: origin,
    host: host,
    scheme: scheme,
    portal: origin + (ctx.portalPath || '/_admin'),
    npmRegistry: origin + '/',
    npmAuthKey: '//' + host + '/',
    pypiIndex: origin + '/pypi/simple/',
    pypiUpload: origin + '/pypi/',
    pypiHost: host.replace(/:\d+$/, ''),
    dockerHost: host,
    user: ctx.username || 'your-user-name',
    today: new Date().toISOString().slice(0, 10)
  };
}

// {{name}} for every known name. an unknown one is left as it is, so a typo shows up on the page instead of vanishing
function fill(text, vars) {
  return String(text === undefined || text === null ? '' : text).replace(/\{\{(\w+)\}\}/g, function (all, key) {
    return Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : all;
  });
}

export { build, fill };
