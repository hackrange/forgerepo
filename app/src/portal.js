// The portal's two addresses, and the page served at them.
// Author: Tim Rice
//
// /admin gets rewritten to /_admin up front, so there's only one path through the code.
// Catch: admin is a real npm package. non-browser requests for /admin, and anything under
// /admin/-/ (tarballs), stay with the registry. a break glass key means a browser whatever it accepts.
// case insensitive, same as express matches /_admin

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');

const PORTAL = '/_admin';
const ALIAS = '/admin';
const BASES = [PORTAL, ALIAS];

// which address they came in on, so sso drops them back there. only BASES values get believed
const BASE_COOKIE = 'nr_portal';

function under(lowerPath, prefix) {
  return lowerPath === prefix || lowerPath.startsWith(`${prefix}/`);
}

function wantsPortal(req) {
  if (req.query && req.query.bgt !== undefined) return true;
  return /\btext\/html\b/i.test(String(req.get('accept') || ''));
}

function alias(req, res, next) {
  const lower = String(req.path || '').toLowerCase();

  if (under(lower, ALIAS)) {
    if (lower.startsWith(`${ALIAS}/-/`)) return next();
    if (lower === ALIAS && !wantsPortal(req)) return next();
    // only rewrite when req.url starts with the alias, i.e. every normal request
    if (!String(req.url).toLowerCase().startsWith(ALIAS)) return next();
    req.portalBase = ALIAS;
    req.url = PORTAL + req.url.slice(ALIAS.length);
    return next();
  }

  if (under(lower, PORTAL)) req.portalBase = PORTAL;
  return next();
}

// Case ignored, express treats /_API like /_api and a gate shouldn't have a side door.
function isGated(requestPath) {
  const lower = String(requestPath || '').toLowerCase();
  return lower.startsWith(PORTAL) || lower.startsWith('/_api');
}

function isPortalPath(requestPath) {
  return String(requestPath || '').toLowerCase().startsWith(PORTAL);
}

function readCookie(header, name) {
  for (const part of String(header || '').split(';')) {
    const at = part.indexOf('=');
    if (at < 0 || part.slice(0, at).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(at + 1).trim());
    } catch (err) {
      return null;
    }
  }
  return null;
}

//where to send somebody home to after single sign on
function baseFrom(req) {
  const raw = readCookie(req.headers && req.headers.cookie, BASE_COOKIE);
  return BASES.includes(raw) ? raw : PORTAL;
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// page rendered per address. assets carry a content hash so a new page never gets a stale script.
// title() is the name in Settings, favicon() an uploaded one or null
function portalPage(publicDir, { title = () => null, favicon = async () => null } = {}) {
  const template = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');
  const versions = {};
  for (const file of ['style.css', 'app.js', 'icon.svg']) {
    try {
      versions[file] = crypto.createHash('sha256').update(fs.readFileSync(path.join(publicDir, file))).digest('hex').slice(0, 12);
    } catch (err) {
      versions[file] = config.version;
    }
  }
  const shells = {};
  for (const base of BASES) {
    shells[base] = template
      .replace(/\{\{base\}\}/g, base)
      .replace(/\{\{v:([\w.-]+)\}\}/g, (match, file) => versions[file] || config.version);
  }
  // name and favicon go in last, so nothing typed into the name can turn into a placeholder
  const rendered = new Map();
  const render = (base, name, fav) => {
    const key = `${base}\n${name}\n${fav ? fav.sha256 : ''}`;
    if (rendered.has(key)) return rendered.get(key);
    const link = fav
      ? `<link rel="icon" type="${escapeHtml(fav.type)}" href="${base}/brand/favicon?v=${escapeHtml(fav.sha256.slice(0, 12))}">`
      : `<link rel="icon" type="image/svg+xml" href="${base}/icon.svg?v=${versions['icon.svg']}">`;
    const page = shells[base].replace('{{title}}', () => escapeHtml(name)).replace('{{favicon}}', () => link);
    if (rendered.size >= 32) rendered.clear();
    rendered.set(key, page);
    return page;
  };

  return async function sendPortal(req, res) {
    const base = BASES.includes(req.portalBase) ? req.portalBase : PORTAL;
    let name = 'ForgeRepo';
    let fav = null;
    try {
      name = String(title() || '').trim() || 'ForgeRepo';
      fav = await favicon();
    } catch (err) {
      //db hiccup, the plain page still works
    }
    res.cookie(BASE_COOKIE, base, {
      httpOnly: true,
      // lax not strict, the provider's redirect back is cross-site
      sameSite: 'lax',
      secure: config.secureCookies,
      path: '/_api/sso',
      maxAge: 30 * 24 * 3600 * 1000
    });
    res.type('html').send(render(base, name, fav));
  };
}

module.exports = { PORTAL, ALIAS, BASE_COOKIE, alias, isGated, isPortalPath, baseFrom, portalPage, wantsPortal, escapeHtml };
