// ForgeRepo. filtered package registry, portal on the same port.
// Author: Tim Rice
//
// /_admin (or /admin) is the portal, /_api its json, /pypi is python when on, the rest is npm.
// npm names can't start with _ so the underscore paths never collide. Handy.

const path = require('path');
const express = require('express');
const config = require('./config');
const db = require('./db');
const log = require('./logger');
const auth = require('./security/auth');
const ipacl = require('./security/network/ipacl');
const cache = require('./registry/npm/cache');
const artifactbackfill = require('./storage/backfill');
const policy = require('./policy');
const upstreams = require('./registry/shared/upstreams');
const portal = require('./portal');
const { HttpError } = require('./lib/errors');

const app = express();

app.disable('x-powered-by');
app.disable('etag');
// only nginx gets believed on forwarded headers. get this wrong and the ip allow list is decoration
app.set('trust proxy', config.trustProxy);

// /admin gets rewritten onto /_admin before anything below sees it
app.use(portal.alias);
// five minutes for a request body to arrive, a docker push layer excepted (it gets dropped when it stalls instead)
app.use(require('./lib/http').bodyDeadline(300000, /^\/v2\/.+\/blobs\/uploads\//));

// ---------------------------------------------------------------- security headers

app.use((req, res, next) => {
  res.set('x-content-type-options', 'nosniff');
  res.set('x-frame-options', 'DENY');
  res.set('referrer-policy', 'no-referrer');
  res.set('permissions-policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.set('cross-origin-opener-policy', 'same-origin');
  res.set('cross-origin-resource-policy', 'same-origin');
  // HSTS only if the proxy says https
  if (req.secure) res.set('strict-transport-security', 'max-age=31536000; includeSubDomains');

  // only the portal serves html so only it gets a CSP. no inline script, nice and tight
  if (portal.isPortalPath(req.path)) {
    res.set(
      'content-security-policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    res.set('cache-control', 'no-store');
  }
  // everything behind a sign in, token secrets included: stored by nobody. a route with a reason to be cached sets its own later
  if (String(req.path).toLowerCase().startsWith('/_api')) res.set('cache-control', 'no-store');
  next();
});

// ---------------------------------------------------------------- health

//liveness only. no version string, that's a free gift to whoever is matching bug lists
app.get('/_health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    res.status(503).json({ ok: false });
  }
});

// ---------------------------------------------------------------- the gate (none shall pass)

const publicDir = path.join(__dirname, '..', 'public');
const staticOptions = { dotfiles: 'deny', index: false, maxAge: '5m', redirect: false };

// same 404 as a missing path. not even a hint there's an admin side
function nothingHere(res) {
  res.status(404).type('text/plain').send('Not Found\n');
}

// Portal ip gate. not on the list = flat 404, unless ?bgt=<uuid> (break glass).
// bad key gets the same 404 as no key so nobody can test keys. empty list = wide open
app.use(async (req, res, next) => {
  try {
    if (!db.settings.getBool('acl_enabled')) return next();

    // case insensitive on purpose, /_API/me hits the api too and used to stroll right past
    if (!portal.isGated(req.path)) return next();

    const ip = auth.clientIp(req);
    if (await ipacl.ipAllowed(ip)) return next();
    if (await ipacl.hasGrant(req, ip)) return next();

    const key = req.query && req.query.bgt;
    if (key) {
      // throttled HARD, this is the only door in from an unknown address
      // and if the throttle can't count, no key gets tried
      const perIp = await auth.rateLimit(`bgt:ip:${ip}`, 5, 15 * 60000, { failClosed: true });
      const everyone = await auth.rateLimit('bgt:all', 60, 60 * 60000, { failClosed: true });
      if (!perIp.ok || !everyone.ok) {
        await auth.audit(null, null, ip, 'breakglass.throttled', null, 'too many tries');
        return nothingHere(res);
      }

      const result = await ipacl.redeem(key, ip, req.get('user-agent'));
      if (result.ok) {
        res.cookie(ipacl.GRANT_COOKIE, result.grantId, {
          httpOnly: true,
          sameSite: 'strict',
          secure: config.secureCookies,
          path: '/',
          maxAge: result.minutes * 60000
        });
        await auth.clearRateLimit(`bgt:ip:${ip}`);
        await auth.audit(null, null, ip, 'breakglass.used', result.label, `${result.minutes} minute grant`);
        //clean url, key gone from the address bar
        return res.redirect(302, `${req.portalBase || portal.PORTAL}/`);
      }
      await auth.audit(null, null, ip, 'breakglass.failed', null, `bad key from ${ip}`);
    }

    return nothingHere(res);
  } catch (err) {
    next(err);
  }
});

// registry client allow list, separate from the portal's. botching it costs installs, not your way back in
app.use(async (req, res, next) => {
  try {
    if (!db.settings.getBool('registry_acl_enabled')) return next();
    if (portal.isGated(req.path)) return next();

    const ip = auth.clientIp(req);
    if (await ipacl.registryAllowed(ip)) return next();

    // a token beats an address guess. off by default, without require_auth it's a hole in the filter
    if (db.settings.getBool('registry_acl_token_ok')) {
      const raw = auth.registryCredential(req);
      const token = raw ? await auth.lookupToken(raw) : null;
      if (token) {
        // saves the registry a second lookup
        req.npmIdentity = token;
        return next();
      }
    }

    // devs get told why. hiding is the portal's job
    return res.status(403).json({ error: 'this registry does not accept connections from your network' });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------- portal

const branding = require('./branding');

// uploaded icon and favicon. the type was read off the bytes at upload, sandboxed anyway
app.get('/_admin/brand/:kind', async (req, res, next) => {
  try {
    const got = await branding.body(req.params.kind).catch(() => null);
    if (!got) return nothingHere(res);
    res.set('content-type', got.type);
    res.set('content-disposition', 'inline');
    res.set('content-security-policy', "default-src 'none'; sandbox");
    res.set('cache-control', 'private, max-age=300');
    return res.send(got.body);
  } catch (err) {
    return next(err);
  }
});

const sendPortal = portal.portalPage(publicDir, {
  title: () => db.settings.get('registry_name'),
  favicon: () => branding.current().then((b) => b.favicon)
});
app.get('/_admin/index.html', sendPortal);
app.use('/_admin', express.static(publicDir, staticOptions));
// page navigates off the hash, so any deeper path gets it too
app.get('/_admin', sendPortal);
app.get('/_admin/*', sendPortal);

// json only, so no cross-site form posts. strangers get 32kb, signed in 1 MB, imports more (see api/shared/json-body)
const { jsonBody } = require('./api/shared/json-body');

app.use(
  '/_api',
  (req, res, next) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const type = String(req.get('content-type') || '').split(';')[0].trim();
      if (req.method !== 'DELETE' && type !== 'application/json') {
        return res.status(415).json({ error: 'send json' });
      }
    }
    next();
  },
  auth.attachSession,
  jsonBody,
  (req, res, next) => {
    // login and the who-am-i probe happen before there's a session, so no csrf yet
    if (req.path === '/login' || (req.path === '/me' && req.method === 'GET')) return next();
    return auth.requireCsrf(req, res, next);
  },
  require('./api'),
  (req, res) => res.status(404).json({ error: 'no such endpoint' })
);

// ---------------------------------------------------------------- registry (the actual point of all this)

app.use('/pypi', require('./registry/pypi/routes'));
// only /nuget/v3... is NuGet's, /nuget itself is the npm package called nuget
app.use('/nuget', require('./registry/nuget/routes'));
// only group/artifact/file paths are Maven's, /maven itself is the npm package called maven
app.use('/maven', require('./registry/maven/routes'));
// only the gem source's own paths are Ruby's, /rubygems itself is the npm package called rubygems
app.use('/rubygems', require('./registry/rubygems/routes'));
// only the CDN's own paths are CocoaPods', /cocoapods itself is the npm package called cocoapods
app.use('/cocoapods', require('./registry/cocoapods/routes'));
// only scope/name paths, /identifiers and /login are Swift's, /swift itself is the npm package called swift
app.use('/swift', require('./registry/swift/routes'));
// only packages.json, p2/ and dists/ are Composer's, /composer itself is the npm package called composer
app.use('/composer', require('./registry/composer/routes'));
// only /rpm/<mirror>/repodata/... and the packages a mirror's index lists, /rpm itself is the npm package called rpm
app.use('/rpm', require('./registry/rpm/routes'));
// only /apt/<mirror>/dists/..., its pool and /apt/signing-key.asc, /apt itself is the npm package called apt
app.use('/apt', require('./registry/apt/routes'));
// /v2 steps aside for an npm package called v2, the same way /pypi does
app.use('/', require('./registry/oci/routes'));
app.use('/', require('./registry/npm/routes'));

// ---------------------------------------------------------------- when things go wrong

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  const status = err instanceof HttpError ? err.status : err.status || err.statusCode || 500;
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'that request body is too big' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'that json will not parse' });
  }
  if (status >= 500) {
    // one raised on purpose is a sentence somebody wrote for whoever asked: the queue is full, the upstream would
    // not answer. those go back as they are. anything else got here by blowing up, and still says nothing
    if (err instanceof HttpError) {
      log.warn(`${req.method} ${log.safeUrl(req.originalUrl)} answered ${status}`, err.message);
      return res.status(status).json({ error: err.message });
    }
    log.error(`${req.method} ${log.safeUrl(req.originalUrl)} blew up`, err);
    //don't leak internals
    return res.status(500).json({ error: 'something went wrong on our end' });
  }
  res.status(status).json({ error: err.message });
});

// ---------------------------------------------------------------- boot up

// old cache came from what's now the default upstream. stamp it so an upgrade doesn't refetch everything
async function stampCachedSource() {
  const fallback = await upstreams.defaultUpstream();
  if (!fallback) return;
  const meta = await db.query('UPDATE packuments SET source = ? WHERE source IS NULL', [fallback.name]);
  const tars = await db.query('UPDATE tarballs SET source = ? WHERE source IS NULL', [fallback.name]);
  if (meta.affectedRows || tars.affectedRows) {
    log.info(`marked ${meta.affectedRows} cached document(s) and ${tars.affectedRows} tarball(s) as coming from ${fallback.name}`);
  }
}

async function main() {
  log.info(`ForgeRepo ${config.version} starting up`);
  // say it out loud, a shared-db node on its local db looks fine until the nodes disagree
  log.info(
    config.db.external
      ? `database is ${config.db.host}:${config.db.port}/${config.db.database}` +
        (config.db.ssl ? ' over tls' : ', no tls')
      : `database is the one in this container (${config.db.socketPath})`
  );
  // number/true = XFF believed from anyone, so the allow lists can be spoofed
  if (typeof config.trustProxy === 'number' || config.trustProxy === true) {
    log.warn(`TRUST_PROXY is ${config.trustProxy}: X-Forwarded-For is believed from anything that reaches port ${config.port}. `
      + 'The IP allow lists depend on that address. Make sure only the proxy can reach this port, '
      + "or set TRUST_PROXY to the proxy's own address so nothing else is believed.");
  }
  await db.connect();
  await db.loadSchema();
  await db.seed();
  await cache.init();
  // after seed, needs settings
  await upstreams.ensureDefault();
  await stampCachedSource();
  await policy.reload(true);
  await ipacl.loadAcl(true);
  await ipacl.loadFeeds(true);
  // every timer lives in jobs/, one place to see what runs when
  const jobs = require('./jobs');
  jobs.start();
  artifactbackfill.start();

  const server = app.listen(config.port, config.bindAddress, () => {
    log.info(`registry and portal are listening on ${config.bindAddress}:${config.port}`);
    log.info(`portal is at /_admin and /admin, policy mode is ${db.settings.get('policy_mode')}`);
  });

  // big tarballs from a cold cache can take a while. patience. a pushed layer of a few GB on a slow link more so, the
  // five minute limit everything else gets is bodyDeadline above
  server.headersTimeout = 65000;
  server.requestTimeout = 6 * 60 * 60 * 1000;

  const shutdown = (signal) => {
    log.info(`got ${signal}, shutting down`);
    artifactbackfill.stop();
    jobs.stop();
    server.close(async () => {
      await db.close().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 15000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  log.error('could not start', err);
  process.exit(1);
});
