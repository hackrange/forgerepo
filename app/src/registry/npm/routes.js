// The npm facing side, aka the thing developers point their .npmrc at.
// Author: Tim Rice
// policy first. blocked versions get trimmed out, tarball links point back here

const express = require('express');
const db = require('../../db');
const policy = require('../../policy');
const upstream = require('./upstream');
const auth = require('../../security/auth');
const killswitch = require('../../policy/killswitch');
const registryMode = require('../../policy/mode');
const packages = require('../../db/repositories/packages');
const { record } = require('../shared/access');
const { looksLikeNpmClient, refuse, openRequest } = require('./client');
const { servePackument } = require('./packument');
const { serveTarball } = require('./tarball');
const publish = require('./publish');
const auditRoutes = require('./audit');

const router = express.Router();

// ---------------------------------------------------------------- auth

// only enforced with require_auth, but we always note who
async function identify(req, res, next) {
  req.startedAt = Date.now();
  const raw = auth.registryCredential(req);

  if (raw) {
    // ip filter may have looked it up already
    const token = req.npmIdentity || (await auth.lookupToken(raw));
    if (token) {
      req.npmIdentity = token;
      auth.touchToken(token.id, auth.clientIp(req)).catch(() => {});
    } else if (db.settings.getBool('require_auth')) {
      record(req, { action: 'deny', status: 401, reason: 'bad token' });
      return res.status(401).json({ error: 'that auth token is not valid on this registry' });
    }
  } else if (db.settings.getBool('require_auth')) {
    record(req, { action: 'deny', status: 401, reason: 'no token' });
    return res
      .status(401)
      .json({ error: 'this registry needs a token, run: npm config set //<host>/:_authToken <your token>' });
  }

  next();
}

router.use(identify);

// ---------------------------------------------------------------- odds and ends

// just a 200, no version to match against bug lists
router.get('/-/ping', (req, res) => {
  res.json({});
});

router.get('/-/whoami', (req, res) => {
  if (req.npmIdentity) return res.json({ username: req.npmIdentity.username });
  res.status(401).json({ error: 'no token was sent' });
});

router.use(auditRoutes);

// npm search, filtered to what people are actually allowed to install
router.get('/-/v1/search', async (req, res) => {
  const text = String(req.query.text || '').slice(0, 200);
  const size = Math.min(parseInt(req.query.size, 10) || 20, 100);
  try {
    const result = await upstream.search(text, size);
    const objects = [];
    for (const obj of result.objects || []) {
      const name = obj.package && obj.package.name;
      if (!name) continue;
      if (await killswitch.check('npm', name, null)) continue;
      const verdict = await policy.checkPackage(name, undefined, policy.scopeOf(req));
      if (verdict.allowed) objects.push(obj);
    }
    record(req, { action: 'allow', reason: 'search' });
    res.json({ objects, total: objects.length, time: new Date().toISOString() });
  } catch (err) {
    record(req, { action: 'error', status: err.status || 502, reason: err.message });
    res.status(err.status || 502).json({ error: err.message });
  }
});

router.get('/-/package/:name/dist-tags', async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  if (!upstream.validName(name)) return res.status(400).json({ error: 'that is not a valid package name' });

  const dead = await killswitch.check('npm', name, null);
  if (dead) {
    record(req, { package_name: name, action: 'deny', status: 403, reason: dead.reason, blocked_by: 'killswitch' });
    return refuse(res, req, name, null, { reason: dead.reason });
  }
  const verdict = await policy.checkPackage(name, undefined, policy.scopeOf(req));
  if (!verdict.allowed && !db.settings.getBool('audit_mode')) {
    record(req, { package_name: name, action: 'deny', status: 403, reason: verdict.reason, rule_id: verdict.rule && verdict.rule.id });
    await openRequest(req, name, null, verdict.reason);
    return refuse(res, req, name, null, verdict);
  }

  try {
    const { doc } = await upstream.getPackument(name, 'abbreviated');
    const filtered = await policy.filterPackument(name, JSON.parse(JSON.stringify(doc)), policy.scopeOf(req));
    const tags = filtered.doc['dist-tags'] || {};
    const killed = await killswitch.killedVersions('npm', name, Object.values(tags));
    for (const [tag, v] of Object.entries(tags)) if (killed.has(v)) delete tags[tag];
    if (registryMode.lockdown()) {
      const onDisk = new Set((await packages.tarballVersions(name)).map((r) => r.version));
      for (const [tag, v] of Object.entries(tags)) if (!onDisk.has(v)) delete tags[tag];
    }
    record(req, { package_name: name, action: 'allow' });
    res.json(tags);
  } catch (err) {
    record(req, { package_name: name, action: 'error', status: err.status || 502, reason: err.message });
    res.status(err.status || 502).json({ error: err.message });
  }
});

// express's default advertised PUT,DELETE (only ever 405) and scanners wrote it up as WebDAV
router.options('*', (req, res) => {
  res.set('allow', 'GET, HEAD, POST, PUT, OPTIONS');
  res.status(204).end();
});

// npm dist-tag add / rm
router.put('/-/package/:name/dist-tags/:tag', (req, res) => publish.handleTag(req, res, decodeURIComponent(req.params.name), req.params.tag));
router.delete('/-/package/:name/dist-tags/:tag', (req, res) => publish.handleTag(req, res, decodeURIComponent(req.params.name), req.params.tag));

// npm publish and npm deprecate, for reserved names only. the name is the whole path, a scope's slash arrives encoded
router.put('*', (req, res) => {
  let name;
  try {
    name = decodeURIComponent(req.path).replace(/^\/+/, '');
  } catch (err) {
    return res.status(400).json({ error: 'that url is not encoded properly' });
  }
  // npm unpublish writes a trimmed document to /<name>/-rev/<rev> before it deletes. never here
  if (!name || name.includes('/-rev/') || name.includes('/-/')) {
    record(req, { package_name: name || null, action: 'deny', status: 405, reason: 'unpublish attempt' });
    return res.status(405).json({ error: 'a published version is never removed here. Deprecate it with npm deprecate instead' });
  }
  return publish.handlePut(req, res, name);
});
router.delete('*', (req, res) => {
  record(req, { action: 'deny', status: 405, reason: 'delete attempt' });
  res.status(405).json({ error: 'a published version is never removed here. Deprecate it with npm deprecate instead' });
});

// ---------------------------------------------------------------- the main path

router.get('*', async (req, res) => {
  // not secrecy. npm has packages called config.json, index.php, phpmyadmin... and
  // wordlist scanners report all of them as exposed files. saves someone an afternoon
  if (db.settings.getBool('npm_clients_only') && !looksLikeNpmClient(req)) {
    record(req, { action: 'deny', status: 404, reason: 'not an npm client' });
    return res.status(404).json({ error: 'not found' });
  }

  let decoded;
  try {
    decoded = decodeURIComponent(req.path).replace(/^\/+/, '');
  } catch (err) {
    return res.status(400).json({ error: 'that url is not encoded properly' });
  }
  if (!decoded) {
    // no product name, no policy mode, no portal link
    return res.json({ ok: true });
  }

  const marker = decoded.indexOf('/-/');
  if (marker > 0 && decoded.endsWith('.tgz')) {
    return serveTarball(req, res, decoded.slice(0, marker), decoded.slice(marker + 3));
  }
  return servePackument(req, res, decoded);
});

module.exports = router;
