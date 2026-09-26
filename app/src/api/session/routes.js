// Portal API, login, logout, the current user, SSO sign in, password change.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const branding = require('../../branding');
const config = require('../../config');
const sso = require('../../security/sso');
const portal = require('../../portal');
const ecosystems = require('../../ecosystems');
const log = require('../../logger');
const session = require('../../services/session');
const { wrap } = require('../../lib/http');
const { actorOf } = require('../../lib/actor');
const { required } = require('../../lib/validate');

const router = express.Router();

// ---------------------------------------------------------------- session

router.post(
  '/login',
  wrap(async (req, res) => {
    const username = required(req.body.username, 64, 'username');
    const password = String(req.body.password || '');
    // read fresh every attempt so enable_local_login.sh works with no restart
    if (!sso.passwordLoginAllowed()) {
      return res.status(403).json({
        error: 'this box signs in through your identity provider. Use the button on the login page.'
      });
    }
    const result = await auth.login(username, password, req);
    if (!result.ok) return res.status(result.status || 401).json({ error: result.error });

    const created = await auth.createSession(res, result.user, req);
    res.json({
      ok: true,
      csrf: created.csrf,
      user: {
        id: result.user.id,
        username: result.user.username,
        role: result.user.role,
        mustChangePassword: !!result.user.must_change_password
      },
      permissions: auth.permsFor(result.user.role)
    });
  })
);

router.post(
  '/logout',
  wrap(async (req, res) => {
    if (req.user) {
      await auth.auditReq(req, req.user.impersonator ? 'impersonate.end' : 'logout', req.user.username,
        req.user.impersonator ? 'signed out while acting as them, which signs the admin out too' : null);
    }
    await auth.destroySession(req, res);
    res.json({ ok: true });
  })
);

// ---------------------------------------------------------------- SSO
// nothing from the browser is believed until the id token's signature checks out

router.get(
  '/sso/login',
  wrap(async (req, res) => {
    try {
      const url = await sso.begin(req);
      // this login belongs to this browser, the callback has to come back to it
      sso.bindBrowser(res, url);
      res.redirect(302, url);
    } catch (err) {
      log.warn('could not start an sso login', err.message);
      res.redirect(302, `${portal.baseFrom(req)}/#login?sso_error=${encodeURIComponent(err.message.slice(0, 200))}`);
    }
  })
);

router.get(
  '/sso/callback',
  wrap(async (req, res) => {
    // read once, then gone whatever happens next
    const sameBrowser = sso.sameBrowser(req, req.query.state);
    sso.forgetBrowser(res);
    if (req.query.error) {
      const said = String(req.query.error_description || req.query.error).slice(0, 200);
      await auth.audit(null, null, auth.clientIp(req), 'login.sso.failed', null, `the provider said: ${said}`);
      return res.redirect(302, `${portal.baseFrom(req)}/#login?sso_error=${encodeURIComponent(said)}`);
    }
    try {
      if (!sameBrowser) throw new Error('that sign in was started in another browser, or its cookie was lost. Start again from this browser');
      const user = await sso.complete(req.query);
      await auth.createSession(res, user, req);
      // groups changed upstream, nobody here did it. log it, somebody WILL ask
      const note = user.created
        ? `account made on the way in, as ${user.role}`
        : (user.roleChanged ? `role ${user.roleChanged.from} to ${user.roleChanged.to}, from the provider's groups` : null);
      await auth.audit(user.id, user.username, auth.clientIp(req), 'login.sso', user.username, note);
      res.redirect(302, `${portal.baseFrom(req)}/`);
    } catch (err) {
      log.warn('an sso login failed', err.message);
      await auth.audit(null, null, auth.clientIp(req), 'login.sso.failed', null, err.message.slice(0, 255));
      res.redirect(302, `${portal.baseFrom(req)}/#login?sso_error=${encodeURIComponent(err.message.slice(0, 200))}`);
    }
  })
);

router.get(
  '/me',
  wrap(async (req, res) => {
    const brandIcon = await branding.current().then((b) => (b.icon ? b.icon.sha256.slice(0, 12) : null)).catch(() => null);
    // time ran out while acting as someone: the admin's own session comes back, if it is still good
    if (!req.user) {
      const back = await auth.returnFromImpersonation(req, res, null);
      if (back) {
        req.session = back;
        req.user = back.user;
        await auth.auditReq(req, 'impersonate.end', null, `the ${auth.IMPERSONATE_MINUTES} minutes ran out`);
      }
    }
    // asked before login, so no provider details in here. the name is already in the page title
    if (!req.user) return res.json({ loggedIn: false, sso: sso.publicState(), registryName: db.settings.get('registry_name'), brandIcon });
    res.json({
      loggedIn: true,
      // page needs to know which sign in screen to draw if the session dies mid-page
      sso: sso.publicState(),
      csrf: req.session.csrf,
      user: req.user,
      permissions: auth.permsFor(req.user.role),
      policyMode: db.settings.get('policy_mode'),
      auditMode: db.settings.getBool('audit_mode'),
      registryMode: require('../../policy/mode').current(),
      registryName: db.settings.get('registry_name'),
      brandIcon,
      impersonation: req.user.impersonator ? { by: req.user.impersonator.username, endsAt: req.session.impersonation.endsAt } : null,
      maxImportMB: Math.round(config.maxImportBytes / 1048576),
      ecosystems: ecosystems.enabled((k) => db.settings.getBool(k)).map((e) => ({ id: e.id, name: e.name, label: e.label })),
      // switched off ones still name old rows
      ecosystemNames: Object.fromEntries(ecosystems.ALL.map((e) => [e.id, e.name])),
      version: config.version
    });
  })
);

router.post(
  '/me/password',
  auth.requireLogin,
  wrap(async (req, res) => {
    // acting as someone is not owning their account
    if (req.user.impersonator) return res.status(403).json({ error: 'a password cannot be changed while acting as someone else' });
    await session.changePassword(actorOf(req), req.session.sessionId, String(req.body.current_password || ''), String(req.body.new_password || ''));
    res.json({ ok: true });
  })
);

module.exports = router;
