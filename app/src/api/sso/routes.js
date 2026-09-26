// Portal API, single sign on settings.
// Author: Tim Rice

const express = require('express');
const db = require('../../db');
const auth = require('../../security/auth');
const sso = require('../../security/sso');
const { wrap } = require('../../lib/http');
const { fail } = require('../../lib/errors');

const router = express.Router();

// ---------------------------------------------------------------- single sign on

// check the provider BEFORE turning sso on, and really before killing the password form
router.post(
  '/sso/test',
  auth.requirePerm('settings:write'),
  wrap(async (req, res) => {
    sso.invalidate();
    try {
      const doc = await sso.metadata(true);
      await auth.auditReq(req, 'sso.test', db.settings.get('oidc_issuer'), 'read the configuration');
      res.json({
        ok: true,
        issuer: doc.issuer,
        authorization_endpoint: doc.authorization_endpoint,
        token_endpoint: doc.token_endpoint,
        jwks_uri: doc.jwks_uri,
        userinfo_endpoint: doc.userinfo_endpoint || null,
        redirect: sso.redirectUri(),
        // provider needs this exact address, hand it back for copy/paste
        note: 'register the redirect address above at the provider, exactly as it reads'
      });
    } catch (err) {
      await auth.auditReq(req, 'sso.test', db.settings.get('oidc_issuer'), `failed: ${err.message}`);
      fail(400, err.message);
    }
  })
);

module.exports = router;
