// Portal API, how big a json body may be. a form's worth for most requests, a whole file for the few that take one.
// Author: Tim Rice

const express = require('express');
const config = require('../../config');
const { can } = require('../../security/auth/permissions');

const TYPE = ['application/json'];
const SIGNED_IN_BYTES = 1024 * 1024;

// the routes that take a whole file, with the permission each one checks anyway. keep in step with the routes
const FILE_SIZED = {
  'POST /rules/import': 'rules:import',
  'POST /import': 'backup:import',
  // package.json, lockfile, SBOM or a zip of them, from the review page
  'POST /tools/review': 'rules:read',
  // a csv of kills, up to 2 MB before the json around it
  'POST /killswitch/bulk': 'settings:write'
};

// strangers get 32kb. signed in gets 1 MB, and the import limit only where a route needs it and the role could use it,
// so nobody can park 64 MB on any endpoint before a permission check has even run
const anonymousJson = express.json({ limit: '32kb', type: TYPE });
const signedInJson = express.json({ limit: SIGNED_IN_BYTES, type: TYPE });
const fileSizedJson = express.json({ limit: Math.max(config.maxImportBytes, SIGNED_IN_BYTES), type: TYPE });

function fileSized(req) {
  const where = String(req.path || '').toLowerCase().replace(/\/+$/, '');
  const perm = FILE_SIZED[`${req.method} ${where}`];
  return Boolean(perm && req.user && !req.user.mustChangePassword && can(req.user, perm));
}

function jsonBody(req, res, next) {
  if (!req.session) return anonymousJson(req, res, next);
  return (fileSized(req) ? fileSizedJson : signedInJson)(req, res, next);
}

module.exports = { jsonBody, fileSized, FILE_SIZED, SIGNED_IN_BYTES };
