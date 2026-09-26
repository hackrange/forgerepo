// Logins, sessions, registry tokens and permission checks, one require away.
// Author: Tim Rice
// the pieces live next door. this list is the whole public surface, keep it the same shape

const { COOKIE, COOKIE_PREV } = require('./cookies');
const { ROLES, can, permsFor } = require('./permissions');
const { hashPassword, verifyPassword, checkPasswordPolicy } = require('./passwords');
const { rateLimit, clearRateLimit, sweepRateLimits } = require('./rate-limit');
const { createSession, destroySession, dropUserSessions, loadSession, sweepSessions } = require('./sessions');
const { IMPERSONATE_MINUTES, startImpersonation, stopImpersonation, returnFromImpersonation } = require('./impersonation');
const { login } = require('./login');
const { newToken, hashToken, lookupToken, issueBearer, registryCredential, touchToken } = require('./tokens');
const { clientIp } = require('./client-ip');
const { attachSession, requireLogin, requirePasswordCurrent, requirePerm, requireCsrf } = require('./middleware');
const { audit, auditReq } = require('./audit-log');

module.exports = {
  COOKIE,
  COOKIE_PREV,
  IMPERSONATE_MINUTES,
  startImpersonation,
  stopImpersonation,
  returnFromImpersonation,
  ROLES,
  can,
  permsFor,
  hashPassword,
  verifyPassword,
  checkPasswordPolicy,
  rateLimit,
  clearRateLimit,
  createSession,
  destroySession,
  dropUserSessions,
  loadSession,
  sweepSessions,
  sweepRateLimits,
  login,
  newToken,
  hashToken,
  lookupToken,
  issueBearer,
  registryCredential,
  touchToken,
  clientIp,
  attachSession,
  requireLogin,
  requirePasswordCurrent,
  requirePerm,
  requireCsrf,
  audit,
  auditReq
};
