// @ts-check
// Who did something, taken off the request once, so services never need the request itself.
// Author: Tim Rice

const auth = require('../security/auth');

/**
 * @typedef {object} Actor
 * @property {number|null} id user id, the impersonated one while acting as someone
 * @property {string|null} name their username, what created_by columns record
 * @property {string|null} username what the audit trail records, "admin as dev1" while impersonating
 * @property {string|null} ip client address
 * @property {any} user the session user, for permission checks
 */

/**
 * @param {any} req
 * @returns {Actor}
 */
function actorOf(req) {
  const u = req.user || {};
  // acting as someone: the record names both of them
  const who = u.impersonator ? `${u.impersonator.username} as ${u.username}` : u.username;
  return { id: u.id || null, name: u.username || null, username: who || null, ip: auth.clientIp(req), user: req.user || null };
}

/**
 * same row auth.auditReq writes, without needing the request
 * @param {Actor} actor
 * @param {string} action
 * @param {string|null} target
 * @param {string|null} detail
 * @param {{ before?: any, after?: any, result?: string }} [extra] what it was, what it is now, and whether it worked
 */
function audit(actor, action, target, detail, extra) {
  if (extra === undefined) return auth.audit(actor.id, actor.username, actor.ip, action, target, detail);
  return auth.audit(actor.id, actor.username, actor.ip, action, target, detail, extra);
}

module.exports = { actorOf, audit };
