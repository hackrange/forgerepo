// @ts-check
// Input checking for anything a request hands us, aka trust nobody.
// Author: Tim Rice

const { fail } = require('./errors');

/**
 * ids are plain positive integers or nothing. no "1 OR 1=1" today thanks
 * @param {unknown} value
 * @returns {number}
 */
function idParam(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 4294967295) fail(400, 'that id is not valid');
  return n;
}

/**
 * @param {unknown} value
 * @param {number} max
 * @param {string} [label]
 * @returns {string|null}
 */
function str(value, max, label) {
  if (value === undefined || value === null) return null;
  const s = String(value).trim();
  if (!s) return null;
  if (s.length > max) fail(400, `${label || 'that field'} is too long, max ${max} characters`);
  return s;
}

/**
 * @param {unknown} value
 * @param {number} max
 * @param {string} [label]
 * @returns {string}
 */
function required(value, max, label) {
  const s = str(value, max, label);
  if (!s) return fail(400, `${label || 'that field'} is required`);
  return s;
}

// search box -> LIKE pattern. escape % and _ ("node_fetch" used to match way too much),
// then * becomes the one wildcard people actually type
/** @param {unknown} search */
function likeBody(search) {
  return String(search).replace(/[\\%_]/g, (ch) => `\\${ch}`).replace(/\*/g, '%');
}

/**
 * @param {unknown} search
 * @returns {string|null}
 */
function likeTerm(search) {
  if (!search) return null;
  return `%${likeBody(search)}%`;
}

/**
 * same but anchored. cve. finds cve.block, not every row with cve somewhere in it
 * @param {unknown} search
 * @returns {string|null}
 */
function likePrefix(search) {
  if (!search) return null;
  return `${likeBody(search)}%`;
}

/**
 * @template T
 * @param {unknown} value
 * @param {T} fallback
 * @returns {boolean|T}
 */
function boolFlag(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

/**
 * @template T
 * @param {unknown} value
 * @param {number} min
 * @param {number} max
 * @param {T} fallback
 * @returns {number|T}
 */
function intIn(value, min, max, fallback) {
  const n = parseInt(String(value), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

/**
 * case-insensitive, hands back the list's own spelling since it goes straight into a query.
 * Used to lowercase the input so MODERATE never matched and the severity filter did absolutely nothing.
 * @template T, F
 * @param {unknown} value
 * @param {readonly T[]} list
 * @param {F} fallback
 * @returns {T|F}
 */
function oneOf(value, list, fallback) {
  const s = String(value || '').toLowerCase();
  const hit = list.find((item) => String(item).toLowerCase() === s);
  return hit === undefined ? fallback : hit;
}

/**
 * sort columns come from a fixed map, never straight from the query string
 * @param {unknown} requested
 * @param {Record<string, string>} allowed
 * @param {string} fallback
 * @returns {string}
 */
function sortClause(requested, allowed, fallback) {
  const key = String(requested || '').toLowerCase();
  return allowed[key] || fallback;
}

/**
 * @param {{ limit?: unknown, page?: unknown }} query
 * @returns {{ limit: number, offset: number, page: number }}
 */
function paging(query) {
  // 1000 max, nobody reads a thousand rows anyway
  const limit = intIn(query.limit, 1, 1000, 50);
  const page = intIn(query.page, 1, 100000, 1);
  return { limit, offset: (page - 1) * limit, page };
}

module.exports = { idParam, str, required, likeTerm, likePrefix, boolFlag, intIn, oneOf, sortClause, paging };
