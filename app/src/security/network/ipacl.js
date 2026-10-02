// IP allow list for the portal, plus break glass keys for when you locked yourself out.
// Author: Tim Rice
// break glass grants are pinned to the redeeming ip, keys stored as sha256 only

const crypto = require('crypto');
const db = require('../../db');
const log = require('../../logger');
const allowlists = require('../../db/repositories/allowlists');
const feedRows = require('../../db/repositories/acl-feeds');
const breakglass = require('../../db/repositories/breakglass');

const GRANT_COOKIE = 'nr_bg';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------- ip parsing (bigints, sorry)

function parseV4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

function parseV6(text) {
  // 45 is the longest real one (with a dotted quad on the end). anything longer is junk, and slow junk
  if (text.length > 45) return null;
  let head = text;
  let tailV4 = null;

  //trailing dotted quad -> two hex groups
  const dotted = head.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const v4 = parseV4(dotted[1]);
    if (v4 === null) return null;
    tailV4 = v4;
    head = head.slice(0, dotted.index);
    head = head.replace(/:$/, head.endsWith('::') ? ':' : '');
  }

  const halves = head.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':').filter((s) => s !== '') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter((s) => s !== '') : [];

  const groups = [];
  for (const g of left) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    groups.push(BigInt(parseInt(g, 16)));
  }

  const tailGroups = [];
  for (const g of right) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    tailGroups.push(BigInt(parseInt(g, 16)));
  }
  if (tailV4 !== null) {
    tailGroups.push((tailV4 >> 16n) & 0xffffn);
    tailGroups.push(tailV4 & 0xffffn);
  }

  const total = groups.length + tailGroups.length;
  if (halves.length === 2) {
    if (total > 7) return null;
    while (groups.length + tailGroups.length < 8) groups.push(0n);
  } else if (total !== 8) {
    return null;
  }

  const all = groups.concat(tailGroups);
  let value = 0n;
  for (const g of all) value = (value << 16n) | g;
  return value;
}

// v4-mapped v6 comes back as plain v4 so 10.0.0.0/8 still matches
function parseIp(input) {
  let text = String(input || '').trim();
  if (!text) return null;
  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);

  if (text.includes(':')) {
    const mapped = text.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
    if (mapped) {
      const v4 = parseV4(mapped[1]);
      return v4 === null ? null : { version: 4, value: v4 };
    }
    const v6 = parseV6(text);
    return v6 === null ? null : { version: 6, value: v6 };
  }

  const v4 = parseV4(text);
  return v4 === null ? null : { version: 4, value: v4 };
}

function parseCidr(input) {
  const text = String(input || '').trim();
  if (!text) return null;
  const slash = text.lastIndexOf('/');
  const ipPart = slash >= 0 ? text.slice(0, slash) : text;
  const ip = parseIp(ipPart);
  if (!ip) return null;

  const maxBits = ip.version === 4 ? 32 : 128;
  let prefix = maxBits;
  if (slash >= 0) {
    const raw = text.slice(slash + 1);
    if (!/^\d{1,3}$/.test(raw)) return null;
    prefix = Number(raw);
    if (prefix > maxBits) return null;
  }
  const shift = BigInt(maxBits - prefix);
  return { version: ip.version, base: (ip.value >> shift) << shift, prefix, shift, text };
}

function cidrContains(cidr, ip) {
  if (!cidr || !ip || cidr.version !== ip.version) return false;
  return (ip.value >> cidr.shift) === (cidr.base >> cidr.shift);
}

function validCidr(text) {
  return parseCidr(text) !== null;
}

function normalizeCidr(text) {
  const c = parseCidr(text);
  if (!c) return null;
  if (c.version === 4) {
    const b = c.base;
    const octets = [(b >> 24n) & 255n, (b >> 16n) & 255n, (b >> 8n) & 255n, b & 255n];
    return `${octets.join('.')}/${c.prefix}`;
  }
  const groups = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(((c.base >> BigInt(i * 16)) & 0xffffn).toString(16));
  return `${groups.join(':')}/${c.prefix}`;
}

// ---------------------------------------------------------------- portal acl lookup

let aclCache = [];
let aclLoadedAt = 0;
let aclDirty = true;

async function loadAcl(force) {
  if (!force && !aclDirty && Date.now() - aclLoadedAt < 5000) return aclCache;
  const rows = await allowlists.enabledEntries('portal');
  aclCache = rows.map((r) => ({ id: r.id, label: r.label, cidr: parseCidr(r.cidr), text: r.cidr })).filter((r) => r.cidr);
  aclLoadedAt = Date.now();
  aclDirty = false;
  return aclCache;
}

function invalidateAcl() {
  aclDirty = true;
}

async function ipAllowed(ipText) {
  const list = await loadAcl();
  // empty = wide open. safety net, not a bug
  if (!list.length) return true;
  const ip = parseIp(ipText);
  if (!ip) return false;
  return list.some((entry) => cidrContains(entry.cidr, ip));
}

// ---------------------------------------------------------------- registry acl
// own table, one shared list would definitely open one side more than meant

let regCache = [];
let regLoadedAt = 0;
let regDirty = true;

async function loadRegistryAcl(force) {
  if (!force && !regDirty && Date.now() - regLoadedAt < 5000) return regCache;
  const rows = await allowlists.enabledEntries('registry');
  regCache = rows.map((r) => ({ id: r.id, label: r.label, cidr: parseCidr(r.cidr), text: r.cidr })).filter((r) => r.cidr);
  regLoadedAt = Date.now();
  regDirty = false;
  return regCache;
}

function invalidateRegistryAcl() {
  regDirty = true;
}

async function registryAllowed(ipText) {
  const list = await loadRegistryAcl();
  const feed = await loadFeeds();
  // same safety net. an unfetched feed counts as empty too, a github hiccup
  // must not refuse every build
  if (!list.length && !feed.count) {
    log.warn('client allow list is on but empty, letting everything through');
    return true;
  }
  const ip = parseIp(ipText);
  if (!ip) return false;
  if (list.some((entry) => cidrContains(entry.cidr, ip))) return true;
  return inRanges(ip.version === 4 ? feed.v4 : feed.v6, ip.value);
}

// ---------------------------------------------------------------- fetched lists
// thousands of entries, so merged into ranges at load and binary searched

let feedCache = { v4: [], v6: [], count: 0 };
let feedLoadedAt = 0;
let feedDirty = true;

function activeFeeds() {
  return db.settings.getBool('registry_acl_github') ? ['github'] : [];
}

function toRange(cidr) {
  const size = 1n << BigInt((cidr.version === 4 ? 32 : 128) - cidr.prefix);
  return [cidr.base, cidr.base + size - 1n];
}

// touching counts too, 10/8 + 11/8 is one range
function mergeRanges(ranges) {
  const sorted = ranges.slice().sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out = [];
  for (const [start, end] of sorted) {
    const last = out[out.length - 1];
    if (last && start <= last[1] + 1n) {
      if (end > last[1]) last[1] = end;
    } else {
      out.push([start, end]);
    }
  }
  return out;
}

function inRanges(ranges, value) {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (value < ranges[mid][0]) hi = mid - 1;
    else if (value > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

async function loadFeeds(force) {
  if (!force && !feedDirty && Date.now() - feedLoadedAt < 5000) return feedCache;
  const feeds = activeFeeds();
  feedLoadedAt = Date.now();
  feedDirty = false;

  if (!feeds.length) {
    feedCache = { v4: [], v6: [], count: 0 };
    return feedCache;
  }

  const rows = await feedRows.cidrs(feeds);
  const v4 = [];
  const v6 = [];
  for (const row of rows) {
    const cidr = parseCidr(row.cidr);
    if (!cidr) continue;
    (cidr.version === 4 ? v4 : v6).push(toRange(cidr));
  }
  feedCache = { v4: mergeRanges(v4), v6: mergeRanges(v6), count: rows.length };
  return feedCache;
}

function invalidateFeeds() {
  feedDirty = true;
}

// typed + fetched, checked before the last typed network can be deleted
async function registryNetworkCount(exceptId) {
  const typed = await allowlists.enabledCount('registry', exceptId);
  const feeds = activeFeeds();
  const fetched = feeds.length ? await feedRows.countIn(feeds) : 0;
  return { typed, fetched, total: typed + fetched };
}

// ---------------------------------------------------------------- grants

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

// hashed like sessions, reading the table won't walk you past the allow list
function grantKey(id) {
  return crypto.createHash('sha256').update(String(id)).digest('hex');
}

async function hasGrant(req, ipText) {
  const id = parseCookies(req.headers.cookie)[GRANT_COOKIE];
  if (!id || !/^[a-f0-9]{64}$/.test(id)) return false;
  const row = await breakglass.liveGrant(grantKey(id));
  if (!row) return false;
  //grant only works from the exact address that redeemed it
  return row.ip === ipText;
}

async function sweepGrants() {
  await breakglass.sweepGrants();
}

// ---------------------------------------------------------------- break glass (in case of emergency)

function hashUuid(uuid) {
  return crypto.createHash('sha256').update(String(uuid).toLowerCase()).digest('hex');
}

function newKeyUuid() {
  const uuid = crypto.randomUUID();
  return { uuid, hash: hashUuid(uuid), hint: uuid.slice(0, 8) };
}

async function redeem(uuid, ipText, userAgent) {
  if (!db.settings.getBool('breakglass_enabled')) {
    return { ok: false, error: 'break glass access is switched off' };
  }
  if (!UUID_RE.test(String(uuid || '').trim())) {
    return { ok: false, error: 'that key is not valid' };
  }

  const hash = hashUuid(String(uuid).trim());
  const row = await breakglass.keyByHash(hash);

  // one message for every failure, no probing for live keys
  const nope = { ok: false, error: 'that key is not valid' };
  if (!row) return nope;
  if (row.revoked) return nope;
  if (row.expires_at && new Date(row.expires_at) < new Date()) return nope;
  if (row.max_uses > 0 && row.uses >= row.max_uses) return nope;

  // burn a use. the WHERE clause stops two people racing for the last one
  if (!(await breakglass.burnUse(row.id, ipText))) return nope;

  const minutes = row.grant_minutes || db.settings.getInt('breakglass_grant_minutes', 60);
  const grantId = crypto.randomBytes(32).toString('hex');
  await breakglass.createGrant({ key: grantKey(grantId), keyId: row.id, ip: ipText, userAgent: String(userAgent || '').slice(0, 255), minutes });

  log.warn(`break glass key "${row.label}" was used from ${ipText}`);
  return { ok: true, grantId, minutes, label: row.label, keyId: row.id };
}

module.exports = {
  GRANT_COOKIE,
  UUID_RE,
  parseIp,
  parseCidr,
  cidrContains,
  validCidr,
  normalizeCidr,
  loadAcl,
  invalidateAcl,
  ipAllowed,
  loadRegistryAcl,
  invalidateRegistryAcl,
  registryAllowed,
  loadFeeds,
  invalidateFeeds,
  registryNetworkCount,
  mergeRanges,
  inRanges,
  hasGrant,
  sweepGrants,
  hashUuid,
  newKeyUuid,
  redeem
};
