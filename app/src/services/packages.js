// npm packages seen: the list with today's verdicts, purging, and the bulk actions.
// Author: Tim Rice

const policy = require('../policy');
const cache = require('../registry/npm/cache');
const log = require('../logger');
const rules = require('../db/repositories/rules');
const packages = require('../db/repositories/packages');
const { audit } = require('../lib/actor');

// every row gets checked against policy as it stands now. npm has its own table, the others are what the store holds
async function list(search, paging, type = 'npm') {
  const { rows, total } = type === 'npm' ? await packages.page(search, paging) : await packages.storedPage(type, search, paging);
  const adapter = require('../ecosystems').adapter(type);
  for (const row of rows) {
    // SUMs come back from the driver as strings
    for (const k of ['hits', 'files', 'cached_bytes', 'cached_versions']) if (row[k] !== undefined && row[k] !== null) row[k] = Number(row[k]);
    const verdict = await policy.checkPackage(row.name, adapter);
    row.allowed = verdict.allowed;
    row.reason = verdict.reason;
  }
  // an image counts the tags it holds completely, layers and all
  if (type === 'oci') {
    const images = require('../registry/oci/cache-state');
    for (const row of rows) {
      const tags = await require('../db').query('SELECT tag FROM oci_tags WHERE repository = ?', [row.name]);
      let whole = 0;
      for (const t of tags) if ((await images.refState(row.name, t.tag)).complete) whole += 1;
      row.cached_versions = whole;
      row.known_tags = tags.length;
    }
  }
  return { rows, total };
}

// every tag an image is known by, what the rules say about it now, and how much of it is on disk
async function tags(name) {
  const images = require('../registry/oci/cache-state');
  const gate = require('../registry/oci/gate');
  const { aliases } = await require('../registry/oci/upstream').canonicalName(name);
  const rows = await require('../db/repositories/oci-tags').forRepository(name);
  const out = [];
  for (const row of rows) {
    const held = await images.refState(name, row.tag);
    const verdict = await gate.decide(name, row.tag, undefined, { aliases });
    out.push({
      tag: row.tag, digest: row.digest, checked_at: row.checked_at, allowed: !!verdict.allowed, reason: verdict.reason || null,
      complete: held.complete, files: held.files || 0, held_files: held.heldFiles || 0
    });
  }
  return out;
}

async function versions(name) {
  const rows = await packages.versions(name);
  for (const row of rows) {
    const verdict = await policy.checkVersion(name, row.version);
    row.allowed = verdict.allowed;
    row.reason = verdict.reason;
  }
  return rows;
}

async function purge(actor, name) {
  await cache.dropPackage(name);
  await audit(actor, 'cache.purge.package', name, null);
}

// purge (drop files, keep row), forget (the row too), allow, deny.
// forgotten packages pop right back the moment someone asks. names are already checked, failures join skipped
async function bulk(actor, action, names, skipped) {
  let affected = 0;
  let freed = 0;

  for (const name of names) {
    try {
      if (action === 'purge' || action === 'forget') {
        const bytes = await packages.cachedBytes(name);
        await cache.dropPackage(name);
        freed += bytes;
        if (action === 'forget') await packages.forget(name);
      } else {
        await rules.upsert({ pattern: name, kind: action, note: 'set from the packages list', created_by: actor.name }, { note: 'values', enabled: 1 });
      }
      affected += 1;
    } catch (err) {
      log.error(`bulk ${action} failed on ${name}`, err.message);
      skipped.push({ name, error: 'could not do it' });
    }
  }

  if (action === 'allow' || action === 'deny') policy.invalidate();
  await audit(actor, `package.bulk.${action}`, `${affected} packages`, names.slice(0, 50).join(','));
  return { affected, freed };
}

async function purgeCache(actor) {
  await cache.purgeAll();
  await audit(actor, 'cache.purge.all', null, null);
}

module.exports = { list, tags, versions, purge, bulk, purgeCache };
