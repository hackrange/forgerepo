// Kill switch. the button for the morning a package turns out to be compromised.
// Author: Tim Rice
// a kill beats everything: allow rules, pins, scopes, exemptions, audit only mode. killed versions vanish
// from metadata and get refused by name, and the traffic log says who already pulled them.
// three kinds: a package (maybe some versions), one file by its sha256, or everything an advisory is recorded against

const db = require('../db');
const auth = require('../security/auth');
const kills = require('../db/repositories/killswitch');
const packages = require('../db/repositories/packages');
const pypiFiles = require('../db/repositories/pypi-files');
const accessLog = require('../db/repositories/access-log');
const log = require('../logger');
const ecosystems = require('../ecosystems');
const { httpError } = require('../lib/errors');

const KINDS = ['package', 'hash', 'advisory'];
const CACHE_MS = 5000;
const MAX_REASON = 500;
// what one hash or advisory kill can reach. far more than any real advisory, small enough to hold in memory
const MAX_COVERED = 5000;

let cache = null;
let cachedAt = 0;

function invalidate() {
  cache = null;
}

// what a kill keys on. the newer types say (a NuGet id is one package in any case, so lower case)
function normalize(ecosystem, name) {
  const n = String(name || '').trim();
  const kind = require('../registry/kinds').get(ecosystem);
  if (kind) return kind.killKey(n);
  return ecosystem === 'pypi' ? require('../ecosystems/pypi/name').normalize(n) : n;
}

// CVE-2021-44228, PYSEC-2024-1, GHSA-xxxx-xxxx-xxxx. GHSA keeps its lower case tail, the way the feed writes it
function advisoryId(raw) {
  const s = String(raw || '').trim();
  if (!/^[A-Za-z][A-Za-z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{1,62}$/.test(s)) return null;
  const cut = s.indexOf('-');
  const prefix = s.slice(0, cut).toUpperCase();
  const tail = s.slice(cut + 1);
  return `${prefix}-${prefix === 'GHSA' ? tail.toLowerCase() : tail.toUpperCase()}`;
}

const key = (...parts) => parts.join('\n');

// the files or versions a hash or advisory kill reaches right now, from what this box has seen
async function coveredFiles(entry) {
  if (entry.kind === 'hash') {
    return (await kills.filesWithDigest(entry.subject, MAX_COVERED)).map((f) => ({ ...f, byFile: true }));
  }
  if (entry.kind === 'advisory') {
    const names = await kills.advisoryNames(entry.subject);
    return kills.findingsNaming(names, MAX_COVERED);
  }
  return [];
}

async function active() {
  if (cache && Date.now() - cachedAt < CACHE_MS) return cache;
  const entries = (await kills.liveEntries()).map((e) => ({ ...e, kind: e.kind || 'package', subject: e.subject || '' }));
  const byVersion = new Map();
  const byFile = new Map();
  const hashes = new Map();
  for (const e of entries) {
    if (e.kind === 'package') continue;
    if (e.kind === 'hash') hashes.set(e.subject, e);
    for (const f of await coveredFiles(e)) {
      // one npm version is one tarball, so the version goes. a PyPI release has many files, only that one does
      if (f.byFile) byFile.set(key(f.ecosystem, f.package_name, f.filename), e);
      if (!f.byFile || f.ecosystem === 'npm') {
        const k = key(f.ecosystem, f.package_name, f.version);
        if (!byVersion.has(k)) byVersion.set(k, e);
      }
    }
  }
  cache = { entries, byVersion, byFile, hashes };
  cachedAt = Date.now();
  return cache;
}

function covers(entry, version, adapter) {
  if (!entry.version_range) return true;
  if (!version) return false;
  try {
    return adapter.satisfies(version, entry.version_range);
  } catch (err) {
    // a version the range cannot judge is not proof it is safe
    return true;
  }
}

function describe(entry) {
  if (entry.kind === 'hash') return `the file with sha256 ${entry.subject}`;
  if (entry.kind === 'advisory') return `everything recorded against ${entry.subject}`;
  return `${entry.ecosystem}:${entry.package_name}${entry.version_range ? ` ${entry.version_range}` : ''}`;
}

const refusal = (entry) => `on the kill switch since ${String(entry.created_at).slice(0, 16)}${entry.kind === 'package' ? '' : ` (${entry.subject})`}: ${entry.reason}`;

// the kill covering this package, or this exact version. null = nothing
async function check(ecosystem, name, version) {
  const n = normalize(ecosystem, name);
  const adapter = ecosystems.adapter(ecosystem);
  const { entries, byVersion } = await active();
  for (const entry of entries) {
    if (entry.kind !== 'package' || entry.ecosystem !== ecosystem || entry.package_name !== n) continue;
    if (!version && entry.version_range) continue;
    if (covers(entry, version, adapter)) return { id: entry.id, reason: refusal(entry) };
  }
  const hit = version ? byVersion.get(key(ecosystem, n, version)) : null;
  return hit ? { id: hit.id, reason: refusal(hit) } : null;
}

// one file by name, for PyPI releases where a hash kill takes a single wheel. its .metadata goes with it
async function checkFile(ecosystem, name, filename) {
  const { byFile } = await active();
  const n = normalize(ecosystem, name);
  const f = String(filename || '').replace(/\.metadata$/, '');
  const hit = byFile.get(key(ecosystem, n, f));
  return hit ? { id: hit.id, reason: refusal(hit) } : null;
}

// the bytes about to go out, whatever name they arrived under
async function checkHash(sha256) {
  const { hashes } = await active();
  const hit = hashes.get(String(sha256 || '').toLowerCase());
  return hit ? { id: hit.id, reason: refusal(hit) } : null;
}

async function anyHashKills() {
  return (await active()).hashes.size > 0;
}

// version -> reason, for trimming metadata
async function killedVersions(ecosystem, name, versions) {
  const out = new Map();
  const n = normalize(ecosystem, name);
  const { entries, byVersion } = await active();
  const mine = entries.filter((e) => e.kind === 'package' && e.ecosystem === ecosystem && e.package_name === n);
  if (!mine.length && !byVersion.size) return out;
  const adapter = ecosystems.adapter(ecosystem);
  for (const v of versions || []) {
    const hit = mine.find((e) => covers(e, v, adapter)) || byVersion.get(key(ecosystem, n, v));
    if (hit) out.set(v, refusal(hit));
  }
  return out;
}

// ---------------------------------------------------------------- cached copies

async function purge(entry) {
  const adapter = ecosystems.adapter(entry.ecosystem);
  let dropped = 0;
  if (entry.kind && entry.kind !== 'package') {
    for (const f of await coveredFiles(entry)) {
      if (f.ecosystem === 'npm') {
        await require('../registry/npm/cache').dropTarball(f.package_name, f.version);
        dropped += 1;
      } else if (f.ecosystem === 'pypi') {
        const pypi = require('../registry/pypi/upstream');
        const files = f.byFile ? [f] : (await pypiFiles.cachedFiles(f.package_name)).filter((r) => r.version === f.version);
        for (const r of files) {
          await pypi.dropFile(f.package_name, r.filename);
          dropped += 1;
        }
      } else if (f.ecosystem === 'oci') {
        // a layer by its hash, or an image an advisory is recorded against by its digest
        dropped += f.byFile
          ? await require('../storage/artifacts').forgetFile('oci', f.package_name, f.filename)
          : await require('../registry/oci/cache').dropImages(f.package_name, (ref) => ref === f.version);
      } else if (require('../registry/kinds').get(f.ecosystem)) {
        dropped += f.byFile
          ? await require('../storage/artifacts').forgetFile(f.ecosystem, f.package_name, f.filename)
          : await require('../storage/artifacts').forgetVersion(f.ecosystem, f.package_name, f.version);
      }
    }
    return dropped;
  }
  if (entry.ecosystem === 'npm') {
    const cache = require('../registry/npm/cache');
    const rows = await packages.tarballVersions(entry.package_name);
    for (const r of rows) {
      if (!covers(entry, r.version, adapter)) continue;
      await cache.dropTarball(entry.package_name, r.version);
      dropped += 1;
    }
  } else if (entry.ecosystem === 'pypi') {
    const pypi = require('../registry/pypi/upstream');
    const rows = await pypiFiles.cachedFiles(entry.package_name);
    for (const r of rows) {
      if (r.version && !covers(entry, r.version, adapter)) continue;
      await pypi.dropFile(entry.package_name, r.filename);
      dropped += 1;
    }
  } else if (entry.ecosystem === 'oci') {
    dropped += await require('../registry/oci/cache').dropImages(entry.package_name, entry.version_range ? (ref) => covers(entry, ref, adapter) : null);
  } else if (require('../registry/kinds').get(entry.ecosystem)) {
    // the files are kept under the package's own spelling, the lookup ignores case (a NuGet kill is lower case)
    for (const r of await require('../db/repositories/artifacts').cachedFiles(entry.ecosystem, entry.package_name)) {
      if (r.version && !covers(entry, r.version, adapter)) continue;
      dropped += await require('../storage/artifacts').forgetFile(entry.ecosystem, r.package_name, r.filename);
    }
  }
  return dropped;
}

// ---------------------------------------------------------------- who already has it

// the packages a kill reaches, each with the exact versions that count (null = any version the kill covers)
async function targets(entry) {
  if (!entry.kind || entry.kind === 'package') return [{ ecosystem: entry.ecosystem, name: entry.package_name, versions: null }];
  const grouped = new Map();
  for (const f of await coveredFiles(entry)) {
    const k = key(f.ecosystem, f.package_name);
    if (!grouped.has(k)) grouped.set(k, { ecosystem: f.ecosystem, name: f.package_name, versions: new Set() });
    grouped.get(k).versions.add(f.version);
  }
  // an advisory across a hundred packages still gets an answer, just not a slow one
  return [...grouped.values()].slice(0, 50);
}

async function impact(entry, days = 30) {
  const groups = new Map();
  for (const t of await targets(entry)) {
    const adapter = ecosystems.adapter(t.ecosystem);
    const rows = await accessLog.pullsFor(t.ecosystem, t.name, days);
    for (const r of rows) {
      if (t.ecosystem === 'oci') {
        // an image pull is its manifest. a layer is not a download of anything a person named, and a kill on a tag
        // covers a pull by that tag as well as by the digest it gave
        if (!r.manifest) continue;
        const refs = [r.requested, r.version].filter(Boolean);
        if (t.versions ? !refs.some((v) => t.versions.has(v)) : (entry.version_range && !refs.some((v) => covers(entry, v, adapter)))) continue;
      } else if (t.versions ? (!r.pulled_exact || !t.versions.has(r.version)) : (entry.version_range && (!r.pulled_exact || !covers(entry, r.version, adapter)))) continue;
      const k = [t.ecosystem, t.name, r.token_name, r.application, r.environment, r.ip, r.version].join('\n');
      const g = groups.get(k) || {
        ecosystem: t.ecosystem, package: t.name, token: r.token_name, application: r.application, environment: r.environment, ip: r.ip, version: r.version, downloads: 0, last: r.ts
      };
      g.downloads += 1;
      groups.set(k, g);
    }
  }
  return [...groups.values()].sort((a, b) => String(b.last).localeCompare(String(a.last))).slice(0, 500);
}

// ---------------------------------------------------------------- the button

function headline(entry) {
  if (entry.kind === 'hash') return `the file with sha256 ${entry.subject}`;
  if (entry.kind === 'advisory') return `every version recorded against ${entry.subject}`;
  const what = `${entry.package_name}${entry.version_range ? ` ${entry.version_range}` : ' (every version)'}`;
  const newer = require('../registry/kinds').get(entry.ecosystem);
  const kind = newer ? newer.label : ({ pypi: 'the PyPI project', oci: 'the image' }[entry.ecosystem] || 'the npm package');
  return `${kind} ${what}`;
}

// a CSV of kills: one mail with the count, the reason, and which of them were pulled lately
async function tellAdminsBulk(done, reason, user) {
  const mail = require('../integrations/mail');
  const who = await require('../integrations/mail/malware-alerts').recipients();
  const name = db.settings.get('registry_name') || 'ForgeRepo';
  const url = db.settings.get('public_url');
  const pulledBy = [];
  for (const k of done.slice(0, 100)) {
    const entry = await kills.byId(k.id);
    const pulled = entry ? await impact(entry).catch(() => []) : [];
    if (pulled.length) pulledBy.push(`- ${k.name}${k.range ? ` ${k.range}` : ''}: pulled by ${pulled.length} token, application or address combination(s)`);
  }
  const lines = [
    `${user || 'someone'} put ${done.length} package(s) on the kill switch from a CSV.`, '', `Reason: ${reason}`, '',
    'Each is refused to every token, application and environment, and left out of all metadata, until someone lifts it.', '',
    pulledBy.length ? 'Pulled in the last 30 days:' : `None of the first ${Math.min(done.length, 100)} shows up in the last 30 days of traffic.`,
    ...pulledBy.slice(0, 50), '',
    'Killed:', ...done.slice(0, 50).map((k) => `- ${k.ecosystem}:${k.name}${k.range ? ` ${k.range}` : ' (every version)'}`),
    done.length > 50 ? `...and ${done.length - 50} more on the portal` : ''
  ];
  if (url) lines.push('', `${url}/_admin/#killswitch`);
  for (const u of who) {
    await mail.send({ to: u.email, subject: `[${name}] Kill switch: ${done.length} packages from a CSV`, text: lines.join('\n'), kind: 'killswitch' })
      .catch((err) => log.warn(`could not mail ${u.username} about the bulk kill`, err.message));
  }
}

async function tellAdmins(entry, purged, pulled, reached) {
  const mail = require('../integrations/mail');
  const malwaremail = require('../integrations/mail/malware-alerts');
  let who;
  try {
    who = await malwaremail.recipients();
  } catch (err) {
    return;
  }
  const name = db.settings.get('registry_name') || 'ForgeRepo';
  const url = db.settings.get('public_url');
  const short = entry.kind === 'package' ? `${entry.package_name}${entry.version_range ? ` ${entry.version_range}` : ' (every version)'}` : entry.subject;
  const lines = [
    `${entry.created_by || 'someone'} put ${headline(entry)} on the kill switch.`,
    '',
    `Reason: ${entry.reason}`,
    '',
    'It is refused to every token, application and environment, and left out of all metadata, until someone lifts it.',
    entry.kind === 'hash' ? `It matches ${reached} file(s) seen so far, and any file with that hash that turns up later.` : null,
    entry.kind === 'advisory' ? `The vulnerability scan has recorded it against ${reached} version(s). Versions it matches later are covered as the scan finds them.` : null,
    purged ? `${purged} cached file(s) were deleted.` : 'No cached files were deleted.',
    '',
    pulled.length ? `Pulled in the last 30 days by ${pulled.length} token, application or address combination(s):` : 'Nothing in the traffic log shows it being pulled in the last 30 days.'
  ].filter((l) => l !== null);
  for (const p of pulled.slice(0, 20)) {
    lines.push(`- ${entry.kind === 'package' ? '' : `${p.package} `}${p.version || '?'} to ${p.token || 'no token'}${p.application ? `, ${p.application}` : ''}${p.environment ? ` in ${p.environment}` : ''} from ${p.ip || '?'} (${p.downloads}x, last ${String(p.last).slice(0, 16)})`);
  }
  if (pulled.length > 20) lines.push(`...and ${pulled.length - 20} more on the portal`);
  if (url) lines.push('', `${url}/_admin/#killswitch`);
  for (const u of who) {
    await mail.send({ to: u.email, subject: `[${name}] Kill switch: ${short}`, text: lines.join('\n'), kind: 'killswitch' })
      .catch((err) => log.warn(`could not mail ${u.username} about the kill switch`, err.message));
  }
}

// quiet: part of a bulk kill, which sends one summary instead of a mail per package
async function kill({ kind = 'package', ecosystem, packageName, versionRange, subject, reason, purgeCache, user, userId, ip, quiet }) {
  if (!KINDS.includes(kind)) throw httpError(400, 'a kill names a package, a file hash or an advisory');
  const byPackage = kind === 'package';
  const n = byPackage ? normalize(ecosystem, packageName) : '';
  const eco = byPackage ? ecosystem : '';
  const range = byPackage ? versionRange || '' : '';
  const what = byPackage ? '' : String(subject || '');
  if (kind === 'hash' && !/^[0-9a-f]{64}$/.test(what)) throw httpError(400, 'a file kill takes the sha256 of the file, 64 hex characters');
  if (kind === 'advisory' && advisoryId(what) !== what) throw httpError(400, 'that is not an advisory id');
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  const text = String(reason || '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim().slice(0, MAX_REASON);
  if (!text) throw httpError(400, 'say why, the reason goes to everyone who gets refused');
  const dupe = await kills.activeDuplicate({ kind, ecosystem: eco, name: n, range, subject: what });
  if (dupe) throw httpError(409, 'that is already on the kill switch');
  const result = await kills.create({ kind, ecosystem: eco, name: n, range, subject: what, reason: text, user: user ? String(user).slice(0, 64) : null });
  invalidate();
  const entry = await kills.byId(result.insertId);
  const reached = byPackage ? null : (await coveredFiles(entry)).length;
  let purged = 0;
  if (purgeCache) {
    purged = await purge(entry).catch((err) => {
      log.error(`kill switch purge of ${describe(entry)} failed`, err.message);
      return 0;
    });
    await kills.setPurged(entry.id, purged);
  }
  log.error(`kill switch: ${describe(entry)} killed by ${user}: ${text}`);
  await auth.audit(userId || null, user, ip, 'killswitch.kill', describe(entry).slice(0, 255),
    `${text}${reached === null ? '' : `, covers ${reached} known`}${purgeCache ? `, ${purged} cached file(s) deleted` : ''}`,
    { after: { status: 'active', kind, ecosystem: eco, package: n, version_range: range, subject: what, reason: text, purged_files: purged } });
  if (quiet) return { ...entry, purged_files: purged, covers: reached };
  const pulled = await impact(entry).catch(() => []);
  tellAdmins(entry, purged, pulled, reached).catch(() => {});
  return { ...entry, purged_files: purged, pulled: pulled.length, covers: reached };
}

async function lift(id, user, note, ip, userId) {
  const entry = await kills.byId(id);
  if (!entry) throw httpError(404, 'there is no such kill');
  if (entry.status !== 'active') throw httpError(409, 'that kill has already been lifted');
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  const why = String(note || '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim().slice(0, MAX_REASON) || null;
  const done = await kills.lift(id, { user: user ? String(user).slice(0, 64) : null, note: why });
  if (done !== 1) throw httpError(409, 'someone else just lifted that');
  invalidate();
  log.warn(`kill switch: ${describe(entry)} lifted by ${user}`);
  await auth.audit(userId || null, user, ip, 'killswitch.lift', describe(entry).slice(0, 255), why, { before: { status: 'active' }, after: { status: 'lifted' } });
  return kills.byId(id);
}

module.exports = {
  tellAdminsBulk, KINDS, MAX_REASON, MAX_COVERED, normalize, advisoryId, active, check, checkFile, checkHash, anyHashKills, killedVersions,
  covers, coveredFiles, describe, purge, impact, kill, lift, invalidate
};
