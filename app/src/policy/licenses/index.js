// Licenses. what each file is licensed under, and what the lists think of that
// Author: Tim Rice
// off: nothing. warn: npm-notice + a log line. enforce: review is held, blocked is rejected, both through quarantine

const db = require('../../db');
const spdx = require('./spdx');
const quarantine = require('../quarantine');
const log = require('../../logger');
const artifactsRepo = require('../../db/repositories/artifacts');
const holdsRepo = require('../../db/repositories/quarantine');

const MODES = ['off', 'warn', 'enforce'];
const VERDICTS = ['allowed', 'review', 'blocked'];
const MEMO_MS = 10 * 60000;
const MEMO_MAX = 2000;
const BATCH = 100;

function mode() {
  const m = String(db.settings.get('license_enforcement') || 'off');
  return MODES.includes(m) ? m : 'off';
}

// learning mode serves everything, licenses just get logged
function holding() {
  return mode() === 'enforce' && !db.settings.getBool('audit_mode');
}

let compiled = null;
let compiledKey = '';
function lists() {
  const parts = ['license_allowed', 'license_review', 'license_blocked', 'license_unlisted', 'license_unknown'].map((k) => String(db.settings.get(k) || ''));
  const key = parts.join('\u0000');
  if (!compiled || key !== compiledKey) {
    compiled = spdx.compile({ allowed: parts[0], review: parts[1], blocked: parts[2], unlisted: parts[3], unknown: parts[4] });
    compiledKey = key;
  }
  return compiled;
}

// ---------------------------------------------------------------- reading

const memo = new Map();

function transient(message) {
  const e = new Error(message);
  e.transient = true;
  return e;
}

// registry switched off and never cached: unknown for now, not written down, read again once it is back
const offline = () => !require('../../registry/npm/upstream').upstreamEnabled();
const OFFLINE_NOTE = 'the upstream registry is switched off and this metadata was never cached';

async function fetchRead(ecosystem, name, version) {
  if (ecosystem === 'npm') {
    let doc;
    try {
      ({ doc } = await require('../../registry/npm/upstream').getPackument(name, 'full'));
    } catch (err) {
      if (offline()) return { ...spdx.fromNpm(null), note: OFFLINE_NOTE, unsaved: true };
      if (err.status === 404) return spdx.fromNpm(null);
      throw transient(`the metadata for ${name} could not be read: ${err.message}`);
    }
    const meta = doc && doc.versions && doc.versions[version];
    if (!meta) return { ...spdx.fromNpm(null), note: 'that version is not in the metadata' };
    return spdx.fromNpm(meta);
  }
  if (ecosystem === 'pypi') {
    try {
      const got = await require('../../registry/pypi/upstream').getJson(name, version);
      return spdx.fromPypi(require('../../ecosystems/pypi/metadata').fromJsonInfo((got.doc && got.doc.info) || {}));
    } catch (err) {
      if (offline()) return { ...spdx.fromPypi(null), note: OFFLINE_NOTE, unsaved: true };
      // private indexes have no JSON API. that is a permanent unknown, not a hiccup
      if (err.status === 404) return { ...spdx.fromPypi(null), note: 'the registry has no JSON API to read the license from' };
      throw transient(`the metadata for ${name} could not be read: ${err.message}`);
    }
  }
  const kind = require('../../registry/kinds').get(ecosystem);
  if (kind) {
    try {
      return await kind.license(name, version);
    } catch (err) {
      if (offline()) return { ...spdx.fromText(''), note: OFFLINE_NOTE, unsaved: true };
      if (err.status === 404) return spdx.fromText('');
      throw transient(`the metadata for ${name} could not be read: ${err.message}`);
    }
  }
  return { ...spdx.fromText(''), note: 'this kind of package has no license reader' };
}

async function read(ecosystem, name, version) {
  const key = `${ecosystem}\u0000${name}\u0000${version}`;
  const hit = memo.get(key);
  if (hit && Date.now() - hit.at < MEMO_MS) return hit.read;
  const got = await fetchRead(ecosystem, name, version);
  if (got.unsaved) return got;
  if (memo.size >= MEMO_MAX) memo.delete(memo.keys().next().value);
  memo.set(key, { read: got, at: Date.now() });
  return got;
}

function fromStored(row) {
  const expression = row.license_expression;
  const tree = expression ? spdx.parse(expression).tree : null;
  return { tree: tree || null, expression: tree ? expression : null, note: row.license_note || null };
}

function judge(got) {
  const out = spdx.evaluate(got, lists());
  return { ...out, note: got.note || null };
}

// ---------------------------------------------------------------- holds

async function lift(file, noteText) {
  const rows = await holdsRepo.licenseHoldsToLift(file);
  for (const r of rows) await quarantine.resolve(r.id, 'release', 'system', noteText).catch(() => {});
  return rows.length;
}

// holds follow the verdict. a person's call beats the lists
async function apply(file, outcome) {
  const holds = await holdsRepo.licenseHoldsFor(file);
  if (holds.some((h) => h.status !== 'open' && h.resolved_by && h.resolved_by !== 'system')) return 'decided';

  if (outcome.verdict === 'allowed') {
    await lift(file, 'license is allowed now');
    return 'allowed';
  }
  const sysRejected = holds.filter((h) => h.status === 'rejected');
  const reason = `license ${outcome.expression || 'unknown'} is ${outcome.verdict}: ${outcome.reason}`.slice(0, 1000);
  if (outcome.verdict === 'review') {
    // was blocked, now only needs a look
    for (const h of sysRejected) await quarantine.resolve(h.id, 'release', 'system', 'license moved to review').catch(() => {});
    await quarantine.hold(file, { source: 'license', reason });
    return 'held';
  }
  if (sysRejected.length) return 'rejected';
  const placed = await quarantine.hold(file, { source: 'license', reason });
  await quarantine.resolve(placed.id, 'reject', 'system', reason).catch(() => {});
  return 'rejected';
}

async function save(artifactId, outcome) {
  if (!artifactId || !outcome) return;
  await artifactsRepo.saveLicense(artifactId, {
    expression: outcome.expression ? outcome.expression.slice(0, 512) : null, verdict: outcome.verdict, note: outcome.note ? String(outcome.note).slice(0, 255) : null
  });
}

// a waiver for this exact license counts as allowed for the holds. the real verdict is still what gets stored
async function effective(file, outcome) {
  if (!outcome || outcome.verdict === 'allowed') return outcome;
  const w = await require('../waivers').licenseWaived(file.ecosystem, file.packageName, file.version, outcome.expression).catch(() => null);
  return w ? { ...outcome, verdict: 'allowed', waived: { id: w.id, expires_at: w.expires_at } } : outcome;
}

// ---------------------------------------------------------------- the download gate

// null = licenses are off. { unavailable } = could not be read and enforce wants an answer first
async function gate(file) {
  const m = mode();
  if (m === 'off') return null;
  const row = await artifactsRepo.licenseFor(file);
  let got;
  if (row && row.license_checked_at) {
    got = fromStored(row);
  } else {
    try {
      got = await read(file.ecosystem, file.packageName, file.version);
    } catch (err) {
      log.warn(`license: ${file.ecosystem} ${file.packageName}@${file.version}: ${err.message}`);
      if (holding()) return { unavailable: true, reason: 'its license could not be read yet, try again in a minute' };
      return null;
    }
  }
  const outcome = judge(got);
  const counted = await effective(file, outcome);
  if (outcome.verdict !== 'allowed') {
    log.info(`license: ${file.ecosystem} ${file.packageName}@${file.version} ${outcome.expression || 'unknown'} is ${outcome.verdict}${counted.waived ? ', waived' : ''}`);
  }
  if (holding()) await apply(file, counted);
  const stored = !!(row && row.license_checked_at);
  if (row && !stored && !got.unsaved) await save(row.id, outcome).catch(() => {});
  return { ...outcome, waived: counted.waived || null, stored: stored || !!row || !!got.unsaved, warn: outcome.verdict !== 'allowed' && !counted.waived };
}

function noticeLine(label, outcome) {
  return `LICENSE: ${label} ${outcome.expression || 'has no license this registry can read'} is ${outcome.verdict}`;
}

// a license waiver changed. a file held before it was ever cached has no stored license, so reevaluate never sees it
async function rejudgeHeld(ecosystem, name) {
  if (!holding()) return;
  const held = await holdsRepo.licenseHeldFiles({ ecosystem, name });
  for (const h of held) {
    await gate({ ecosystem: h.ecosystem, packageName: h.package_name, version: h.version, filename: h.filename })
      .catch((err) => log.warn(`license: rechecking ${h.package_name}@${h.version} after a waiver change failed: ${err.message}`));
  }
}

// ---------------------------------------------------------------- background

const nap = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let job = { running: false, read: 0, failed: 0, startedAt: null, finishedAt: null };
let rerun = false;

function status() {
  return { ...job };
}

// reads files nobody has checked yet. a hiccup leaves the row for next time
async function backfill() {
  if (mode() === 'off' || job.running) return;
  job = { running: true, read: 0, failed: 0, startedAt: new Date(), finishedAt: null };
  try {
    let after = 0;
    let failures = 0;
    for (;;) {
      const rows = await artifactsRepo.uncheckedLicenses(after, BATCH);
      if (!rows.length || mode() === 'off') break;
      for (const r of rows) {
        after = r.id;
        const file = { ecosystem: r.ecosystem, packageName: r.package_name, version: r.version, filename: r.filename };
        try {
          const got = await read(r.ecosystem, r.package_name, r.version);
          if (got.unsaved) continue;
          const outcome = judge(got);
          await save(r.id, outcome);
          if (holding()) await apply(file, await effective(file, outcome));
          job.read += 1;
        } catch (err) {
          job.failed += 1;
          failures += 1;
          //upstream is down, no point hammering it
          if (failures >= 20) throw err;
        }
        await nap(10);
      }
    }
  } catch (err) {
    log.warn('license backfill stopped early', err.message);
  } finally {
    job.running = false;
    job.finishedAt = new Date();
  }
}

// lists changed. rejudge what's stored, no network
let reevaluating = null;
function reevaluate() {
  if (reevaluating) {
    rerun = true;
    return reevaluating;
  }
  reevaluating = (async () => {
    do {
      rerun = false;
      compiled = null;
      const enforcing = holding();
      let after = 0;
      for (;;) {
        const rows = await artifactsRepo.checkedLicenses(after, 500);
        if (!rows.length) break;
        for (const r of rows) {
          after = r.id;
          const outcome = judge(fromStored(r));
          const file = { ecosystem: r.ecosystem, packageName: r.package_name, version: r.version, filename: r.filename };
          if (outcome.verdict !== r.license_verdict) {
            await artifactsRepo.setLicenseVerdict(r.id, outcome.verdict);
          }
          if (enforcing && (outcome.verdict !== 'allowed' || outcome.verdict !== r.license_verdict)) await apply(file, await effective(file, outcome));
        }
      }
      if (!enforcing) {
        // not enforcing any more, so the holds licenses placed go
        const held = await holdsRepo.licenseHeldFiles();
        for (const h of held) {
          await lift({ ecosystem: h.ecosystem, packageName: h.package_name, version: h.version, filename: h.filename }, 'license enforcement is off');
        }
      }
    } while (rerun);
  })()
    .catch((err) => log.error('license re-evaluation failed', err.message))
    .finally(() => {
      reevaluating = null;
      backfill().catch(() => {});
    });
  return reevaluating;
}

async function recheck() {
  memo.clear();
  await artifactsRepo.clearLicenseChecks();
  backfill().catch(() => {});
}

async function summary() {
  const counts = await artifactsRepo.licenseCounts();
  const inUse = await artifactsRepo.licensesInUse();
  const held = await holdsRepo.licenseHoldCounts();
  return {
    mode: mode(),
    learning: db.settings.getBool('audit_mode'),
    counts: Object.fromEntries(counts.map((c) => [c.verdict || 'unchecked', Number(c.n)])),
    inUse: inUse.map((r) => ({ ...r, files: Number(r.files), packages: Number(r.packages) })),
    holds: { open: Number(held.open), rejected: Number(held.rejected) },
    job: status()
  };
}

// one-off look for Check a package
async function describe(ecosystem, name, version) {
  const got = await read(ecosystem, name, version);
  const outcome = judge(got);
  return { expression: outcome.expression, verdict: outcome.verdict, reason: outcome.reason, source: got.source, raw: got.raw, mode: mode() };
}

module.exports = {
  MODES, VERDICTS, mode, lists, read, judge, apply, save, gate, noticeLine, backfill, reevaluate, rejudgeHeld, recheck, status, summary, describe, fromStored
};
