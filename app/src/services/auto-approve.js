// Every request is checked as soon as it arrives: its files downloaded (so cached) and scanned for malware, and its
// advisories looked up, so whoever decides sees the answer next to it. With Auto approve on, a request whose files all
// scan clean and whose worst advisory is below High is approved by itself. Anything else waits for a person, with a
// note saying why. Requested September 18, 2026. Auto approve is switched on the Dashboard, by admins only.
// Author: Tim Rice

const semver = require('semver');
const db = require('../db');
const log = require('../logger');
const auth = require('../security/auth');
const ecosystems = require('../ecosystems');
const policy = require('../policy');
const requests = require('../db/repositories/requests');

const MAX_REASON = 500;
// one request at a time: every file goes through the malware scanners, and an image can be sixty layers
const RECHECK_MINUTES = 5;
const SCAN_WAIT_MS = 10 * 60000;
const IMAGE_SCAN_WAIT_MS = 10 * 60000;
const SEVERE = ['CRITICAL', 'HIGH'];
const RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 };
const MAX_PLATFORMS = 64;
// a release can be sixty wheels and an image sixty layers: fetch and scan a few at once, and look at two requests at
// a time so one big one doesn't hold up the small ones behind it
const FILES_AT_ONCE = 4;
const REQUESTS_AT_ONCE = 2;

// run work over items, n at a time, results in order
async function pool(items, n, work) {
  const out = new Array(items.length);
  let next = 0;
  const one = async () => {
    while (next < items.length) {
      const i = next;
      next += 1;
      out[i] = await work(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, one));
  return out;
}

function on() {
  return db.settings.getBool('auto_approve');
}

function describe() {
  return {
    on: on(),
    by: db.settings.get('auto_approve_by') || '',
    at: db.settings.get('auto_approve_at') || '',
    reason: db.settings.get('auto_approve_reason') || ''
  };
}

// ---------------------------------------------------------------- the rules, no I/O, so the tests can read them

// facts about one request -> { outcome: 'approve' | 'leave' | 'wait', note }
// a person decides whenever anything is unknown, flagged, held or High and up
function decide(f) {
  if (f.stop) return { outcome: 'leave', note: f.stop };
  if (f.wait) return { outcome: 'wait', note: f.wait };
  if (!f.versions || !f.versions.length) return { outcome: 'leave', note: 'no version could be checked' };
  for (const v of f.versions) {
    if (v.killed) return { outcome: 'leave', note: `${v.version} is on the kill switch` };
    if (v.denied) return { outcome: 'leave', note: `${v.version}: ${v.denied}` };
    if (v.license) return { outcome: 'leave', note: `${v.version}: ${v.license}` };
    if (!v.files || !v.files.length) return { outcome: 'leave', note: `${v.version}: nothing to download and scan` };
    const bad = v.files.find((x) => x.malware === 'MALICIOUS' || x.malware === 'SUSPICIOUS');
    if (bad) return { outcome: 'leave', note: `${v.version}: a malware scanner says ${bad.malware} (${bad.name})` };
    const pendingScan = v.files.find((x) => x.malware === 'SCANNING');
    if (pendingScan) return { outcome: 'wait', note: `${v.version}: still being scanned for malware` };
    const unanswered = v.files.find((x) => x.malware !== 'CLEAN');
    if (unanswered) return { outcome: 'leave', note: `${v.version}: no malware answer for ${unanswered.name}${unanswered.why ? ` (${unanswered.why})` : ''}` };
    if (v.advisories === null || v.advisories === undefined) return { outcome: 'leave', note: `${v.version}: the advisory check gave no answer` };
    if (v.advisories === 'SCANNING') return { outcome: 'wait', note: `${v.version}: the image is still being scanned for vulnerable packages` };
    const worst = String(v.advisories.worst || '').toUpperCase();
    if (SEVERE.includes(worst)) {
      return { outcome: 'leave', note: `${v.version}: ${worst.toLowerCase()} advisories${v.advisories.ids ? ` (${v.advisories.ids})` : ''}, a person has to approve this` };
    }
    if (v.advisories.count && !RANK[worst]) return { outcome: 'leave', note: `${v.version}: advisories with no severity, a person has to look` };
  }
  const worst = f.versions.map((v) => String(v.advisories.worst || '').toUpperCase()).sort((a, b) => (RANK[b] || 0) - (RANK[a] || 0))[0];
  return {
    outcome: 'approve',
    note: `malware scan clean, ${worst ? `worst advisory ${worst.toLowerCase()}` : 'no advisories'}, checked ${f.versions.map((v) => v.version).join(', ')}`
  };
}

// ---------------------------------------------------------------- gathering the facts

const pinsOf = (range) => String(range || '').split('||').map((s) => s.trim().replace(/^==/, '')).filter(Boolean);

// the versions to approve: the exact ones asked for, or the newest one the range allows that is not cooling off.
// a version still cooling off is never pinned, a pin skips the wait and that would undo the protection
async function chooseVersions(eco, name, range) {
  const cooloff = require('../policy/cooloff');
  if (eco === 'oci') {
    const tags = pinsOf(range);
    if (tags.some((t) => t.includes('*'))) return { stop: 'a tag pattern names no tag to check, ask for one tag' };
    return { versions: tags.length ? tags : ['latest'] };
  }
  const exact = require('../warm').pinsFor(range, eco);
  const kind = require('../registry/kinds').get(eco);
  if (kind) {
    const listed = await kind.versions(name);
    let all = listed.versions;
    if (exact) all = all.filter((v) => exact.some((p) => kind.version.compare(p, v.version) === 0));
    else if (range) all = all.filter((v) => v.listed && kind.version.satisfies(v.version, range));
    else all = all.filter((v) => v.listed && !kind.version.isPrerelease(v.version));
    const ready = cooloff.exempt(name) ? all : all.filter((v) => !cooloff.reasonFor(v.published));
    if (!ready.length) return all.length ? { wait: 'every matching version is still cooling off' } : { stop: 'no version matches what was asked for' };
    ready.sort((a, b) => kind.version.compare(b.version, a.version));
    return { versions: (exact ? ready : [ready[0]]).map((v) => v.version) };
  }
  if (eco === 'pypi') {
    const pypi = require('../registry/pypi/upstream');
    const pypiVersion = require('../ecosystems/pypi/version');
    const { doc } = await pypi.getJson(name);
    const releases = doc.releases || {};
    const adapter = ecosystems.adapter('pypi');
    let all = Object.keys(releases).filter((v) => pypiVersion.valid(v) && (releases[v] || []).length);
    if (exact) all = all.filter((v) => exact.some((p) => pypiVersion.compare(p, v) === 0));
    else if (range) all = all.filter((v) => adapter.satisfies(v, range));
    else all = all.filter((v) => !pypiVersion.isPrerelease || !pypiVersion.isPrerelease(v));
    const times = cooloff.mergeJsonTimes(new Map(), releases, pypiVersion.normalize || ((v) => v));
    const ready = all.filter((v) => !cooloff.exempt(name) ? !cooloff.pypiReason(times, v, pypiVersion.normalize || ((x) => x)) : true);
    if (!ready.length) return all.length ? { wait: `every matching release is still cooling off` } : { stop: 'no release matches what was asked for' };
    ready.sort((a, b) => pypiVersion.compare(b, a));
    return { versions: exact ? ready : [ready[0]] };
  }
  const npm = require('../registry/npm/upstream');
  const { doc } = await npm.getPackument(name, 'full');
  let all = Object.keys(doc.versions || {}).filter((v) => semver.valid(v));
  if (exact) all = all.filter((v) => exact.includes(v));
  else if (range) all = all.filter((v) => { try { return semver.satisfies(v, range); } catch (err) { return false; } });
  else {
    // no range: what npm would install, the latest tag, unless it is still cooling off
    const latest = doc['dist-tags'] && doc['dist-tags'].latest;
    all = all.filter((v) => !semver.prerelease(v) && (!latest || semver.lte(v, latest)));
  }
  const cooling = cooloff.npmExclusions(name, doc);
  const ready = all.filter((v) => !cooling.has(v));
  if (!ready.length) return all.length ? { wait: `${cooling.get(all[0]) || 'every matching version is still cooling off'}` } : { stop: 'no version matches what was asked for' };
  ready.sort(semver.rcompare);
  return { versions: exact ? ready : [ready[0]], doc };
}

// what the malware scanners said about one stored file
async function malwareOf(sha256) {
  const malware = require('../malware');
  if (!malware.enabled() || !malware.activeScanners().length) return { malware: 'OFF', why: 'malware scanning is switched off' };
  const got = await malware.ensureScanned(sha256, SCAN_WAIT_MS);
  if (got === 'timeout') return { malware: 'SCANNING' };
  if (got === 'off') return { malware: 'OFF', why: 'malware scanning is switched off' };
  const rows = await db.query('SELECT scanner, status, findings FROM artifact_scans WHERE sha256 = ?', [sha256]);
  const active = new Set(malware.activeScanners().map((a) => a.id));
  const mine = rows.filter((r) => active.has(r.scanner));
  const flagged = mine.find((r) => r.status === 'MALICIOUS' || r.status === 'SUSPICIOUS');
  if (flagged) return { malware: flagged.status };
  // a blocklist miss is not a scan, it takes a real content scanner to say clean
  const content = mine.filter((r) => r.scanner !== 'blocklist');
  const failed = mine.find((r) => r.status === 'ERROR' || r.status === 'NOT_SCANNED');
  if (failed) {
    let why = '';
    try { why = String((JSON.parse(failed.findings || '[]') || [])[0] || ''); } catch (err) { why = ''; }
    return { malware: 'ERROR', why: why.slice(0, 160) };
  }
  if (!content.length) return { malware: 'OFF', why: 'no content scanner is switched on, a hash blocklist alone is not a scan' };
  return { malware: mine.every((r) => r.status === 'CLEAN') ? 'CLEAN' : 'ERROR' };
}

// npm and PyPI advisories for the chosen versions, one batch to the feed
async function advisoriesFor(eco, name, versions) {
  const cvescan = require('../cvescan');
  const pairs = versions.map((version) => ({ ecosystem: eco, name, version }));
  const scan = await cvescan.scanPairs(pairs, { max: 100 });
  if (scan.asked < pairs.length) return new Map(versions.map((v) => [v, null]));
  const out = new Map();
  for (const version of versions) {
    const hit = scan.found.get(eco === 'npm' ? `${name}@${version}` : `${eco}:${name}@${version}`);
    out.set(version, hit ? { worst: String(hit.severity || '').toUpperCase(), ids: String(hit.cves || '').split(', ').slice(0, 3).join(', '), count: 1 } : { worst: '', count: 0 });
  }
  return out;
}

async function licenseProblem(eco, name, version) {
  const licenses = require('../policy/licenses');
  if (licenses.mode() !== 'enforce') return null;
  const d = await licenses.describe(eco, name, version).catch(() => null);
  if (!d) return 'its license could not be read';
  if (d.verdict === 'blocked' || d.verdict === 'review') return `license ${d.expression || 'unknown'} is ${d.verdict === 'blocked' ? 'blocked' : 'on the review list'}`;
  return null;
}

// download (which caches it) and scan every file of one npm version
async function npmFacts(name, version, doc) {
  const npm = require('../registry/npm/upstream');
  const meta = doc.versions[version];
  await npm.getTarball(name, version, meta.dist);
  const row = await db.one("SELECT sha256, filename FROM artifacts WHERE ecosystem = 'npm' AND package_name = ? AND version = ? ORDER BY id LIMIT 1", [name, version]);
  if (!row) return { files: [] };
  return { files: [{ name: row.filename, ...(await malwareOf(row.sha256)) }] };
}

async function pypiFacts(name, version) {
  const pypi = require('../registry/pypi/upstream');
  const pypiVersion = require('../ecosystems/pypi/version');
  const { doc } = await pypi.getJson(name);
  const key = Object.keys(doc.releases || {}).find((v) => pypiVersion.compare(v, version) === 0);
  const files = await pool((doc.releases[key] || []).filter((x) => x && !x.yanked).slice(0, 80), FILES_AT_ONCE, async (f) => {
    await pypi.getFile(name, f.filename, version);
    const row = await db.one("SELECT sha256 FROM artifacts WHERE ecosystem = 'pypi' AND package_name = ? AND filename = ? LIMIT 1", [name, f.filename]);
    return row ? { name: f.filename, ...(await malwareOf(row.sha256)) } : { name: f.filename, malware: 'ERROR', why: 'it was not kept, is caching switched off?' };
  });
  return { files };
}

// download (which caches it) and scan what a version of a newer type is made of: a .nupkg, a pom and a jar
async function kindFacts(eco, name, version) {
  const files = await require('../registry/kinds').get(eco).fetch(name, version);
  return { files: await pool(files, FILES_AT_ONCE, async (got) => ({ name: got.filename, ...(await malwareOf(got.sha256)) })) };
}

// an image tag: every platform image, config and layer downloaded and scanned, and what is inside it
async function imageFacts(repository, tag) {
  const images = require('../registry/oci/upstream');
  const ociName = require('../ecosystems/oci/name');
  const top = await images.getManifest(repository, tag);
  const platforms = [];
  if (Array.isArray(top.doc.manifests)) {
    for (const m of top.doc.manifests.slice(0, MAX_PLATFORMS)) {
      if (!m || !ociName.isDigest(m.digest)) continue;
      const got = await images.getManifest(repository, m.digest);
      platforms.push({ digest: m.digest, doc: got.doc, runs: !(m.platform && m.platform.os === 'unknown') });
    }
  } else platforms.push({ digest: top.digest, doc: top.doc, runs: true });
  // layers shared between platforms are one file, fetched and scanned once
  const blobs = [...new Set(platforms.flatMap((p) => [...(p.doc.config ? [p.doc.config] : []), ...(Array.isArray(p.doc.layers) ? p.doc.layers : [])]
    .map((b) => b && b.digest).filter((d) => ociName.isDigest(d))))];
  const files = await pool(blobs, FILES_AT_ONCE, async (blob) => {
    await images.getBlob(repository, blob);
    return { name: blob.slice(0, 19), ...(await malwareOf(blob.slice(7))) };
  });
  // what is inside: the image scans, counting what has a fix when the box is set to
  const scanner = require('../images/scanner');
  const runnable = platforms.filter((p) => p.runs && Array.isArray(p.doc.layers));
  const fixableOnly = db.settings.getBool('oci_scan_ignore_unfixed');
  let worst = '';
  for (const p of runnable) {
    let row = await db.one('SELECT status, severity, fixable_severity FROM image_scans WHERE repository = ? AND digest = ? ORDER BY id DESC LIMIT 1', [repository, p.digest]);
    if (!row || !['done', 'skipped', 'failed'].includes(row.status)) {
      scanner.queue(repository, p.digest, { force: false });
      const until = Date.now() + IMAGE_SCAN_WAIT_MS;
      while (Date.now() < until) {
        await new Promise((r) => setTimeout(r, 3000));
        row = await db.one('SELECT status, severity, fixable_severity FROM image_scans WHERE repository = ? AND digest = ? ORDER BY id DESC LIMIT 1', [repository, p.digest]);
        if (row && ['done', 'skipped', 'failed'].includes(row.status)) break;
      }
    }
    if (!row || !['done', 'skipped', 'failed'].includes(row.status)) return { files, advisories: 'SCANNING' };
    if (row.status === 'failed') return { files, advisories: null };
    const sev = String((fixableOnly ? row.fixable_severity : row.severity) || '').toUpperCase();
    if ((RANK[sev] || 0) > (RANK[worst] || 0)) worst = sev;
  }
  return { files, advisories: { worst, count: worst ? 1 : 0, ids: worst ? 'the Vulnerabilities page lists them' : '' } };
}

async function gather(row) {
  const eco = row.ecosystem || 'npm';
  const type = ecosystems.get(eco);
  if (!type) return { stop: `${eco} is not a package type this box knows` };
  if (type.setting && !db.settings.getBool(type.setting)) return { stop: `${type.name} is switched off in Settings` };
  if (require('../policy/mode').current() !== 'normal') return { wait: `the registry is in ${require('../policy/mode').current()} mode` };
  if (!db.settings.getBool('upstream_enabled')) return { wait: 'the upstream registry is switched off' };
  if (!db.settings.getBool('cache_tarballs')) return { stop: 'Keep tarballs on disk is off, so nothing can be kept and scanned' };
  // a newer type's request is checked under the name as the feed spells it, the advisory feed minds the case of some
  const kind = require('../registry/kinds').get(eco);
  const name = kind ? (await kind.versions(row.package_name)).id : row.package_name;
  const adapter = type.adapter;
  if (await require('../policy/private-names').isPrivate(eco, name).catch(() => false)) return { stop: 'a reserved name, publish it here instead' };
  const verdict = await policy.checkPackage(name, adapter);
  if (verdict.rule && verdict.rule.kind === 'deny') return { stop: `a deny rule names it: ${verdict.reason}` };
  if (eco !== 'oci') {
    const squat = await require('../policy/typosquat').check(eco, name).catch(() => null);
    if (squat) return { stop: `the name looks like ${squat.lookalike} (${squat.technique}), a person has to look` };
  }
  const chosen = await chooseVersions(eco, name, row.version_range);
  if (chosen.stop || chosen.wait) return chosen;
  const killswitch = require('../policy/killswitch');
  const advisories = eco === 'oci' ? null : await advisoriesFor(eco, name, chosen.versions);
  const versions = [];
  for (const version of chosen.versions) {
    const v = { version };
    if (await killswitch.check(eco, name, version)) {
      versions.push({ ...v, killed: true });
      break;
    }
    const pinned = await policy.checkVersion(name, version, adapter);
    if (pinned.rule && pinned.rule.kind === 'deny') {
      versions.push({ ...v, denied: pinned.reason });
      break;
    }
    if (eco !== 'oci') v.license = await licenseProblem(eco, name, version);
    if (v.license) {
      versions.push(v);
      break;
    }
    if (eco === 'oci') Object.assign(v, await imageFacts(name, version));
    else {
      Object.assign(v, eco === 'pypi' ? await pypiFacts(name, version) : kind ? await kindFacts(eco, name, version) : await npmFacts(name, version, chosen.doc));
      v.advisories = advisories.get(version);
    }
    versions.push(v);
  }
  return { versions };
}

// the rule a pin writes: 4.17.21 for npm, ==2.32.3 for PyPI, the tag itself for an image
function rangeFor(eco, versions) {
  return versions.map((v) => (eco === 'pypi' ? `==${v}` : v)).join(' || ').slice(0, 128);
}

// what the approval allows. a request with no version came from a blocked install, which never says which version
// it wanted, so pinning the newest can approve one the install can't use. with Scan before serving on every later
// version is still scanned before it goes out, so the whole package is safe to allow. otherwise pin what was checked
function approvalRange(row, versions) {
  const eco = row.ecosystem || 'npm';
  if (!String(row.version_range || '').trim() && db.settings.getBool('malware_scan_before_serve')) return { range: '', whole: true };
  return { range: rangeFor(eco, versions), whole: false };
}

async function mark(id, state, note) {
  await db.query('UPDATE requests SET auto_state = ?, auto_note = ?, auto_at = NOW() WHERE id = ?', [state, String(note || '').slice(0, 500), id]);
}

const ACTOR = { id: null, name: 'auto-approve', ip: null };

async function review(row) {
  let facts;
  try {
    facts = await gather(row);
  } catch (err) {
    facts = { wait: `could not check it right now: ${String(err.message || err).slice(0, 200)}` };
  }
  const result = decide(facts);
  const fresh = await requests.byId(row.id);
  if (!fresh || fresh.status !== 'pending') return result;
  if (result.outcome === 'approve' && on()) {
    const { range, whole } = approvalRange(fresh, facts.versions.map((v) => v.version));
    const note = `auto approved: ${result.note}${whole ? ', any version (each one is scanned before it is served)' : `, pinned to ${range}`}`;
    const won = await require('./requests').claimAuto(ACTOR, fresh, note, range);
    if (won) {
      await mark(row.id, 'approved', note);
      await auth.audit(null, 'auto-approve', null, 'request.approve.auto', `${row.ecosystem || 'npm'}:${row.package_name}`, `${range || 'any version'}: ${result.note}`);
      log.info(`auto approved ${row.ecosystem || 'npm'}:${row.package_name} ${range || 'any version'}`);
    }
  } else if (result.outcome === 'approve') {
    // auto approve is off: a person decides, and sees that it came back clean
    await mark(row.id, 'clear', result.note);
  } else {
    await mark(row.id, result.outcome === 'wait' ? 'waiting' : 'flagged', result.note);
  }
  return result;
}

// ---------------------------------------------------------------- the worker

let running = false;

// which requests need a look: never checked, waiting and due, stuck mid check, or clear and auto approve is on
function dueClause() {
  return `status = 'pending' AND (auto_state IS NULL
    OR (auto_state = 'waiting' AND auto_at < NOW() - INTERVAL ${RECHECK_MINUTES} MINUTE)
    OR (auto_state = 'checking' AND auto_at < NOW() - INTERVAL 30 MINUTE)
    ${on() ? "OR auto_state = 'clear'" : ''})`;
}

// the next due request, claimed so the other worker can't take it too
async function claimNext() {
  for (let tries = 0; tries < 5; tries += 1) {
    const row = await db.one(`SELECT * FROM requests WHERE ${dueClause()} ORDER BY created_at, id LIMIT 1`);
    if (!row) return null;
    const got = await db.query(`UPDATE requests SET auto_state = 'checking', auto_note = 'checking now', auto_at = NOW() WHERE id = ? AND ${dueClause()}`, [row.id]);
    if (got.affectedRows) return row;
  }
  return null;
}

async function sweep() {
  if (running) return 0;
  running = true;
  let done = 0;
  const worker = async () => {
    for (;;) {
      const row = await claimNext();
      if (!row) return;
      await review(row).catch((err) => log.error(`auto approve could not check request ${row.id}`, err.message));
      done += 1;
    }
  };
  try {
    await Promise.all(Array.from({ length: REQUESTS_AT_ONCE }, worker));
  } catch (err) {
    log.error('auto approve sweep failed', err.message);
  } finally {
    running = false;
  }
  return done;
}

// a new request, or auto approve just switched on: look now instead of at the next tick
function nudge() {
  setImmediate(() => sweep().catch(() => {}));
}

// what the person asking is told while the check runs
function waitNote(ecosystem) {
  const how = ecosystem === 'oci' ? 'up to 30 minutes for a new image' : 'up to 10 minutes';
  return `It is being scanned for malware and checked for advisories now, which can take ${how}. ${on()
    ? 'If it comes back clean it is approved by itself, so try again later.'
    : 'An approver will see the results next to your request.'}`;
}

async function set(value, { reason, user, userId, ip }) {
  const want = Boolean(value);
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  const why = String(reason || '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim().slice(0, MAX_REASON);
  if (!why) { const e = new Error('say why, it goes to the admins and into the audit trail'); e.status = 400; throw e; }
  if (want === on()) { const e = new Error(`auto approve is already ${want ? 'on' : 'off'}`); e.status = 409; throw e; }
  const who = user ? String(user).slice(0, 64) : '';
  await db.settings.set('auto_approve_reason', why);
  await db.settings.set('auto_approve_by', who);
  await db.settings.set('auto_approve_at', new Date().toISOString().slice(0, 19).replace('T', ' '));
  await db.settings.set('auto_approve', want ? '1' : '0');
  log.warn(`auto approve ${want ? 'on' : 'off'} by ${who}: ${why}`);
  await auth.audit(userId || null, who, ip, 'auto_approve', want ? 'on' : 'off', why, { before: { auto_approve: !want }, after: { auto_approve: want } });
  if (want) nudge();
  tellAdmins(want, who, why).catch(() => {});
  return describe();
}

async function tellAdmins(want, user, reason) {
  const mail = require('../integrations/mail');
  const who = await require('../integrations/mail/malware-alerts').recipients();
  const name = db.settings.get('registry_name') || 'ForgeRepo';
  const url = db.settings.get('public_url');
  const what = want
    ? 'Pending requests are now approved by themselves when a malware scan comes back clean and nothing High or Critical is known. Everything else waits for a person.'
    : 'Requests wait for a person again.';
  const text = [`${user || 'someone'} switched auto approve ${want ? 'on' : 'off'}.`, '', `Reason: ${reason}`, '', what, url ? `\n${url}/_admin/#dash` : ''].join('\n');
  for (const u of who) {
    await mail.send({ to: u.email, subject: `[${name}] Auto approve ${want ? 'on' : 'off'}`, text, kind: 'auto-approve' })
      .catch((err) => log.warn(`could not mail ${u.username} about auto approve`, err.message));
  }
}

// the line an install refused for want of a rule gets while auto approve is on, so a pipeline log says to wait
function refusalHint(ecosystem, reason) {
  if (!on() || !db.settings.getBool('auto_request') || !/^not on the whitelist/.test(String(reason || ''))) return '';
  return ` It is being scanned and checked now, and approved by itself if it comes back clean. Try again in ${ecosystem === 'oci' ? 'up to 30 minutes' : 'up to 10 minutes'}.`;
}

module.exports = { on, describe, decide, rangeFor, approvalRange, waitNote, refusalHint, set, sweep, nudge, review, RECHECK_MINUTES };
