// Cooling off. brand new versions wait a while before anyone gets them.
// Author: Tim Rice
// hijacked releases tend to get spotted and pulled within days, so a version published an hour
// ago is left out of metadata and refused by name until it has aged. a pinned allow rule skips the wait

const db = require('../db');

const MAX_HOURS = 8760;
const HOUR = 3600000;

function hours() {
  const n = parseInt(db.settings.get('cooloff_hours'), 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, MAX_HOURS) : 0;
}

function enabled() {
  return hours() > 0 && !db.settings.getBool('audit_mode');
}

// no publish time: wave it through (default) or hold it back like a new one
function unknownHolds() {
  return db.settings.get('cooloff_unknown') === 'hold';
}

// * only, same as the rule patterns. case folded, npm and pypi names are
function glob(pattern, text) {
  const p = String(pattern).toLowerCase();
  const t = String(text).toLowerCase();
  let i = 0;
  let j = 0;
  let star = -1;
  let mark = 0;
  while (j < t.length) {
    if (i < p.length && p[i] === '*') {
      star = i;
      i += 1;
      mark = j;
    } else if (i < p.length && p[i] === t[j]) {
      i += 1;
      j += 1;
    } else if (star !== -1) {
      i = star + 1;
      mark += 1;
      j = mark;
    } else {
      return false;
    }
  }
  while (i < p.length && p[i] === '*') i += 1;
  return i === p.length;
}

function exemptPatterns() {
  return String(db.settings.get('cooloff_exempt') || '')
    .split(/[\n,]+/)
    .map((s) => s.replace(/#.*$/, '').trim())
    .filter(Boolean)
    .slice(0, 500);
}

function exempt(name) {
  return exemptPatterns().some((p) => glob(p, name));
}

// someone pinned this exact version on purpose, so they already looked at it
function pinned(verdict, version) {
  if (!verdict || !verdict.allowed || !verdict.rule || verdict.rule.kind !== 'allow') return false;
  const range = String(verdict.rule.version_range || '').trim().replace(/^(===?|==)\s*/, '');
  return !!range && range === String(version);
}

const ago = (ms) => {
  const h = ms / HOUR;
  if (h < 1) return `${Math.max(1, Math.round(ms / 60000))} minutes`;
  if (h < 48) return `${Math.round(h)} hours`;
  return `${Math.round(h / 24)} days`;
};

// null when the version may go out, else why not
function reasonFor(published, now = Date.now()) {
  const wait = hours();
  if (!wait) return null;
  const t = published ? Date.parse(published) : NaN;
  if (!Number.isFinite(t)) {
    return unknownHolds() ? `its publish time is not known, and new versions wait ${wait} hours` : null;
  }
  const age = now - t;
  if (age >= wait * HOUR) return null;
  const ready = new Date(t + wait * HOUR).toISOString().replace(/\.\d+Z$/, 'Z');
  // a publish time in the future is somebody's clock, or somebody lying. either way it waits
  return `published ${age < 0 ? 'with a time in the future' : `${ago(age)} ago`}, new versions wait ${wait} hours (served from ${ready})`;
}

// ---------------------------------------------------------------- npm

// version -> reason, from a full packument's time map. empty when off or exempt
function npmExclusions(name, doc) {
  const out = new Map();
  if (!enabled() || exempt(name) || !doc || !doc.versions) return out;
  const time = doc.time && typeof doc.time === 'object' ? doc.time : {};
  const now = Date.now();
  for (const version of Object.keys(doc.versions)) {
    const why = reasonFor(time[version], now);
    if (why) out.set(version, why);
  }
  return out;
}

// ---------------------------------------------------------------- pypi

// normalized version -> earliest upload time of any of its files. the release is as old as its first file
function pypiTimes(files, releaseOf, norm) {
  const out = new Map();
  for (const f of files || []) {
    const v = releaseOf(f.filename);
    if (!v) continue;
    const t = f.uploadTime ? Date.parse(f.uploadTime) : NaN;
    if (!Number.isFinite(t)) continue;
    const key = norm(v);
    if (!out.has(key) || t < out.get(key)) out.set(key, t);
  }
  return out;
}

// the JSON API fills in releases the index page gave no times for
function mergeJsonTimes(times, releases, norm) {
  for (const [v, files] of Object.entries(releases || {})) {
    const key = norm(v);
    if (times.has(key)) continue;
    let first = NaN;
    for (const f of Array.isArray(files) ? files : []) {
      const t = Date.parse(f && (f.upload_time_iso_8601 || f.upload_time));
      if (Number.isFinite(t) && !(first <= t)) first = t;
    }
    if (Number.isFinite(first)) times.set(key, first);
  }
  return times;
}

function pypiReason(times, version, norm) {
  if (!enabled()) return null;
  const t = times.get(norm(version));
  return reasonFor(Number.isFinite(t) ? new Date(t).toISOString() : null);
}

module.exports = {
  MAX_HOURS, hours, enabled, unknownHolds, glob, exempt, exemptPatterns, pinned, reasonFor,
  npmExclusions, pypiTimes, mergeJsonTimes, pypiReason
};
