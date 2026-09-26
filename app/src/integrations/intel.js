// What the outside world says about a CVE: CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS scores.
// Author: Tim Rice
// fetched on a schedule, never on a request path, and never blocks anything by itself. an air gapped box just
// shows both feeds as not reachable. only public addresses are fetched, whatever the dns says

const db = require('../db');
const safefetch = require('../security/safefetch');
const repo = require('../db/repositories/intel');
const log = require('../logger');

const FEEDS = {
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  epss: 'https://api.first.org/data/v1/epss'
};
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_BYTES = 16 * 1024 * 1024;
const EPSS_BATCH = 100;
const EPSS_MAX = 20000;

// a promise not a flag, a second caller joins in
let inFlight = null;

function enabled() {
  return db.settings.getBool('intel_feeds_enabled');
}

function hours() {
  const n = db.settings.getInt('intel_feed_hours', 24);
  return n >= 1 ? Math.min(n, 168) : 24;
}

// eslint-disable-next-line no-control-regex -- stripping control characters is the point
const clean = (v, n) => String(v || '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim().slice(0, n) || null;

async function getJson(url) {
  const res = await safefetch.request(url, {
    headers: { accept: 'application/json', 'user-agent': 'ForgeRepo vulnerability intel' },
    timeoutMs: 60000,
    maxBytes: MAX_BYTES,
    publicOnly: true
  });
  if (!res.ok) throw new Error(`${new URL(url).host} answered ${res.status}`);
  try {
    return await res.json();
  } catch (err) {
    throw new Error(`${new URL(url).host} sent something that is not json`);
  }
}

function parseKev(doc) {
  const list = doc && Array.isArray(doc.vulnerabilities) ? doc.vulnerabilities : null;
  if (!list) throw new Error('the KEV catalog has no vulnerabilities list in it');
  const out = new Map();
  for (const v of list) {
    const cve = String((v && v.cveID) || '').trim().toUpperCase();
    if (!repo.CVE.test(cve)) continue;
    out.set(cve, {
      cve,
      added: DATE.test(String(v.dateAdded)) ? v.dateAdded : null,
      due: DATE.test(String(v.dueDate)) ? v.dueDate : null,
      ransomware: String(v.knownRansomwareCampaignUse || '').trim().toLowerCase() === 'known',
      name: clean(v.vulnerabilityName, 255)
    });
  }
  // an empty catalog is a broken download, not good news. it would unmark everything
  if (!out.size) throw new Error('the KEV catalog listed nothing usable');
  return [...out.values()];
}

// scores come as strings. anything outside 0..1 or not a number is not a score
function score(v) {
  const n = Number(v);
  return typeof v !== 'boolean' && String(v).trim() !== '' && Number.isFinite(n) && n >= 0 && n <= 1 ? Math.round(n * 100000) / 100000 : null;
}

function parseEpss(doc, asked) {
  const list = doc && Array.isArray(doc.data) ? doc.data : null;
  if (!list) throw new Error('the EPSS answer has no data list in it');
  const wanted = new Set(asked);
  const out = [];
  for (const r of list) {
    const cve = String((r && r.cve) || '').trim().toUpperCase();
    // only what was asked about, a feed does not get to write rows nobody wanted
    if (!wanted.has(cve)) continue;
    const epss = score(r.epss);
    const percentile = score(r.percentile);
    if (epss === null || percentile === null) continue;
    out.push({ cve, epss, percentile, date: DATE.test(String(r.date)) ? r.date : null });
  }
  return out;
}

async function syncKev() {
  try {
    const rows = parseKev(await getJson(FEEDS.kev));
    await repo.replaceKev(rows);
    await repo.noteFeed('kev', { ok: true, entries: rows.length });
    return { ok: true, entries: rows.length };
  } catch (err) {
    log.warn('the KEV catalog could not be fetched', err.message);
    await repo.noteFeed('kev', { ok: false, error: err.message });
    return { ok: false, error: err.message };
  }
}

async function syncEpss() {
  try {
    const cves = await repo.knownCves(EPSS_MAX);
    // nothing to ask about is not a fetch. the page keeps saying never rather than pretending it went out
    if (!cves.length) {
      await repo.noteFeed('epss', { idle: true });
      return { ok: true, entries: 0, asked: 0 };
    }
    let saved = 0;
    for (let i = 0; i < cves.length; i += EPSS_BATCH) {
      const batch = cves.slice(i, i + EPSS_BATCH);
      const url = `${FEEDS.epss}?cve=${batch.map(encodeURIComponent).join(',')}`;
      const rows = parseEpss(await getJson(url), batch);
      await repo.saveEpss(rows);
      saved += rows.length;
    }
    await repo.noteFeed('epss', { ok: true, entries: saved });
    return { ok: true, entries: saved, asked: cves.length };
  } catch (err) {
    log.warn('EPSS scores could not be fetched', err.message);
    await repo.noteFeed('epss', { ok: false, error: err.message });
    return { ok: false, error: err.message };
  }
}

function sync(who) {
  if (!inFlight) {
    inFlight = (async () => {
      const kev = await syncKev();
      const epss = await syncEpss();
      log.info(`vulnerability intel refreshed (${who || 'schedule'}): KEV ${kev.ok ? `${kev.entries} listed` : 'failed'}, EPSS ${epss.ok ? `${epss.entries} scored` : 'failed'}`);
      return { kev, epss };
    })().finally(() => { inFlight = null; });
  }
  return inFlight;
}

// hourly job: a feed whose last check is older than the setting gets another go. a failure retries next hour
async function maybeSync() {
  if (!enabled() || inFlight) return null;
  const states = new Map((await repo.feedStates()).map((s) => [s.feed, s]));
  const due = ['kev', 'epss'].some((f) => {
    const s = states.get(f);
    const stamp = s && (s.error ? null : s.checked_at);
    return !stamp || Date.now() - new Date(stamp).getTime() >= hours() * 3600000;
  });
  return due ? sync('schedule') : null;
}

const splitCves = (text) => [...new Set(String(text || '').split(',').map((c) => c.trim().toUpperCase()).filter((c) => repo.CVE.test(c)))];

// what a finding row or an event wants to say, from the intel rows of its CVEs
function combine(rows) {
  const kevRows = rows.filter((r) => Number(r.kev) === 1);
  const scored = rows.filter((r) => r.epss !== null && r.epss !== undefined);
  const top = scored.sort((a, b) => Number(b.epss) - Number(a.epss))[0];
  return {
    kev: kevRows.length > 0,
    kevDue: kevRows.map((r) => r.kev_due).filter(Boolean).map(String).sort()[0] || null,
    ransomware: kevRows.some((r) => Number(r.kev_ransomware) === 1),
    epss: top ? Number(top.epss) : null,
    percentile: top ? Number(top.epss_percentile) : null
  };
}

async function summarize(cvesText) {
  const cves = splitCves(cvesText);
  return combine(cves.length ? await repo.forCves(cves) : []);
}

// a page of finding rows at once, one query. each row gets kev, kevDue, ransomware, epss and percentile
async function annotate(rows) {
  const all = [...new Set(rows.flatMap((r) => splitCves(r.cves)))];
  const byCve = new Map((all.length ? await repo.forCves(all) : []).map((r) => [String(r.cve).toUpperCase(), r]));
  return rows.map((row) => ({ ...row, ...combine(splitCves(row.cves).map((c) => byCve.get(c)).filter(Boolean)) }));
}

async function status() {
  return { enabled: enabled(), hours: hours(), running: !!inFlight, feeds: await repo.feedStates(), counts: await repo.counts() };
}

module.exports = { FEEDS, enabled, parseKev, parseEpss, score, syncKev, syncEpss, sync, maybeSync, summarize, annotate, status };
