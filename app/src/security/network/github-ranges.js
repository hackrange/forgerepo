// GitHub's published ranges (api.github.com/meta), synced onto the client allow list.
// Author: Tim Rice
// NOT proof it's your org - every github account runs from these ranges, tokens do the rest.
// a failed fetch never blocks anyone

const https = require('https');
const db = require('../../db');
const ipacl = require('./ipacl');
const feeds = require('../../db/repositories/acl-feeds');
const log = require('../../logger');
const config = require('../../config');

const FEED = 'github';
const HOST = 'api.github.com';
const PATH = '/meta';
const INSERT_BATCH = 500;

const SECTIONS = [
  {
    key: 'actions',
    label: 'Actions runners',
    note: 'GitHub hosted runners. This is the one a blocked workflow needs.'
  },
  {
    key: 'actions_macos',
    label: 'Actions runners, macOS',
    note: 'GitHub list these separately. Today they sit inside the ranges above, which is not promised.'
  },
  {
    key: 'codespaces',
    label: 'Codespaces',
    note: 'For installs run from inside a codespace rather than from a workflow.'
  }
];

const KNOWN = new Set(SECTIONS.map((s) => s.key));

// a promise not a flag, so a second caller joins in instead of seeing "already running"
let inFlight = null;

function chosenSections() {
  const raw = String(db.settings.get('registry_acl_github_sections') || '');
  const picked = raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => KNOWN.has(s));
  // junk setting = runners, that's why anyone turns this on
  return picked.length ? picked : ['actions'];
}

function enabled() {
  return db.settings.getBool('registry_acl_github');
}

//do the stored rows match the sections ticked right now?
async function storedSectionsMatch() {
  const stored = await feeds.sections(FEED);
  return stored.map((r) => r.section).sort().join(',') === chosenSections().slice().sort().join(',');
}

function fetchMeta(etag) {
  return new Promise((resolve, reject) => {
    const headers = {
      accept: 'application/vnd.github+json',
      // github refuses requests without one
      'user-agent': `ForgeRepo/${config.version}`
    };
    if (etag) headers['if-none-match'] = etag;

    const req = https.request({ host: HOST, path: PATH, method: 'GET', headers }, (res) => {
      // real doc is ~200KB, way past that isn't worth buffering
      let text = '';
      let tooBig = false;
      res.on('data', (chunk) => {
        if (tooBig) return;
        text += chunk;
        if (text.length > 8 * 1024 * 1024) {
          tooBig = true;
          req.destroy();
        }
      });
      res.on('end', () => {
        if (tooBig) return reject(new Error('the answer was far bigger than the meta document should be'));
        resolve({ code: res.statusCode, etag: res.headers.etag || null, body: text });
      });
    });
    req.setTimeout(30000, () => req.destroy(new Error('github took too long to answer')));
    req.on('error', reject);
    req.end();
  });
}

async function state() {
  const row = await feeds.state(FEED);
  return row || { feed: FEED, etag: null, synced_at: null, checked_at: null, ranges: 0, error: null };
}

async function noteError(message) {
  await feeds.noteError(FEED, String(message || '').slice(0, 255));
}

async function status() {
  const st = await state();
  const bySection = await feeds.countsBySection(FEED);
  return {
    enabled: enabled(),
    sections: SECTIONS.map((s) => ({
      ...s,
      chosen: chosenSections().includes(s.key),
      ranges: Number((bySection.find((r) => r.section === s.key) || {}).n || 0)
    })),
    ranges: Number(st.ranges || 0),
    syncedAt: st.synced_at,
    checkedAt: st.checked_at,
    error: st.error || null,
    hours: db.settings.getInt('registry_acl_github_hours', 24),
    syncing: !!inFlight
  };
}

// ---------------------------------------------------------------- the sync

// returns a result, never throws
function sync(by) {
  if (inFlight) return inFlight;
  if (!enabled()) return Promise.resolve({ ok: false, error: 'the GitHub feed is switched off' });
  inFlight = runSync(by);
  return inFlight;
}

async function runSync(by) {
  try {
    const st = await state();
    const wanted = chosenSections();
    const have = await feeds.countFor(FEED);

    // Etag covers the whole doc, not our slice. Newly ticked section + 304 = it
    // never shows up. Weird bug to chase, so only quote it if sections match
    const sameSections = await storedSectionsMatch();

    // ...and never against an empty table, a 304 there means zero ranges forever
    const answer = await fetchMeta(have > 0 && sameSections ? st.etag : null);

    if (answer.code === 304) {
      await feeds.noteChecked(FEED);
      return { ok: true, changed: false, ranges: have };
    }
    if (answer.code !== 200) {
      const why = `github answered ${answer.code}`;
      await noteError(why);
      return { ok: false, error: why };
    }

    let doc;
    try {
      doc = JSON.parse(answer.body);
    } catch (err) {
      await noteError('github sent something that was not json');
      return { ok: false, error: 'github sent something that was not json' };
    }

    const rows = [];
    const seen = new Set();
    const skipped = [];
    for (const section of wanted) {
      const list = doc[section];
      if (!Array.isArray(list)) {
        skipped.push(section);
        continue;
      }
      for (const entry of list) {
        const cidr = ipacl.normalizeCidr(entry);
        if (!cidr) continue;
        const key = `${section} ${cidr}`;
        if (seen.has(key)) continue;
        seen.add(key);
        rows.push([FEED, section, cidr, cidr.includes(':') ? 6 : 4]);
      }
    }

    // github changed something. not a reason to empty the list
    if (!rows.length) {
      const why = skipped.length
        ? `github no longer publishes ${skipped.join(', ')}`
        : 'github sent no ranges for the sections asked for';
      await noteError(why);
      return { ok: false, error: why };
    }

    // one transaction, replace not merge
    await feeds.replace(FEED, rows, answer.etag, INSERT_BATCH);

    ipacl.invalidateFeeds();
    log.info(`github ranges updated: ${rows.length} network(s) across ${wanted.join(', ')}${by ? ` (${by})` : ''}`);
    if (skipped.length) log.warn(`github no longer publishes ${skipped.join(', ')}, that section was left out`);
    return { ok: true, changed: true, ranges: rows.length, skipped };
  } catch (err) {
    await noteError(err.message).catch(() => {});
    log.error('could not fetch the github ranges', err.message);
    return { ok: false, error: err.message };
  } finally {
    inFlight = null;
  }
}

// on switch off, so a stale list isn't left matching things
async function clear() {
  await feeds.clear(FEED);
  ipacl.invalidateFeeds();
}

// hourly knock. empty table or wrong sections = due now
async function maybeSync() {
  if (!enabled() || inFlight) return;
  const hours = db.settings.getInt('registry_acl_github_hours', 24);
  if ((await feeds.countFor(FEED)) > 0 && (await storedSectionsMatch())) {
    if (!hours) return;
    const st = await state();
    const stamp = st.checked_at || st.synced_at;
    // a failed check retries next hour, not tomorrow
    if (!st.error && stamp && Date.now() - new Date(stamp).getTime() < hours * 3600000) return;
  }
  await sync('schedule');
}

module.exports = { FEED, SECTIONS, KNOWN, chosenSections, status, sync, clear, maybeSync };
