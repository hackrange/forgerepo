// The numbers behind the dashboard page.
// Author: Tim Rice
// slow queries for numbers that barely move, so cached in memory

const db = require('./db');
const cache = require('./registry/npm/cache');
const upstream = require('./registry/npm/upstream');
const upstreams = require('./registry/shared/upstreams');
const cards = require('./db/repositories/dashboard-cards');

let entry = null;

function ttlMs() {
  return db.settings.getInt('dashboard_cache_minutes', 30) * 60 * 1000;
}

function invalidate() {
  entry = null;
}

async function compute() {
  const [rules, pkgs, pending, denies, allows, cacheInfo, integrityOpen, quarantineOpen, malwareFlagged] = await Promise.all([
    db.one("SELECT SUM(kind='allow') AS allows, SUM(kind='deny') AS denies FROM rules WHERE enabled = 1"),
    db.one('SELECT COUNT(*) AS n FROM packages'),
    db.one("SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'"),
    db.one("SELECT COUNT(*) AS n FROM access_log WHERE action = 'deny' AND ts > DATE_SUB(NOW(), INTERVAL 1 DAY)"),
    db.one("SELECT COUNT(*) AS n FROM access_log WHERE action = 'allow' AND ts > DATE_SUB(NOW(), INTERVAL 1 DAY)"),
    cache.stats(),
    db.one("SELECT COUNT(*) AS n FROM integrity_events WHERE status = 'open'"),
    db.one("SELECT COUNT(*) AS n FROM quarantine_holds WHERE status = 'open'"),
    db.one("SELECT COUNT(DISTINCT sha256) AS n FROM artifact_scans WHERE status IN ('MALICIOUS', 'SUSPICIOUS')")
  ]);

  // clearing stamps a time (per name or global), neither touches the log.
  // blocked again = back on the list
  const since = db.settings.get('blocked_cleared_at') || '1970-01-01 00:00:00';
  const topBlocked = await db.query(
    `SELECT a.package_name, COUNT(*) AS n
       FROM access_log a
       LEFT JOIN cleared_packages c ON c.name = a.package_name
      WHERE a.action = 'deny'
        AND a.package_name IS NOT NULL
        AND a.ts > DATE_SUB(NOW(), INTERVAL 7 DAY)
        AND a.ts > ?
        AND (c.name IS NULL OR a.ts > c.cleared_at)
      GROUP BY a.package_name ORDER BY n DESC LIMIT 10`,
    [since]
  );
  const topPackages = await db.query(
    'SELECT name, hits, blocked_hits, last_access FROM packages ORDER BY hits DESC LIMIT 10'
  );
  // sums come back from the database as text, the page and the api want numbers
  const topApplications = (await cards.topApplications(7))
    .map((a) => ({ ...a, requests: num(a.requests), packages: num(a.packages), blocked: num(a.blocked) }));

  return {
    policyMode: db.settings.get('policy_mode'),
    auditMode: db.settings.getBool('audit_mode'),
    requireAuth: db.settings.getBool('require_auth'),
    aclEnabled: db.settings.getBool('acl_enabled'),
    upstream: await upstream.upstreamBase(),
    upstreamCount: (await upstreams.all()).filter((u) => u.enabled).length,
    allowRules: Number(rules.allows || 0),
    denyRules: Number(rules.denies || 0),
    packages: Number(pkgs.n),
    pendingRequests: Number(pending.n),
    integrityOpen: Number(integrityOpen.n),
    quarantineOpen: Number(quarantineOpen.n),
    malwareFlagged: Number(malwareFlagged.n),
    malwareEnabled: db.settings.getBool('malware_scanning'),
    quarantineMode: db.settings.get('quarantine_mode') === 'strict' ? 'strict' : 'permissive',
    denies24h: Number(denies.n),
    allows24h: Number(allows.n),
    cache: cacheInfo,
    topBlocked,
    topPackages,
    topApplications,
    cards: await cardNumbers()
  };
}

// ---------------------------------------------------------------- the cards

// the daily average never reaches back further than the traffic log keeps, or 90 days
function windowDays() {
  const keep = db.settings.getInt('log_retention_days', 30);
  return keep > 0 ? Math.min(keep, 90) : 90;
}

const num = (v) => Number(v || 0);

// how far back "in use" reaches for the risky card
const RISKY_DAYS = 30;
const SEV_WEIGHT = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1 };

// known exploited beats likely beats merely severe, and more downloads breaks a tie. not a science, an order to work in
function riskScore(r) {
  return (SEV_WEIGHT[String(r.severity || '').toUpperCase()] || 0) * 10 + (r.kev ? 50 : 0) + (Number(r.epss) || 0) * 40
    + Math.min(10, Math.log10(1 + num(r.downloads)) * 3);
}

async function cardNumbers() {
  const [vuln, attempts, standing, licenses, band, integrity, waiverNums, risky] = await Promise.all([
    cards.vulnerableCounts(), cards.attemptCounts(24), cards.standingCounts(), cards.licenseCounts(), cards.bandwidth(windowDays()),
    // the shared numbers count every waiver, the route narrows them for anyone who isn't staff
    cards.integrityCounts(), cards.waiverCounts(null), cards.riskyCounts(RISKY_DAYS)
  ]);
  const tried = Object.fromEntries(cards.ATTACKS.map((k) => [k, 0]));
  for (const r of attempts) if (cards.ATTACKS.includes(r.blocked_by)) tried[r.blocked_by] = num(r.n);
  const verdict = (v) => licenses.find((r) => r.verdict === v) || {};
  const span = num(band.days.span);
  return {
    vulnerable: { packages: num(vuln.packages), versions: num(vuln.versions), serious: num(vuln.serious), kev: num(vuln.kev) },
    malicious: {
      packages: standing.malware + standing.typosquat + standing.killswitch,
      flaggedPackages: standing.malware,
      lookalikes: standing.typosquat,
      killSwitches: standing.killswitch,
      attempts24h: tried.malware + tried.typosquat + tried.killswitch,
      attemptsByCheck: tried
    },
    license: {
      blockedPackages: num(verdict('blocked').packages),
      blockedFiles: num(verdict('blocked').files),
      reviewPackages: num(verdict('review').packages),
      reviewFiles: num(verdict('review').files)
    },
    risky: { versions: num(risky.versions), applications: num(risky.applications), kev: num(risky.kev) },
    integrity: { open: num(integrity.open), packages: num(integrity.packages) },
    waivers: { ending: num(waiverNums.ending), expired: num(waiverNums.expired) },
    bandwidth: {
      pulled24h: num(band.last24.served),
      fetched24h: num(band.last24.fetched),
      pulledDailyAverage: span ? Math.round(num(band.days.served) / span) : null,
      fetchedDailyAverage: span ? Math.round(num(band.days.fetched) / span) : null,
      averageDays: span,
      // npm publish and twine upload, the bytes clients sent in
      publishing: true,
      pushed24h: num(band.last24.pushed),
      pushedDailyAverage: span ? Math.round(num(band.days.pushed) / span) : null
    }
  };
}

// the packages behind one card, the same shape whichever card it is.
// options.traffic: whether the caller may see traffic. options.waiverOwner: null for every waiver, a user id for theirs.
// left out means no traffic and no waivers, so a new caller shows nothing it shouldn't
async function list(kind, options = {}) {
  if (kind === 'vulnerable') {
    return (await cards.vulnerableList()).map((r) => ({
      ecosystem: r.ecosystem,
      package: r.package_name,
      version: r.version,
      why: `${String(r.severity || 'unrated').toLowerCase()}${r.cves ? `, ${r.cves}` : ''}`,
      extra: r.fixed_in ? `fixed in ${r.fixed_in}` : 'no fix yet',
      seen: r.last_seen
    }));
  }
  if (kind === 'license') {
    return (await cards.licenseList()).map((r) => ({
      ecosystem: r.ecosystem,
      package: r.package_name,
      version: r.version,
      why: `${r.license_verdict === 'blocked' ? 'blocked' : 'needs a review'}: ${r.license_expression || 'no license found'}`,
      extra: r.license_note || '',
      seen: r.last_seen
    }));
  }
  if (kind === 'risky') {
    const rows = await require('./integrations/intel').annotate(await cards.riskyList(RISKY_DAYS));
    return rows.map((r) => ({ ...r, score: riskScore(r) })).sort((a, b) => b.score - a.score).slice(0, cards.LIST_LIMIT).map((r) => ({
      ecosystem: r.ecosystem,
      package: r.package_name,
      version: r.version,
      why: `${String(r.severity || 'unrated').toLowerCase()}${r.kev ? ', on CISA KEV' : ''}`
        + `${r.epss !== null && r.epss !== undefined ? `, EPSS ${(r.epss * 100).toFixed(1)}%` : ''}${r.cves ? `, ${r.cves}` : ''}`,
      extra: options.traffic === true
        ? `${num(r.downloads)} by ${num(r.apps)} app(s)${r.fixed_in ? `, fixed in ${r.fixed_in}` : ''}`
        : (r.fixed_in ? `fixed in ${r.fixed_in}` : ''),
      seen: r.pulled_at
    }));
  }
  if (kind === 'integrity') {
    return (await cards.integrityList()).map((r) => ({
      ecosystem: r.ecosystem,
      package: r.package_name,
      version: r.version,
      why: `${r.kind === 'content' ? 'the bytes changed' : 'the published digest changed'}: first ${r.expected}, now ${r.observed}`,
      extra: `${num(r.occurrences)} time(s)`,
      seen: r.last_seen
    }));
  }
  if (kind === 'waivers') {
    return (await cards.waiverList(options.waiverOwner)).map((r) => ({
      ecosystem: r.ecosystem,
      package: r.package_name,
      version: r.version_range || 'every version',
      why: `${r.kind} waiver ${r.status === 'expired' || new Date(r.expires_at) <= new Date() ? 'ran out' : 'ends'} ${String(r.expires_at).slice(0, 16)}${r.subject ? ` [${r.subject}]` : ''}`,
      extra: r.reference || '',
      seen: r.expires_at
    }));
  }
  if (kind !== 'malicious') throw new Error(`no such dashboard list: ${kind}`);
  const { files, squats, kills, attempts } = await cards.maliciousList(30);
  const tries = new Map(attempts.map((a) => [`${a.ecosystem}\n${a.package_name}\n${a.blocked_by}`, num(a.attempts)]));
  const tried = (r, check) => tries.get(`${r.ecosystem}\n${r.package_name}\n${check}`) || 0;
  const rows = [
    ...files.map((r) => ({
      ecosystem: r.ecosystem, package: r.package_name, version: r.version, check: 'malware',
      why: `${String(r.status).toLowerCase()} by ${r.scanner}${r.signature ? `: ${r.signature}` : ''}`, attempts: tried(r, 'malware'), seen: r.seen
    })),
    ...squats.map((r) => ({
      ecosystem: r.ecosystem, package: r.package_name, version: '', check: 'typosquat',
      why: `looks like ${r.looks_like} (${r.technique})`, attempts: tried(r, 'typosquat'), seen: r.last_seen
    })),
    ...kills.map((r) => ({
      // a hash or advisory kill has no one package, it says what it names instead
      ecosystem: r.ecosystem || null,
      package: r.kind === 'hash' ? `file ${String(r.subject).slice(0, 16)}...` : r.kind === 'advisory' ? r.subject : r.package_name,
      version: r.kind && r.kind !== 'package' ? 'everything it reaches' : r.version_range || 'every version', check: 'killswitch',
      why: `kill switch: ${r.reason}`, attempts: tried(r, 'killswitch'), seen: r.created_at
    }))
  ];
  // dates arrive as strings, which sort just fine
  rows.sort((a, b) => String(b.seen || '').localeCompare(String(a.seen || '')));
  return rows.slice(0, cards.LIST_LIMIT).map((r) => ({ ...r, extra: `${r.attempts} in 30 days` }));
}

//cache the promise so two viewers share one run
async function stats(options) {
  const opts = options || {};
  const ttl = ttlMs();
  const now = Date.now();

  if (!opts.refresh && ttl > 0 && entry && now - entry.at < ttl) {
    const data = await entry.promise;
    return { ...data, cachedAt: new Date(entry.at).toISOString(), ageSeconds: Math.round((Date.now() - entry.at) / 1000), cacheMinutes: ttl / 60000 };
  }

  const mine = { at: now, promise: compute() };
  entry = mine;
  try {
    const data = await mine.promise;
    return { ...data, cachedAt: new Date(mine.at).toISOString(), ageSeconds: 0, cacheMinutes: ttl / 60000 };
  } catch (err) {
    // a failed run must not sit in the cache sulking for half an hour
    if (entry === mine) entry = null;
    throw err;
  }
}

// one person's own waiver card
async function waiverNumbers(ownerId) {
  const w = await cards.waiverCounts(ownerId);
  return { ending: num(w.ending), expired: num(w.expired) };
}

module.exports = { stats, invalidate, list, waiverNumbers };
