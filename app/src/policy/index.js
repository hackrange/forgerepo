// The rule engine, aka the bouncer. Decides if a package (or one version of it) gets in.
// Author: Tim Rice
//
// matching rules sorted by priority, specificity, deny before allow. first match wins, no appeals.
// nothing matched? whitelist says no, blacklist says sure.
// ranged rules only bite per version, so a ranged allow still opens the door at package level.
// name spelling + range testing come from ecosystems/, default npm

const crypto = require('crypto');
const semver = require('semver');
const db = require('../db');
const npm = require('../ecosystems/npm');
const rulesRepo = require('../db/repositories/rules');
const lifecycle = require('./lifecycle');
const pypiName = require('../ecosystems/pypi/name');
const { Glob } = require('../lib/glob');

let rules = [];
let loadedAt = 0;
let dirty = true;
// md5 of the rule rows we built from. same print = same answers, so nothing gets redone
let fingerprint = '';

// compiled patterns per ecosystem, cleared when the rules really change
const compiled = new Map();

// what the rules said about each version, per package + scope + mode. typescript has 3800 versions
// and checking them all against 10k rules on every install pinned the cpu, so ask once and remember
const verdicts = new Map();
let remembered = 0;
const MAX_REMEMBERED = 200000;

const TTL_MS = 5000;

async function reload(force) {
  if (!force && !dirty && Date.now() - loadedAt < TTL_MS) return rules;
  const rows = await rulesRepo.enabledForEngine();
  const print = crypto.createHash('md5').update(JSON.stringify(rows)).digest('hex');
  if (!force && print === fingerprint) {
    loadedAt = Date.now();
    dirty = false;
    return rules;
  }
  rules = rows.map((r) => {
    const raw = String(r.pattern);
    const app = Number(r.application_id) || 0;
    const env = Number(r.environment_id) || 0;
    return {
      ...r,
      application_id: app,
      environment_id: env,
      // a rule for one application in one environment is more specific than one for everyone
      scopeRank: (app ? 1 : 0) + (env ? 1 : 0),
      pattern: raw,
      //deny matches loosely, allow matches exactly. see ecosystems/npm.js
      regex: toRegex(npm.rulePattern(r.kind, raw)),
      weight: specificity(raw)
    };
  });
  rules.sort(compare);
  compiled.clear();
  verdicts.clear();
  remembered = 0;
  fingerprint = print;
  loadedAt = Date.now();
  dirty = false;
  return rules;
}

function invalidate() {
  dirty = true;
  // an exact allow rule also tells the typosquat check a name is legit
  try {
    require('./typosquat').invalidate();
  } catch (err) {
    // not loaded yet, nothing cached to clear
  }
}

// glob style. Only `*` is special, and yes it happily crosses the scope slash.
// used to be a regex, but five stars and a long name could tie the box up for a while
function toRegex(pattern) {
  return new Glob(pattern);
}

// This ecosystem's rules only. `requests` on npm and on PyPI are separate projects, so
// never even look at the other side's. How a name is spelled is the adapter's call
//filed by name too. a pattern with no star only ever matches its own spelling, so it goes in
// a bucket under that spelling and a lookup reads one bucket plus the globs, not all 10k rules
function indexFor(eco) {
  let idx = compiled.get(eco.id);
  if (!idx) {
    idx = { list: [], exact: new Map(), wild: [], kinds: new Set(), apps: new Set([0]), envs: new Set([0]) };
    for (const rule of rules) {
      if ((rule.ecosystem || npm.id) !== eco.id) continue;
      const text = String(eco.rulePattern(rule.kind, rule.pattern));
      const regex = eco === npm ? rule.regex : toRegex(text);
      const entry = { rule, regex, at: idx.list.length };
      idx.list.push(entry);
      idx.kinds.add(rule.kind);
      idx.apps.add(rule.application_id);
      idx.envs.add(rule.environment_id);
      if (text.includes('*')) {
        idx.wild.push(entry);
      } else {
        const key = `${rule.kind}\0${text}`;
        if (!idx.exact.has(key)) idx.exact.set(key, []);
        idx.exact.get(key).push(entry);
      }
    }
    compiled.set(eco.id, idx);
  }
  return idx;
}

// every rule that could match this name, in the full list's order. still tested one by one after,
// so this only skips rules that could never have matched anyway
function candidatesFor(eco, name) {
  const idx = indexFor(eco);
  let hits = [];
  for (const kind of idx.kinds) {
    const bucket = idx.exact.get(`${kind}\0${eco.ruleName(kind, name)}`);
    if (bucket) hits = hits.concat(bucket);
  }
  if (idx.wild.length) hits = hits.concat(idx.wild);
  return hits.sort((a, b) => a.at - b.at);
}

// exact name beats a glob, longer glob beats a shorter one
function specificity(pattern) {
  if (!pattern.includes('*')) return 1000 + pattern.length;
  return pattern.replace(/\*/g, '').length;
}

function compare(a, b) {
  if (b.priority !== a.priority) return b.priority - a.priority;
  if ((b.scopeRank || 0) !== (a.scopeRank || 0)) return (b.scopeRank || 0) - (a.scopeRank || 0);
  if (b.weight !== a.weight) return b.weight - a.weight;
  if (a.kind !== b.kind) return a.kind === 'deny' ? -1 : 1;
  return a.id - b.id;
}

function defaultDecision() {
  const mode = db.settings.get('policy_mode');
  if (mode === 'blacklist') {
    return { allowed: true, rule: null, reason: 'blacklist mode, nothing blocks it' };
  }
  return { allowed: false, rule: null, reason: 'not on the whitelist' };
}

function scopeText(rule) {
  const app = rule.application_id ? (rule.application_name || `application ${rule.application_id}`) : null;
  const env = rule.environment_id ? (rule.environment_name || `environment ${rule.environment_id}`) : null;
  if (app && env) return ` for ${app} in ${env}`;
  if (app) return ` for ${app}`;
  if (env) return ` in ${env}`;
  return '';
}

function describe(rule) {
  const range = rule.version_range ? ` ${rule.version_range}` : '';
  return `${rule.kind === 'deny' ? 'blocked by' : 'allowed by'} rule ${rule.pattern}${range}${scopeText(rule)}`;
}

const EVERYONE = Object.freeze({ app: 0, env: 0 });

// only ever the token's application and environment. nothing a client sends in a header, or anyone could pick the loose one
function scopeOf(req) {
  const id = (req && req.npmIdentity) || {};
  return { app: Number(id.applicationId) || 0, env: Number(id.environmentId) || 0 };
}

// no scope asked for = only the rules that cover everyone
function applies(rule, scope) {
  const s = scope || EVERYONE;
  return (!rule.application_id || rule.application_id === s.app) && (!rule.environment_id || rule.environment_id === s.env);
}

// every deny for this name, ranged or not. checkPackage skips ranged denies (fine for serving),
// but the review/tree walk must not offer to allow lodash while 4.17.20 is blocked
async function denyRulesFor(name, ecosystem, scope) {
  const eco = ecosystem || npm;
  await reload();
  return candidatesFor(eco, name)
    .filter(({ rule, regex }) => rule.kind === 'deny' && applies(rule, scope) && regex.test(eco.ruleName(rule.kind, name)))
    .map(({ rule }) => rule);
}

// package level check, runs before we bother fetching metadata
async function checkPackage(name, ecosystem, scope) {
  const eco = ecosystem || npm;
  await reload();
  for (const { rule, regex } of candidatesFor(eco, name)) {
    if (!applies(rule, scope)) continue;
    if (!regex.test(eco.ruleName(rule.kind, name))) continue;
    // a ranged deny can't kill the whole package, just some versions of it
    if (rule.kind === 'deny' && rule.version_range) continue;
    return { allowed: rule.kind === 'allow', rule, reason: describe(rule) };
  }
  return defaultDecision();
}

// Version level check. This is the one that filters metadata and gates tarballs
async function checkVersion(name, version, ecosystem, scope) {
  const eco = ecosystem || npm;
  await reload();
  return staged(rememberedMatch(eco, name, version, scope), eco, name, version, scope);
}

// firstMatch, asked once per package + version + scope + mode until the rules change. the stage on top
// is still asked every time, it lives in its own table
function rememberedMatch(eco, name, version, scope) {
  const s = scope || EVERYONE;
  const key = JSON.stringify([eco.id, s.app, s.env, db.settings.get('policy_mode'), name]);
  let seen = verdicts.get(key);
  if (seen) {
    //most recently used goes to the back of the line
    verdicts.delete(key);
  } else {
    seen = { list: candidatesFor(eco, name), byVersion: new Map() };
  }
  verdicts.set(key, seen);
  const v = version === undefined ? 'none' : JSON.stringify(version);
  let verdict = seen.byVersion.get(v);
  if (!verdict) {
    verdict = firstMatch(seen.list, eco, name, version, scope);
    seen.byVersion.set(v, verdict);
    remembered += 1;
    // full? forget the packages nobody asked about lately
    for (const [k, old] of verdicts) {
      if (remembered <= MAX_REMEMBERED || old === seen) break;
      remembered -= old.byVersion.size;
      verdicts.delete(k);
    }
  }
  // a copy, so nobody downstream can scribble on the remembered one
  return { ...verdict };
}

// a lifecycle stage only ever takes away, and only with enforcement on
async function staged(verdict, eco, name, version, scope) {
  if (!verdict.allowed || !version || !lifecycle.enforcing()) return verdict;
  const why = await lifecycle.refusal(eco.id, eco.id === 'pypi' ? pypiName.normalize(name) : name, version, scope);
  return why ? { allowed: false, rule: null, reason: why, lifecycle: true } : verdict;
}

// a rule nobody saved, for dry runs. sorts like the real thing, never touches the cache
function proposedRule(fields) {
  const app = Number(fields.application_id) || 0;
  const env = Number(fields.environment_id) || 0;
  const pattern = String(fields.pattern);
  return {
    id: Number.MAX_SAFE_INTEGER, ecosystem: fields.ecosystem || npm.id, pattern, kind: fields.kind,
    version_range: fields.version_range || '', application_id: app, environment_id: env,
    application_name: fields.application_name || null, environment_name: fields.environment_name || null,
    priority: Number(fields.priority) || 0, enabled: 1, proposed: true,
    scopeRank: (app ? 1 : 0) + (env ? 1 : 0), regex: toRegex(npm.rulePattern(fields.kind, pattern)), weight: specificity(pattern)
  };
}

async function checkVersionWith(extra, name, version, ecosystem, scope) {
  const eco = ecosystem || npm;
  await reload();
  if ((extra.ecosystem || npm.id) !== eco.id) return checkVersion(name, version, eco, scope);
  const regex = eco === npm ? extra.regex : toRegex(eco.rulePattern(extra.kind, extra.pattern));
  const list = [...candidatesFor(eco, name), { rule: extra, regex }].sort((a, b) => compare(a.rule, b.rule));
  return staged(firstMatch(list, eco, name, version, scope), eco, name, version, scope);
}

// an allow rule covers a prerelease only when its own range names one. an approval of the stable line must not let in a
// prerelease somebody points latest at. a deny covers every prerelease in its range, a rule is a statement about them too
function firstMatch(list, eco, name, version, scope) {
  // the allow rule that would have taken it but for being a prerelease, so a refusal can say so
  let passedOver = null;
  for (const { rule, regex } of list) {
    if (!applies(rule, scope)) continue;
    if (!regex.test(eco.ruleName(rule.kind, name))) continue;
    const allow = rule.kind === 'allow';
    if (rule.version_range) {
      if (!version) continue;
      if (!eco.satisfies(version, rule.version_range, { prereleases: allow ? 'auto' : true })) {
        if (allow && !passedOver && eco.satisfies(version, rule.version_range, { prereleases: true })) passedOver = rule;
        continue;
      }
    } else if (allow && version && eco.isPrerelease && eco.isPrerelease(version)) {
      passedOver = passedOver || rule;
      continue;
    }
    return { allowed: rule.kind === 'allow', rule, reason: describe(rule) };
  }
  const fallback = defaultDecision();
  if (fallback.allowed || !passedOver) return fallback;
  const range = passedOver.version_range ? ` ${passedOver.version_range}` : '';
  return { ...fallback, reason: `${version} is a prerelease, rule ${passedOver.pattern}${range}${scopeText(passedOver)} only allows prereleases its range names` };
}

// strips blocked versions out of a packument, fixes the dist-tags, returns a body count
async function filterPackument(name, doc, scope) {
  await reload();
  const versions = doc.versions || {};
  const kept = {};
  let removed = 0;
  // what went and why, safe resolution logs it
  const excluded = [];

  for (const [version, meta] of Object.entries(versions)) {
    const verdict = await checkVersion(name, version, undefined, scope);
    if (verdict.allowed) {
      kept[version] = meta;
    } else {
      removed += 1;
      excluded.push({ version, kind: 'rule', reason: verdict.reason });
    }
  }

  doc.versions = kept;

  const keptList = Object.keys(kept);
  const sorted = keptList.filter((v) => semver.valid(v)).sort(semver.rcompare);

  // any tag pointing at a version we dropped has to go too
  const tags = doc['dist-tags'] || {};
  const cleanTags = {};
  for (const [tag, version] of Object.entries(tags)) {
    if (kept[version]) cleanTags[tag] = version;
  }
  //npm throws a tantrum without a latest tag, so hand it the newest one we kept
  if (!cleanTags.latest && sorted.length) cleanTags.latest = sorted[0];
  // a plain install follows latest, so latest on a prerelease moves to the newest stable version still here. asking for
  // next or beta by name, or the exact prerelease, still gets it if the rules allow it
  const stable = sorted.find((v) => !semver.prerelease(v));
  if (cleanTags.latest && semver.valid(cleanTags.latest) && semver.prerelease(cleanTags.latest) && stable) cleanTags.latest = stable;
  doc['dist-tags'] = cleanTags;

  if (doc.time) {
    const time = { modified: doc.time.modified, created: doc.time.created };
    for (const v of keptList) if (doc.time[v]) time[v] = doc.time[v];
    doc.time = time;
  }

  return { doc, kept: keptList.length, removed, excluded };
}

// for jobs with no caller: allowed for someone. housekeeping must not drop what dev is allowed to use
async function allowedAnywhere(name, version, ecosystem) {
  const eco = ecosystem || npm;
  await reload();
  const { apps, envs } = indexFor(eco);
  const list = candidatesFor(eco, name);
  let first = null;
  for (const app of apps) {
    for (const env of envs) {
      const verdict = firstMatch(list, eco, name, version, { app, env });
      if (verdict.allowed) return verdict;
      if (!first) first = verdict;
    }
  }
  return first;
}

module.exports = {
  reload,
  invalidate,
  scopeOf,
  applies,
  allowedAnywhere,
  checkPackage,
  checkVersion,
  checkVersionWith,
  proposedRule,
  denyRulesFor,
  filterPackument,
  toRegex,
  specificity
};
