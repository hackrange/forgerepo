// The file review for every type after npm: PyPI, NuGet, Maven, RubyGems, CocoaPods, Swift. each judged by its own
// rules only, the way its registry would, and its pinned versions checked against the advisory feed.
// Author: Tim Rice
// findings come out shaped like the npm ones, so the page, the export and the tick boxes treat them all alike
//
// a type is described by a profile: how a name is checked and folded, and what an exact version and a range look
// like. PyPI brings its own (==1.0 is exact there), the newer types get theirs from registry/kinds.js

const db = require('../db');
const policy = require('../policy');
const cvescan = require('../cvescan');
const ecosystems = require('../ecosystems');

// a profile for one of the kinds: a valid version is exact, a valid range is a range
function forKind(id) {
  const kind = require('../registry/kinds').get(id);
  if (!kind) return null;
  const exact = (spec) => {
    const s = String(spec || '').trim();
    return s && kind.version.valid(s) ? s : null;
  };
  return {
    id,
    label: ecosystems.get(id).name,
    setting: ecosystems.get(id).setting,
    validName: (n) => kind.validName(n),
    // the rules fold names themselves, so a name is looked up the way the file spells it
    fold: (n) => n,
    // Newtonsoft.Json and newtonsoft.json are one package, and the advisory feed only knows the first
    sameName: (n) => kind.killKey(n),
    exact,
    specKind(spec) {
      const s = String(spec || '').trim();
      if (exact(s)) return 'exact';
      if (!s || s === '*') return 'range';
      return kind.version.validRange(s) ? 'range' : 'unparsable';
    },
    describe(spec) {
      const s = String(spec || '').trim();
      if (exact(s)) return `exactly ${s} and nothing else`;
      if (!s || s === '*') return 'any version';
      return `versions matching ${s}`;
    },
    resolver: `the ${ecosystems.get(id).name} client`
  };
}

function accepts(adapter, version, range, options) {
  try {
    return adapter.satisfies(version, range, options);
  } catch (err) {
    return false;
  }
}

// a range against a ranged rule is only worked out as far as the exact versions the rule names
function matchRule(profile, adapter, rule, kind, spec) {
  const range = rule.version_range || '';
  const exact = profile.exact(spec);
  if (kind === 'exact') {
    // the same as the registry: an allow rule covers a pinned prerelease only when its range names one
    const allow = rule.kind === 'allow';
    if (!range) {
      if (allow && adapter.isPrerelease(exact)) return null;
      return { type: 'pinned', versions: [exact], why: `pinned version ${exact} is covered by the rule` };
    }
    return accepts(adapter, exact, range, { prereleases: allow ? 'auto' : true }) ? { type: 'pinned', versions: [exact], why: `pinned version ${exact} is inside ${range}` } : null;
  }
  if (kind !== 'range') return null;
  if (!range) return { type: 'range', versions: [], why: `the rule covers every version, and "${spec || 'any version'}" is a range ${profile.resolver} resolves later` };
  const pins = range.split('||').map((p) => profile.exact(p.trim())).filter(Boolean);
  const inside = pins.filter((p) => !spec || spec === '*' || accepts(adapter, p, spec));
  return inside.length
    ? { type: 'range', versions: inside, why: `declared range "${spec || 'any version'}" can resolve to ${inside.join(', ')}` }
    : null;
}

function ruleJson(profile, rule, hit) {
  return {
    pattern: rule.pattern,
    kind: rule.kind,
    version_range: rule.version_range || '',
    version_range_human: profile.describe(rule.version_range),
    note: rule.note || '',
    priority: rule.priority,
    match_type: hit ? hit.type : null,
    affected_versions_in_scope: hit ? hit.versions : [],
    match_explanation: hit ? hit.why : null
  };
}

function detailFor(profile, { status, kind, spec, nameKnown, candidates, atRisk, denyHits, allowHits, decision, matchType, vulnerable, mode }) {
  if (status === 'BLOCKED') {
    const first = denyHits[0] || decision;
    return (first.rule.note || 'matched a deny rule') + (matchType === 'range' ? ` -- ${first.hit.why}` : '');
  }
  if (status === 'WHITELISTED') {
    if (vulnerable) {
      return `WHITELISTED BUT VULNERABLE - also matches deny rule ${denyHits[0].rule.version_range || 'any version'}: ${denyHits[0].hit.why}`;
    }
    return (allowHits[0] && allowHits[0].rule.note) || 'matched an allow rule';
  }
  if (kind === 'unparsable') return 'the version could not be parsed, so nothing could be matched';
  if (!nameKnown) {
    return mode === 'whitelist'
      ? 'no rule mentions this package, and in whitelist mode that means it is refused'
      : 'no rule mentions this package, and in blacklist mode that means it is served';
  }
  const allowed = candidates.filter((c) => c.rule.kind === 'allow').map((c) => c.rule.version_range || 'any version');
  const denied = candidates.filter((c) => c.rule.kind === 'deny').map((c) => c.rule.version_range || 'any version');
  const bits = [];
  if (allowed.length) bits.push(`approved versions are ${allowed.join(' || ')}`);
  if (denied.length) bits.push(`blocked versions are ${denied.join(' || ')}`);
  const human = profile.describe(spec);
  let label;
  if (atRisk && !allowed.length) {
    label = `AT RISK - this package has blocked releases and no approved version at all, and "${spec}" (${human}) is simply not one of the blocked ones`;
  } else if (atRisk) {
    label = `AT RISK - this package has blocked releases, and "${spec}" (${human}) is neither blocked nor approved`;
  } else {
    label = `UNAPPROVED VERSION - the name is covered by the rules but "${spec}" (${human}) falls outside every rule range`;
  }
  return bits.length ? `${label} - ${bits.join('; ')}` : label;
}

// raw: [{ name, spec, section, file }] of one type. returns the findings and what the advisory feed was asked
async function review(profile, raw, notes) {
  if (!raw.length) return { findings: [], checked: 0, asked: 0 };
  if (profile.setting && !db.settings.getBool(profile.setting)) {
    notes.push(`${raw.length} ${profile.label} package(s) were left out, ${profile.label} is switched off on this box. Switch it on under Settings to review them`);
    return { findings: [], checked: 0, asked: 0 };
  }
  const adapter = ecosystems.adapter(profile.id);
  const mode = db.settings.get('policy_mode');
  // same order the engine decides in, only this type's, matched the way this type folds names
  const rules = (await policy.reload())
    .filter((r) => r.ecosystem === profile.id)
    .map((rule) => ({ rule, regex: policy.toRegex(adapter.rulePattern(rule.kind, rule.pattern)) }));

  const findings = [];
  const badNames = [];
  for (const item of raw) {
    const typed = String(item.name || '').trim();
    if (!profile.validName(typed)) {
      badNames.push(typed);
      continue;
    }
    const name = profile.fold(typed);
    const spec = String(item.spec || '').trim();
    const kind = profile.specKind(spec);
    const exact = profile.exact(spec);
    const candidates = rules.filter(({ rule, regex }) => regex.test(adapter.ruleName(rule.kind, name)));
    const nameKnown = candidates.length > 0;
    const matched = [];
    for (const c of candidates) {
      const hit = matchRule(profile, adapter, c.rule, kind, spec);
      if (hit) matched.push({ rule: c.rule, hit });
    }
    const decision = matched.length ? matched[0] : null;
    const denyHits = matched.filter((m) => m.rule.kind === 'deny');
    const allowHits = matched.filter((m) => m.rule.kind === 'allow');
    const status = !decision ? 'NOT_IDENTIFIED' : (decision.rule.kind === 'deny' ? 'BLOCKED' : 'WHITELISTED');
    const vulnerable = denyHits.length > 0;
    const matchType = denyHits.some((m) => m.hit.type === 'pinned') ? 'pinned' : (denyHits.length ? 'range' : null);
    const drift = status === 'NOT_IDENTIFIED' && nameKnown && kind !== 'unparsable';
    const hasBlockedReleases = candidates.some((c) => c.rule.kind === 'deny');
    const atRisk = drift && hasBlockedReleases;

    findings.push({
      ecosystem: profile.id,
      source_file: item.file,
      section: item.section,
      package: typed,
      resolved_package: name !== typed ? name : null,
      declared_version: spec,
      declared_version_human: profile.describe(spec),
      version_spec_kind: kind,
      version_is_pinned: kind === 'exact',
      pinned_version: exact,
      status,
      vulnerable,
      vulnerability_match_type: matchType,
      whitelisted_but_vulnerable: vulnerable && status === 'WHITELISTED',
      name_known_to_rules: nameKnown,
      name_known_version_drift: drift,
      package_has_blocked_releases: hasBlockedReleases,
      at_risk: atRisk,
      detail: detailFor(profile, { status, kind, spec, nameKnown, candidates, atRisk, denyHits, allowHits, decision, matchType, vulnerable, mode }),
      matched_deny_rules: denyHits.map((m) => ruleJson(profile, m.rule, m.hit)),
      matched_allow_rules: allowHits.map((m) => ruleJson(profile, m.rule, m.hit)),
      effective_rule: decision ? ruleJson(profile, decision.rule, decision.hit) : null,
      rules_covering_this_name: status === 'NOT_IDENTIFIED' && nameKnown ? candidates.map((c) => ruleJson(profile, c.rule, null)) : [],
      known_advisory: null
    });
  }
  if (badNames.length) {
    const some = [...new Set(badNames)].slice(0, 3).map((n) => `"${n.slice(0, 60)}"`).join(', ');
    notes.push(`${badNames.length} ${profile.label} entr(ies) did not have a valid package name and were left out, like ${some}`);
  }

  // pinned releases against the advisory feed, the same way the npm ones are. a type with no feed asks nothing
  const pinned = findings.filter((f) => f.version_is_pinned);
  if (!pinned.length) return { findings, checked: 0, asked: 0 };
  // the feed minds case for some types and a file can spell one package several ways, so it is asked under every
  // spelling the file uses and whichever answers counts
  const key = (f) => (profile.sameName ? profile.sameName(f.package) : f.resolved_package || f.package);
  const spellings = new Map();
  for (const f of findings) {
    if (!spellings.has(key(f))) spellings.set(key(f), new Set());
    spellings.get(key(f)).add(f.resolved_package || f.package);
  }
  const pairs = pinned.flatMap((f) => [...spellings.get(key(f))].map((name) => ({ ecosystem: profile.id, name, version: f.pinned_version })));
  const result = await cvescan.scanPairs(pairs);
  for (const note of result.notes) notes.push(`${profile.label}: ${note}`);
  for (const f of pinned) {
    const row = [...spellings.get(key(f))].map((name) => result.found.get(`${profile.id}:${name}@${f.pinned_version}`)).find(Boolean);
    if (!row) continue;
    f.known_advisory = { severity: row.severity, cves: row.cves || '', advisories: row.advisories || '', summary: row.summary || '', fixed_in: row.fixed_in || null };
  }
  return { findings, checked: result.checked, asked: result.asked };
}

module.exports = { review, forKind, matchRule };
