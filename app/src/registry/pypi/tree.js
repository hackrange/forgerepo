// Everything a Python project drags in behind it, like a toddler with a blanket.
// Author: Tim Rice
//
// walks the JSON API's requires_dist one release at a time, same routing/cache/kill switch as everything else.
// A walk, NOT a resolver: newest allowed release, no conflict solving.

const pypi = require('./upstream');
const pypiName = require('../../ecosystems/pypi/name');
const pypiVersion = require('../../ecosystems/pypi/version');

// one PEP 508 requirement, e.g. `requests[socks]>=2.0 ; python_version >= "3.8"` or `requests @ https://...`
// null if gibberish. marker gets cut at the first ; outside quotes
function parseRequirement(text) {
  const raw = String(text || '').trim();
  if (!raw) return null;

  let cut = -1;
  let quote = null;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ';') {
      cut = i;
      break;
    }
  }
  const head = (cut >= 0 ? raw.slice(0, cut) : raw).trim();
  const marker = cut >= 0 ? raw.slice(cut + 1).trim() : '';

  const m = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?\s*(.*)$/.exec(head);
  if (!m) return null;
  const extras = (m[2] || '').split(',').map((e) => e.trim()).filter(Boolean);
  let rest = m[3].trim();

  if (rest.startsWith('@')) {
    return { name: pypiName.normalize(m[1]), extras, specifier: '', marker, url: rest.slice(1).trim() };
  }
  if (rest.startsWith('(') && rest.endsWith(')')) rest = rest.slice(1, -1).trim();
  if (rest && !pypiVersion.validSpecifierSet(rest)) return null;
  return { name: pypiName.normalize(m[1]), extras, specifier: rest, marker, url: null };
}

// a requirement only an extra asks for is optional, e.g.
// `PySocks!=1.5.7 ; extra == "socks"`, and a plain install won't pull it in
function onlyForExtra(marker) {
  return /\bextra\s*==/.test(String(marker || ''));
}

// newest allowed, has files, not yanked. no pre-release unless the range asks, like pip
function pickVersion(releases, range) {
  const candidates = Object.entries(releases || {})
    .filter(([v, files]) => pypiVersion.valid(v) && Array.isArray(files) && files.length && !files.every((f) => f && f.yanked))
    .map(([v]) => v);
  if (!candidates.length) return null;

  const wanted = String(range || '').trim();
  if (!wanted || wanted === 'latest' || wanted === '*') {
    const stable = candidates.filter((v) => !pypiVersion.isPrerelease(v));
    return pypiVersion.maxSatisfying(stable.length ? stable : candidates, '');
  }
  if (!pypiVersion.validSpecifierSet(wanted)) return null;
  return pypiVersion.maxSatisfying(candidates, wanted, { prereleases: 'auto' });
}

async function resolveTree(name, range, options) {
  const opts = { depth: 12, max: 1500, ...(options || {}) };
  const seen = new Map();
  const problems = [];
  const queue = [{ name: pypiName.normalize(name), range: range || 'latest', depth: 0, via: null, when: null }];

  while (queue.length && seen.size < opts.max) {
    const item = queue.shift();
    if (!pypiName.valid(item.name)) {
      problems.push({ name: item.name, error: 'that is not a valid project name' });
      continue;
    }

    let doc;
    try {
      doc = (await pypi.getJson(item.name)).doc;
    } catch (err) {
      problems.push({ name: item.name, error: err.message });
      continue;
    }

    const version = pickVersion(doc.releases, item.range);
    if (!version) {
      problems.push({ name: item.name, error: `nothing matches ${item.range}` });
      continue;
    }

    const key = `${item.name}==${version}`;
    if (seen.has(key)) continue;
    seen.set(key, { name: item.name, version, depth: item.depth, via: item.via, when: item.when });
    if (item.depth >= opts.depth) continue;

    let info = doc.info && doc.info.version === version ? doc.info : null;
    if (!info) {
      try {
        info = (await pypi.getJson(item.name, version)).doc.info;
      } catch (err) {
        problems.push({ name: key, error: `could not read what it needs: ${err.message}` });
        continue;
      }
    }

    for (const line of (info && info.requires_dist) || []) {
      const req = parseRequirement(line);
      if (!req) {
        problems.push({ name: key, error: `could not read the requirement "${line}"` });
        continue;
      }
      if (onlyForExtra(req.marker)) continue;
      if (req.url) {
        problems.push({ name: key, error: `${req.name} is fetched from ${req.url} rather than an index` });
        continue;
      }
      queue.push({ name: req.name, range: req.specifier || 'latest', depth: item.depth + 1, via: key, when: req.marker || null });
    }
  }

  return { packages: [...seen.values()], problems, truncated: seen.size >= opts.max };
}

module.exports = { resolveTree, parseRequirement, onlyForExtra, pickVersion };
