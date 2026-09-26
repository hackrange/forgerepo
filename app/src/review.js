// Reviews an uploaded manifest, lockfile, SBOM or inventory against the rules, each package by its own type's rules.
// Author: Tim Rice
//
// all in memory now, no temp dirs to forget
// verdicts: BLOCKED, WHITELISTED, NOT_IDENTIFIED. flags: vulnerable, at risk, drift (the actually useful bit)

const semver = require('semver');
const db = require('./db');
const policy = require('./policy');
const cvescan = require('./cvescan');
const formats = require('./manifests/formats');
const inventory = require('./manifests/inventory');
const pypiReview = require('./manifests/pypi-review');
const ecosystemReview = require('./manifests/ecosystem-review');
const ecosystems = require('./ecosystems');

// Ceilings. hitting one gets reported, never quietly applied
const LIMITS = {
  zipEntries: 4000,
  jsonFiles: 250,          //json + table files actually parsed
  fileBytes: 16 * 1024 * 1024,
  totalBytes: 128 * 1024 * 1024,
  packages: 20000
};

// ---------------------------------------------------------------- zip reading
// hand rolled on zlib. a third party unzip dep in the box that judges deps? no thanks

const zlib = require('zlib');

const EOCD_SIG = 0x06054b50;
const EOCD64_LOCATOR_SIG = 0x07064b50;
const EOCD64_SIG = 0x06064b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

function findEocd(buf) {
  // zip comment at the end can be up to 64KB, so that's how far back we scan
  const start = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= start; i -= 1) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  return -1;
}

// zip64: real numbers hide in their own record. big SBOMs do get here
function centralDirectory(buf) {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new Error('that does not look like a zip file, no end of directory record');

  let count = buf.readUInt16LE(eocd + 10);
  let size = buf.readUInt32LE(eocd + 12);
  let offset = buf.readUInt32LE(eocd + 16);

  if (offset === 0xffffffff || size === 0xffffffff || count === 0xffff) {
    const loc = eocd - 20;
    if (loc < 0 || buf.readUInt32LE(loc) !== EOCD64_LOCATOR_SIG) {
      throw new Error('that zip needs zip64 and the zip64 record is missing');
    }
    const at = Number(buf.readBigUInt64LE(loc + 8));
    if (at < 0 || at + 56 > buf.length || buf.readUInt32LE(at) !== EOCD64_SIG) {
      throw new Error('that zip has a zip64 record this cannot read');
    }
    count = Number(buf.readBigUInt64LE(at + 32));
    size = Number(buf.readBigUInt64LE(at + 40));
    offset = Number(buf.readBigUInt64LE(at + 48));
  }
  return { count, size, offset };
}

// zip64 extra field, tag 0x0001. only the 0xffffffff fields show up, in order
function zip64Extra(extra, wantSize, wantCompressed, wantOffset) {
  let i = 0;
  while (i + 4 <= extra.length) {
    const id = extra.readUInt16LE(i);
    const len = extra.readUInt16LE(i + 2);
    if (id === 0x0001) {
      const body = extra.slice(i + 4, i + 4 + len);
      let at = 0;
      const out = {};
      if (wantSize && at + 8 <= body.length) { out.size = Number(body.readBigUInt64LE(at)); at += 8; }
      if (wantCompressed && at + 8 <= body.length) { out.compressed = Number(body.readBigUInt64LE(at)); at += 8; }
      if (wantOffset && at + 8 <= body.length) { out.offset = Number(body.readBigUInt64LE(at)); at += 8; }
      return out;
    }
    i += 4 + len;
  }
  return {};
}

function wanted(name) {
  if (name.endsWith('/')) return false;
  if (name.startsWith('__MACOSX/') || name.includes('/__MACOSX/')) return false;
  if (name.split('/').pop().startsWith('._')) return false; // mac resource fork junk, thanks Finder
  const lower = name.toLowerCase();
  return lower.endsWith('.json') || lower.endsWith('.jsonc') ||
    lower.endsWith('.csv') || lower.endsWith('.tsv') || lower.endsWith('.txt') || formats.wantedName(name);
}

// every json/table file out of a zip, straight from the buffer
function readZip(buf, notes) {
  const dir = centralDirectory(buf);
  const files = [];
  let at = dir.offset;
  let total = 0;
  let looked = 0;

  for (let n = 0; n < dir.count; n += 1) {
    if (at + 46 > buf.length || buf.readUInt32LE(at) !== CENTRAL_SIG) break;
    looked += 1;
    if (looked > LIMITS.zipEntries) {
      notes.push(`the archive holds more than ${LIMITS.zipEntries} entries, the rest were not looked at`);
      break;
    }

    const method = buf.readUInt16LE(at + 10);
    let compressed = buf.readUInt32LE(at + 20);
    let size = buf.readUInt32LE(at + 24);
    const nameLen = buf.readUInt16LE(at + 28);
    const extraLen = buf.readUInt16LE(at + 30);
    const commentLen = buf.readUInt16LE(at + 32);
    let local = buf.readUInt32LE(at + 42);
    const name = buf.slice(at + 46, at + 46 + nameLen).toString('utf8');
    const extra = buf.slice(at + 46 + nameLen, at + 46 + nameLen + extraLen);
    at += 46 + nameLen + extraLen + commentLen;

    if (size === 0xffffffff || compressed === 0xffffffff || local === 0xffffffff) {
      const z = zip64Extra(extra, size === 0xffffffff, compressed === 0xffffffff, local === 0xffffffff);
      if (z.size !== undefined) size = z.size;
      if (z.compressed !== undefined) compressed = z.compressed;
      if (z.offset !== undefined) local = z.offset;
    }

    if (!wanted(name)) continue;
    if (files.length >= LIMITS.jsonFiles) {
      notes.push(`stopped after ${LIMITS.jsonFiles} json files, the archive holds more`);
      break;
    }
    if (size > LIMITS.fileBytes) {
      notes.push(`${name} is ${(size / 1048576).toFixed(1)}MB and was skipped`);
      continue;
    }
    if (total + size > LIMITS.totalBytes) {
      notes.push('stopped unpacking at the size ceiling, the archive holds more json than this reads');
      break;
    }
    if (method !== 0 && method !== 8) {
      notes.push(`${name} uses a compression method this cannot read and was skipped`);
      continue;
    }

    // local header lengths decide where data starts, not the central directory's
    if (local + 30 > buf.length || buf.readUInt32LE(local) !== LOCAL_SIG) {
      notes.push(`${name} has a broken local header and was skipped`);
      continue;
    }
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const body = buf.slice(start, start + compressed);

    let text;
    try {
      const raw = method === 0 ? body : zlib.inflateRawSync(body, { maxOutputLength: LIMITS.fileBytes });
      total += raw.length;
      text = raw.toString('utf8');
    } catch (err) {
      notes.push(`${name} could not be decompressed and was skipped`);
      continue;
    }
    files.push({ path: name, text });
  }

  if (!files.length && !notes.length) notes.push('no manifests, lockfiles, SBOMs or name and version tables were found in that archive');
  return files;
}

// ---------------------------------------------------------------- what a file declares

const DEP_SECTIONS = [
  'dependencies', 'devDependencies', 'optionalDependencies',
  'peerDependencies', 'resolutions', 'overrides'
];

const ALIAS_RE = /^npm:(@?[^@]+(?:\/[^@]+)?)@(.+)$/;
const NON_REGISTRY_RE = /^(file:|link:|portal:|workspace:|git\+|git:|github:|bitbucket:|gitlab:|https?:|ssh:|patch:|[\w.-]+\/[\w.-]+#|\.{0,2}\/)/i;

// -> { name, spec, kind }, kind = how much we can actually do with the spec
function normalizeSpec(name, spec) {
  if (typeof spec !== 'string') return { name, spec: String(spec), kind: 'invalid' };
  const s = spec.trim();
  const alias = ALIAS_RE.exec(s);
  if (alias) return { name: alias[1], spec: alias[2].trim(), kind: 'alias' };
  if (NON_REGISTRY_RE.test(s)) return { name, spec: s, kind: 'non-registry' };
  if (s === '' || s === '*' || s === 'x' || s === 'latest') return { name, spec: '*', kind: 'range' };
  if (semver.valid(s)) return { name, spec: s, kind: 'exact' };
  if (semver.validRange(s)) return { name, spec: s, kind: 'range' };
  return { name, spec: s, kind: 'unparsable' };
}

function walkLockV1(node, out, section) {
  const deps = node && node.dependencies;
  if (!deps || typeof deps !== 'object') return;
  for (const [name, info] of Object.entries(deps)) {
    if (!info || typeof info !== 'object') continue;
    if (typeof info.version === 'string' && info.version) out.push({ name, spec: info.version, section });
    walkLockV1(info, out, section);
  }
}

// CycloneDX types that are context, not dependencies
const { NOT_A_DEPENDENCY } = formats;

function extractPackages(doc) {
  const found = [];
  const kinds = [];
  // counted, not silently dropped (see the CycloneDX bit below)
  let otherEcosystems = 0;
  const otherTypes = new Set();
  let notPackages = 0;
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { entries: [], kind: null };

  // npm lockfile v2 and v3
  const pkgs = doc.packages;
  if (pkgs && typeof pkgs === 'object' && !Array.isArray(pkgs) &&
      ('lockfileVersion' in doc || Object.keys(pkgs).some((k) => k.startsWith('node_modules/')))) {
    for (const [key, info] of Object.entries(pkgs)) {
      if (!info || typeof info !== 'object' || key === '' || key === '.') continue;
      let name = info.name;
      if (!name) {
        const idx = key.lastIndexOf('node_modules/');
        name = idx >= 0 ? key.slice(idx + 'node_modules/'.length) : key;
      }
      if (name && typeof info.version === 'string' && info.version) {
        found.push({ name, spec: info.version, section: info.dev ? 'lock:dev' : 'lock:packages' });
      }
    }
    kinds.push('npm-lockfile');
  }

  // npm lockfile v1: dependencies is a nested tree, not a map of ranges
  if ('lockfileVersion' in doc && doc.dependencies && typeof doc.dependencies === 'object' &&
      !Object.values(doc.dependencies).some((v) => typeof v === 'string')) {
    const before = found.length;
    walkLockV1(doc, found, 'lock:dependencies');
    if (found.length > before && !kinds.includes('npm-lockfile')) kinds.push('npm-lockfile');
  }

  let manifestHits = 0;
  for (const section of DEP_SECTIONS) {
    const node = doc[section];
    if (!node || typeof node !== 'object' || Array.isArray(node)) continue;
    for (const [name, spec] of Object.entries(node)) {
      if (typeof spec === 'string') {
        found.push({ name, spec, section });
        manifestHits += 1;
      } else if (spec && typeof spec === 'object') {
        // overrides can nest, like {"foo": {".": "1.2.3", "bar": "2.0.0"}}
        for (const [sub, subspec] of Object.entries(spec)) {
          if (typeof subspec === 'string') {
            found.push({ name: sub === '.' ? name : sub, spec: subspec, section });
            manifestHits += 1;
          }
        }
      }
    }
  }
  if (manifestHits || (doc.name && doc.version && doc.dependencies)) kinds.push('package-manifest');

  // CycloneDX. an SBOM lists a whole estate (repos, tools, other ecosystems), not an npm tree.
  // purl decides when there is one, else the type has to be dependency-ish. skipped stuff gets counted
  const comps = doc.components;
  if (doc.bomFormat === 'CycloneDX' ||
      (Array.isArray(comps) && comps.length && comps[0] && typeof comps[0] === 'object' && 'purl' in comps[0])) {
    let hits = 0;
    const walk = (items) => {
      for (const c of items || []) {
        if (!c || typeof c !== 'object') continue;
        // some tools leave purl out and put the package url in bom-ref instead
        const ref = typeof c['bom-ref'] === 'string' && c['bom-ref'].startsWith('pkg:') ? c['bom-ref'] : '';
        const purl = String(c.purl || ref);
        let name = c.name;
        let ver = c.version;

        let eco = 'npm';
        if (purl.startsWith('pkg:')) {
          const got = formats.fromPurl(purl);
          if (!got || got.other) {
            // named its ecosystem, and it's not one this box has rules for
            otherEcosystems += 1;
            if (got && got.type) otherTypes.add(got.type);
            walk(c.components);
            continue;
          }
          eco = got.ecosystem;
          name = got.name;
          ver = ver || got.version;
        } else if (NOT_A_DEPENDENCY.has(String(c.type || '').toLowerCase())) {
          // no purl, and it's the thing being described
          notPackages += 1;
          walk(c.components);
          continue;
        } else if (c.group) {
          name = `${c.group}/${name}`;
        }

        if (name && typeof ver === 'string' && ver) {
          found.push({ ecosystem: eco, name, spec: ver, section: 'sbom:component' });
          hits += 1;
        }
        walk(c.components);
      }
    };
    walk(Array.isArray(comps) ? comps : []);
    if (hits) kinds.push('cyclonedx-sbom');
  }

  // SPDX. a purl says which ecosystem, a package with none is taken as npm like it always was
  if (Array.isArray(doc.packages) && (doc.spdxVersion || doc.SPDXID)) {
    let hits = 0;
    for (const p of doc.packages) {
      if (!p || typeof p !== 'object') continue;
      let name = p.name;
      let ver = p.versionInfo;
      let eco = 'npm';
      let elsewhere = false;
      for (const ref of Array.isArray(p.externalRefs) ? p.externalRefs : []) {
        const got = formats.fromPurl((ref && ref.referenceLocator) || '');
        if (!got) continue;
        if (got.other) {
          elsewhere = got.type || true;
          continue;
        }
        eco = got.ecosystem;
        name = got.name;
        ver = ver || got.version;
        elsewhere = false;
        break;
      }
      if (elsewhere) {
        otherEcosystems += 1;
        if (typeof elsewhere === 'string') otherTypes.add(elsewhere);
        continue;
      }
      if (name && typeof ver === 'string' && ver) {
        found.push({ ecosystem: eco, name, spec: ver, section: 'sbom:spdx-package' });
        hits += 1;
      }
    }
    if (hits) kinds.push('spdx-sbom');
  }

  // last resort: flat {name: version} map, homegrown inventories love these
  if (!kinds.length) {
    const flat = Object.entries(doc).filter(([, v]) => typeof v === 'string');
    if (flat.length && flat.length === Object.keys(doc).length &&
        flat.every(([, v]) => semver.valid(v) || semver.validRange(v))) {
      for (const [k, v] of flat) found.push({ name: k, spec: v, section: 'flat-map' });
      kinds.push('flat-version-map');
    }
  }

  if (!kinds.length) return { entries: [], kind: null, otherEcosystems, otherTypes: [...otherTypes], notPackages };

  const seen = new Set();
  const entries = [];
  for (const item of found) {
    const key = `${item.ecosystem || 'npm'}\u0000${item.name}\u0000${item.spec}\u0000${item.section}`;
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push(item);
  }
  return { entries, kind: kinds.join('+'), otherEcosystems, otherTypes: [...otherTypes], notPackages };
}

// ---------------------------------------------------------------- ranges in english

// pinned versions a range is made of, or null if it's a real range
function pinsOf(range) {
  const parts = String(range || '').split('||').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return null;
  return parts.every((p) => semver.valid(p)) ? parts : null;
}

function describeRange(range) {
  const text = String(range || '').trim();
  if (!text || text === '*') return 'any version';
  const pins = pinsOf(text);
  if (pins) {
    if (pins.length === 1) return `exactly ${pins[0]} and nothing else`;
    if (pins.length === 2) return `either ${pins[0]} or ${pins[1]} exactly, and nothing else`;
    return `any one of these ${pins.length} exact versions and nothing else: ${pins.join(', ')}`;
  }
  if (semver.valid(text)) return `exactly ${text} and nothing else`;
  const m = /^\^(\d+)\.(\d+)\.(\d+)/.exec(text);
  if (m) {
    return Number(m[1]) > 0
      ? `${text.slice(1)} and up, staying on major ${m[1]} (below ${Number(m[1]) + 1}.0.0)`
      : `${text.slice(1)} and up, staying on 0.${m[2]} (below 0.${Number(m[2]) + 1}.0), because npm treats 0.x as unstable`;
  }
  const t = /^~(\d+)\.(\d+)/.exec(text);
  if (t) return `${text.slice(1)} and up, staying on minor ${t[1]}.${t[2]} (below ${t[1]}.${Number(t[2]) + 1}.0)`;
  return `versions matching ${text}`;
}

// ---------------------------------------------------------------- matching

// Ranges that only overlap a rule are exposure, not a hit and not a pass
function matchRule(rule, declared) {
  const range = rule.version_range || '';
  if (declared.kind === 'exact') {
    // the same as the registry: an allow rule covers a pinned prerelease only when its range names one
    const allow = rule.kind === 'allow';
    let pre = false;
    try {
      pre = !!semver.prerelease(declared.spec);
    } catch (err) {
      pre = false;
    }
    if (!range) {
      if (allow && pre) return null;
      return { type: 'pinned', versions: [declared.spec], why: `pinned version ${declared.spec} is covered by the rule` };
    }
    let ok = false;
    try {
      ok = allow ? semver.satisfies(declared.spec, range) : semver.satisfies(declared.spec, range, { includePrerelease: true });
    } catch (err) {
      ok = false;
    }
    if (!ok) return null;
    return { type: 'pinned', versions: [declared.spec], why: `pinned version ${declared.spec} is inside ${range}` };
  }

  if (declared.kind !== 'range' && declared.kind !== 'alias') return null;
  if (!range) {
    return { type: 'range', versions: [], why: `the rule covers every version, and "${declared.spec}" is a range npm resolves later` };
  }
  let hit = false;
  try {
    hit = semver.intersects(declared.spec, range, { includePrerelease: true });
  } catch (err) {
    hit = false;
  }
  if (!hit) return null;

  const pins = pinsOf(range) || [];
  const inside = pins.filter((p) => {
    try {
      return semver.satisfies(p, declared.spec, { includePrerelease: true });
    } catch (err) {
      return false;
    }
  });
  return {
    type: 'range',
    versions: inside,
    why: inside.length
      ? `declared range "${declared.spec}" can resolve to ${inside.join(', ')}`
      : `declared range "${declared.spec}" overlaps the rule range ${range}`
  };
}

// same test as policy.js. deny ignores case so caps lock doesn't dodge it, allow is exact
function nameMatches(rule, name) {
  return rule.regex.test(rule.kind === 'deny' ? String(name).toLowerCase() : String(name));
}

// ---------------------------------------------------------------- the review

function ruleJson(rule, hit) {
  return {
    pattern: rule.pattern,
    kind: rule.kind,
    version_range: rule.version_range || '',
    version_range_human: describeRange(rule.version_range),
    note: rule.note || '',
    priority: rule.priority,
    match_type: hit ? hit.type : null,
    affected_versions_in_scope: hit ? hit.versions : [],
    match_explanation: hit ? hit.why : null
  };
}

// truncated vs badly written: separate fixes, and the parser can't tell. gave up at the very end = cut short
function explainJson(text, err) {
  const at = /position (\d+)/.exec(String(err.message));
  const end = text.replace(/\s+$/, '').length;
  if (at && Number(at[1]) >= end) {
    return `the file stops in the middle of a record, ${text.length} bytes in, so it is cut short rather than written wrong. ` +
      'Fetch it again and check it arrives whole: a complete document ends with a closing brace.';
  }
  return `invalid JSON: ${err.message}`;
}

// the parts of a file that are some other type, said out loud so the count is trustworthy
function otherNote(file, count, types) {
  const named = (types || []).filter(Boolean).slice(0, 6);
  return `${file}: ${count} package(s) are of a type this registry has no rules for${named.length ? ` (${named.join(', ')})` : ''}, so they were left alone`;
}

async function reviewFiles(files, options) {
  const allRules = await policy.reload();
  // npm packages are judged by npm rules only, the PyPI ones go to their own review below
  const rules = allRules.filter((r) => (r.ecosystem || 'npm') === 'npm');
  const mode = db.settings.get('policy_mode');
  const notes = options.notes || [];

  const scanned = [];
  const skipped = [];
  const unreadable = [];
  const raw = [];

  for (const file of files) {
    // Doesn't start with { or [ ? read it as a name/version table
    const body = file.text.replace(/^\uFEFF/, '');
    // yarn, pnpm, CycloneDX XML, requirements and the TOML lockfiles, before the table reader gets a go
    const other = formats.detectText(file.path, body);
    if (other) {
      if (other.error) {
        unreadable.push({ file: file.path, reason: other.error });
        continue;
      }
      for (const note of other.notes || []) notes.push(`${file.path}: ${note}`);
      if (other.otherEcosystems) notes.push(otherNote(file.path, other.otherEcosystems, other.otherTypes));
      if (other.notPackages) {
        notes.push(`${file.path}: ${other.notPackages} component(s) are repositories, containers or applications rather than dependencies, so they were left out`);
      }
      if (!other.entries.length) {
        skipped.push({ file: file.path, reason: `read as ${other.kind}, but it lists no packages` });
        continue;
      }
      scanned.push({ file: file.path, type: other.kind, packages: other.entries.length });
      for (const entry of other.entries) raw.push({ ...entry, file: file.path });
      continue;
    }
    if (!/^\s*[{[]/.test(body)) {
      const table = inventory.parseTable(body);
      if (table.otherEcosystems) notes.push(otherNote(file.path, table.otherEcosystems, table.otherTypes));
      if (!table.rows.length) {
        skipped.push({ file: file.path, reason: 'not a package manifest, lockfile, SBOM or a name and version table' });
        continue;
      }
      if (table.unparsed) notes.push(`${file.path}: ${table.unparsed} line(s) were not a name and a version and were left out`);
      if (table.repeats) notes.push(`${file.path}: ${table.repeats} line(s) list a package and version already listed, and were read once`);
      scanned.push({ file: file.path, type: 'package-version-table', packages: table.rows.length });
      for (const row of table.rows) raw.push({ ...row, file: file.path });
      continue;
    }

    let doc;
    try {
      doc = JSON.parse(body);
    } catch (err) {
      unreadable.push({ file: file.path, reason: explainJson(body, err) });
      continue;
    }
    const pipfile = formats.detectJson(file.path, doc);
    if (pipfile) {
      for (const note of pipfile.notes) notes.push(`${file.path}: ${note}`);
      scanned.push({ file: file.path, type: pipfile.kind, packages: pipfile.entries.length });
      for (const entry of pipfile.entries) raw.push({ ...entry, file: file.path });
      continue;
    }
    const { entries, kind, otherEcosystems, otherTypes, notPackages } = extractPackages(doc);
    if (!kind) {
      // another tool's export: a list of package records, like {"software": [{"package", "version", "ecosystem"}]}
      const list = inventory.records(doc);
      if (list && list.otherEcosystems) notes.push(otherNote(file.path, list.otherEcosystems, list.otherTypes));
      if (!list || !list.rows.length) {
        skipped.push({ file: file.path, reason: 'not a package manifest, lockfile, SBOM or a list of package records' });
        continue;
      }
      if (list.unparsed) notes.push(`${file.path}: ${list.unparsed} record(s) were not a package and a version and were left out`);
      if (list.repeats) notes.push(`${file.path}: ${list.repeats} record(s) list a package and version already listed, and were read once`);
      scanned.push({ file: file.path, type: 'package-inventory', packages: list.rows.length });
      for (const row of list.rows) raw.push({ ...row, file: file.path });
      continue;
    }
    // say what we skipped out loud, so the count is trustworthy
    if (otherEcosystems) notes.push(otherNote(file.path, otherEcosystems, otherTypes));
    if (notPackages) {
      notes.push(`${file.path}: ${notPackages} component(s) are repositories, containers or applications rather than dependencies, so they were left out`);
    }
    scanned.push({ file: file.path, type: kind, packages: entries.length });
    for (const entry of entries) raw.push({ ...entry, file: file.path });
  }

  let truncated = false;
  if (raw.length > LIMITS.packages) {
    notes.push(`the files declare ${raw.length} packages, only the first ${LIMITS.packages} were reviewed`);
    raw.length = LIMITS.packages;
    truncated = true;
  }

  // npm here, every other type to its own review
  const isNpm = (entry) => !entry.ecosystem || entry.ecosystem === 'npm';
  const findings = [];
  for (const item of raw.filter(isNpm)) {
    const declared = normalizeSpec(item.name, item.spec);
    const candidates = rules.filter((r) => nameMatches(r, declared.name));
    const nameKnown = candidates.length > 0;

    const matched = [];
    if (declared.kind !== 'non-registry' && declared.kind !== 'invalid' && declared.kind !== 'unparsable') {
      for (const rule of candidates) {
        const hit = matchRule(rule, declared);
        if (hit) matched.push({ rule, hit });
      }
    }

    // rules come in decision order, first match wins
    const decision = matched.length ? matched[0] : null;
    const denyHits = matched.filter((m) => m.rule.kind === 'deny');
    const allowHits = matched.filter((m) => m.rule.kind === 'allow');

    let status;
    if (!decision) status = 'NOT_IDENTIFIED';
    else status = decision.rule.kind === 'deny' ? 'BLOCKED' : 'WHITELISTED';

    const vulnerable = denyHits.length > 0;
    const matchType = denyHits.some((m) => m.hit.type === 'pinned') ? 'pinned' : (denyHits.length ? 'range' : null);
    const declaredHuman = declared.kind === 'non-registry'
      ? `not a registry version (${item.spec})`
      : (declared.kind === 'unparsable' || declared.kind === 'invalid'
        ? `"${item.spec}" is not a version npm would understand`
        : describeRange(declared.spec));

    const drift = status === 'NOT_IDENTIFIED' && nameKnown &&
      declared.kind !== 'non-registry' && declared.kind !== 'invalid' && declared.kind !== 'unparsable';
    const hasBlockedReleases = candidates.some((r) => r.kind === 'deny');
    const atRisk = drift && hasBlockedReleases;

    let detail;
    if (status === 'NOT_IDENTIFIED') {
      if (declared.kind === 'non-registry') {
        detail = `non-registry spec (${item.spec}), so there is no version to check against a rule`;
      } else if (declared.kind === 'invalid' || declared.kind === 'unparsable') {
        detail = 'the version could not be parsed, so nothing could be matched';
      } else if (nameKnown) {
        const allowed = candidates.filter((r) => r.kind === 'allow').map((r) => r.version_range || 'any version');
        const denied = candidates.filter((r) => r.kind === 'deny').map((r) => r.version_range || 'any version');
        const bits = [];
        if (allowed.length) bits.push(`approved versions are ${allowed.join(' || ')}`);
        if (denied.length) bits.push(`blocked versions are ${denied.join(' || ')}`);
        let label;
        if (atRisk && !allowed.length) {
          label = `AT RISK - this package has blocked releases and no approved version at all, and "${item.spec}" (${declaredHuman}) is simply not one of the blocked ones`;
        } else if (atRisk) {
          label = `AT RISK - this package has blocked releases, and "${item.spec}" (${declaredHuman}) is neither blocked nor approved`;
        } else {
          label = `UNAPPROVED VERSION - the name is covered by the rules but "${item.spec}" (${declaredHuman}) falls outside every rule range`;
        }
        detail = bits.length ? `${label} - ${bits.join('; ')}` : label;
      } else {
        detail = mode === 'whitelist'
          ? 'no rule mentions this package, and in whitelist mode that means it is refused'
          : 'no rule mentions this package, and in blacklist mode that means it is served';
      }
    } else if (status === 'BLOCKED') {
      const first = denyHits[0] || decision;
      detail = first.rule.note || 'matched a deny rule';
      if (matchType === 'range') detail += ` -- ${first.hit.why}`;
    } else {
      detail = (allowHits[0] && allowHits[0].rule.note) || 'matched an allow rule';
      if (vulnerable) {
        detail = `WHITELISTED BUT VULNERABLE - also matches deny rule ${denyHits[0].rule.version_range || 'any version'} (${describeRange(denyHits[0].rule.version_range)}): ${denyHits[0].hit.why}`;
      }
    }

    findings.push({
      ecosystem: 'npm',
      source_file: item.file,
      section: item.section,
      package: item.name,
      resolved_package: declared.name !== item.name ? declared.name : null,
      declared_version: item.spec,
      declared_version_human: declaredHuman,
      version_spec_kind: declared.kind,
      version_is_pinned: declared.kind === 'exact',
      status,
      vulnerable,
      vulnerability_match_type: matchType,
      whitelisted_but_vulnerable: vulnerable && status === 'WHITELISTED',
      name_known_to_rules: nameKnown,
      name_known_version_drift: drift,
      package_has_blocked_releases: hasBlockedReleases,
      at_risk: atRisk,
      detail,
      matched_deny_rules: denyHits.map((m) => ruleJson(m.rule, m.hit)),
      matched_allow_rules: allowHits.map((m) => ruleJson(m.rule, m.hit)),
      effective_rule: decision ? ruleJson(decision.rule, decision.hit) : null,
      rules_covering_this_name: status === 'NOT_IDENTIFIED' && nameKnown
        ? candidates.map((r) => ruleJson(r, null))
        : [],
      known_advisory: null
    });
  }

  const advisories = await attachAdvisories(findings, notes);
  const others = [...new Set(raw.filter((entry) => !isNpm(entry)).map((entry) => entry.ecosystem))];
  for (const id of others) {
    const list = raw.filter((entry) => entry.ecosystem === id);
    const profile = id === 'pypi' ? pypiReview.profile : ecosystemReview.forKind(id);
    if (!profile) {
      notes.push(`${list.length} ${id} package(s) were left out, this registry has no rules for them`);
      continue;
    }
    const got = await ecosystemReview.review(profile, list, notes);
    findings.push(...got.findings);
    advisories.checked += got.checked;
    advisories.asked += got.asked;
  }

  const rank = { BLOCKED: 0, WHITELISTED: 1, NOT_IDENTIFIED: 2 };
  findings.sort((a, b) =>
    rank[a.status] - rank[b.status] ||
    Number(b.vulnerable) - Number(a.vulnerable) ||
    Number(b.at_risk) - Number(a.at_risk) ||
    Number(b.name_known_version_drift) - Number(a.name_known_version_drift) ||
    a.source_file.localeCompare(b.source_file) ||
    a.package.localeCompare(b.package));

  const count = (fn) => findings.filter(fn).length;
  const summary = {
    total_packages: findings.length,
    unique_packages: new Set(findings.map((f) => `${f.ecosystem}:${f.package}@${f.declared_version}`)).size,
    ecosystems: Object.fromEntries(ecosystems.ALL.filter((e) => e.id !== 'oci').map((e) => [e.id, count((f) => f.ecosystem === e.id)])
      .filter(([id, n]) => n || id === 'npm' || id === 'pypi')),
    blocked: count((f) => f.status === 'BLOCKED'),
    whitelisted: count((f) => f.status === 'WHITELISTED'),
    not_identified: count((f) => f.status === 'NOT_IDENTIFIED'),
    not_identified_name_known: count((f) => f.name_known_version_drift),
    not_identified_name_unknown: count((f) => f.status === 'NOT_IDENTIFIED' && !f.name_known_version_drift),
    at_risk: count((f) => f.at_risk),
    at_risk_no_approved_version: count((f) => f.at_risk && !f.rules_covering_this_name.some((r) => r.kind === 'allow')),
    vulnerable_total: count((f) => f.vulnerable),
    vulnerable_pinned: count((f) => f.vulnerability_match_type === 'pinned'),
    vulnerable_range_overlap: count((f) => f.vulnerability_match_type === 'range'),
    whitelisted_but_vulnerable: count((f) => f.whitelisted_but_vulnerable),
    known_advisories: count((f) => f.known_advisory),
    advisories_critical_or_high: count((f) => f.known_advisory &&
      (f.known_advisory.severity === 'CRITICAL' || f.known_advisory.severity === 'HIGH')),
    versions_checked_against_the_feed: advisories.checked,
    versions_asked_of_the_feed: advisories.asked,
    files_scanned: scanned.length,
    files_skipped: skipped.length,
    files_unreadable: unreadable.length
  };

  return {
    kind: 'npm-package-review',
    format_version: 1,
    generated_at: new Date().toISOString(),
    policy_mode: mode,
    rules_used: allRules.length,
    truncated,
    notes,
    summary,
    files_scanned: scanned,
    files_skipped: skipped,
    files_unreadable: unreadable,
    findings
  };
}

// Pinned versions vs the advisory feed too. whitelisted AND a critical CVE is exactly what people need to see
//ranges aren't releases yet, nothing to look up
async function attachAdvisories(findings, notes) {
  const pinned = findings.filter((f) => f.version_is_pinned);
  if (!pinned.length) return { checked: 0, asked: 0 };

  const result = await cvescan.scanPairs(
    pinned.map((f) => ({ name: f.package, version: f.declared_version }))
  );
  for (const note of result.notes) notes.push(note);

  for (const f of pinned) {
    const row = result.found.get(f.package + '@' + f.declared_version);
    if (!row) continue;
    f.known_advisory = {
      severity: row.severity,
      cves: row.cves || '',
      advisories: row.advisories || '',
      summary: row.summary || '',
      fixed_in: row.fixed_in || null
    };
  }
  return { checked: result.checked, asked: result.asked };
}

// ---------------------------------------------------------------- entry point

// zips spotted by PK magic bytes, not the extension. a zip named .json is still a zip
async function reviewUpload(buffer, filename) {
  const notes = [];
  const isZip = buffer.length > 1 && buffer[0] === 0x50 && buffer[1] === 0x4b;

  let files;
  if (isZip) {
    files = readZip(buffer, notes);
  } else {
    if (buffer.length > LIMITS.fileBytes) {
      const e = new Error(`that file is ${(buffer.length / 1048576).toFixed(1)}MB and the limit for a single file is ${LIMITS.fileBytes / 1048576}MB`);
      e.status = 413;
      throw e;
    }
    files = [{ path: filename || 'uploaded', text: buffer.toString('utf8') }];
  }

  const report = await reviewFiles(files, { notes });
  report.input = { name: filename || 'uploaded', type: isZip ? 'zip archive' : 'single file' };
  if (!report.files_scanned.length) {
    const e = new Error(
      report.files_unreadable.length
        ? `nothing could be reviewed: ${report.files_unreadable[0].reason}`
        : 'nothing in that file is a package manifest, lockfile, SBOM or a name and version table'
    );
    e.status = 400;
    throw e;
  }
  return report;
}

// ------------------------------------------------------------ narrowing it down
// filter names live here because export uses them too, so you export what's on screen
const VIEWS = {
  all: () => true,
  unapproved: (f) => f.status !== 'WHITELISTED',
  undecided: (f) => f.status === 'NOT_IDENTIFIED',
  at_risk: (f) => f.at_risk,
  drift: (f) => f.name_known_version_drift,
  vulnerable: (f) => f.whitelisted_but_vulnerable,
  advisory: (f) => Boolean(f.known_advisory),
  blocked: (f) => f.status === 'BLOCKED'
};

const VIEW_NAMES = Object.keys(VIEWS);

function viewFilter(key) {
  return VIEWS[key] || VIEWS.all;
}

const CSV_COLUMNS = [
  'status', 'vulnerable', 'vulnerability_match_type', 'whitelisted_but_vulnerable',
  'at_risk', 'name_known_version_drift', 'package', 'declared_version',
  'declared_version_human', 'version_is_pinned', 'resolved_package', 'section',
  'source_file', 'version_spec_kind', 'effective_rule_kind', 'effective_rule_pattern',
  'effective_rule_range', 'effective_rule_range_human', 'effective_rule_priority',
  'deny_rule_ranges', 'deny_affected_versions', 'deny_rule_notes', 'allow_rule_ranges',
  'name_known_to_rules', 'package_has_blocked_releases', 'blocked_releases_for_package',
  'rules_covering_this_name', 'advisory_severity', 'advisory_cves', 'advisory_fixed_in',
  'detail', 'ecosystem'
];

function csvRow(f) {
  const eff = f.effective_rule || {};
  const join = (list, pick) => list.map(pick).filter(Boolean).join('; ');
  return [
    f.status,
    f.vulnerable ? 'yes' : 'no',
    f.vulnerability_match_type || '',
    f.whitelisted_but_vulnerable ? 'yes' : 'no',
    f.at_risk ? 'yes' : 'no',
    f.name_known_version_drift ? 'yes' : 'no',
    f.package,
    f.declared_version,
    f.declared_version_human,
    f.version_is_pinned ? 'yes' : 'no',
    f.resolved_package || '',
    f.section,
    f.source_file,
    f.version_spec_kind,
    eff.kind || '',
    eff.pattern || '',
    eff.version_range || '',
    eff.version_range_human || '',
    eff.priority === undefined ? '' : eff.priority,
    join(f.matched_deny_rules, (r) => r.version_range || 'any version'),
    join(f.matched_deny_rules, (r) => r.affected_versions_in_scope.join(', ')),
    join(f.matched_deny_rules, (r) => r.note),
    join(f.matched_allow_rules, (r) => r.version_range || 'any version'),
    f.name_known_to_rules ? 'yes' : 'no',
    f.package_has_blocked_releases ? 'yes' : 'no',
    join(f.rules_covering_this_name.filter((r) => r.kind === 'deny'), (r) => r.version_range || 'any version'),
    join(f.rules_covering_this_name, (r) => `${r.kind} ${r.version_range || 'any version'}`),
    f.known_advisory ? f.known_advisory.severity : '',
    f.known_advisory ? f.known_advisory.cves : '',
    (f.known_advisory && f.known_advisory.fixed_in) || '',
    f.detail,
    f.ecosystem || 'npm'
  ];
}

module.exports = {
  reviewUpload, CSV_COLUMNS, csvRow, LIMITS, VIEW_NAMES, viewFilter,
  describeRange, extractPackages, normalizeSpec
};
