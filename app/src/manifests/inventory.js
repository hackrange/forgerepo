// Inventories: one package per row, as a table (csv, tab separated, lined up columns) or a JSON list of records the
// way other tools export them. an ecosystem column or a package url says which type each row is, otherwise npm.
// Author: Tim Rice
//
// deliberately narrow: read correctly or refused, never half read. a row naming a type this box has no rules for is
// counted, not guessed at, and the same package and version listed again (once per repository, say) is read once

const semver = require('semver');
const aliases = require('../ecosystems/aliases');
const { fromPurl } = require('./formats');

const NAME_COLUMNS = ['package', 'name', 'package_name', 'packagename', 'dependency', 'module', 'library', 'component'];
const VERSION_COLUMNS = ['version', 'package_version', 'packageversion', 'spec', 'range', 'declared', 'resolved', 'versioninfo'];
const TYPE_COLUMNS = ['ecosystem', 'package_manager', 'packagemanager', 'package manager', 'package_type', 'package type', 'manager'];
const PURL_COLUMNS = ['purl', 'package_url', 'packageurl', 'package url'];
// the list inside a JSON export that holds the records
const LIST_KEYS = ['software', 'packages', 'components', 'dependencies', 'libraries', 'items', 'rows', 'results', 'data', 'inventory'];
const MAX_NAME = 300;
const MAX_SPEC = 128;

// tabs, commas, semicolons, or 2+ spaces split. single space doesn't (versions can have spaces)
function tableCells(line) {
  const text = line.replace(/\r$/, '');
  if (text.includes('\t')) return text.split('\t').map((c) => c.trim());
  if (text.includes(',')) return splitCsv(text).map((c) => c.trim());
  if (text.includes(';')) return text.split(';').map((c) => c.trim());
  return text.split(/ {2,}/).map((c) => c.trim());
}

// quoted cells, so ">=1.2, <2" survives
function splitCsv(line) {
  const out = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cell += '"'; i += 1; } else { quoted = false; }
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      out.push(cell);
      cell = '';
    } else {
      cell += ch;
    }
  }
  out.push(cell);
  return out;
}

function looksLikeName(cell) {
  return /^(@[^\s/@]+\/)?[^\s/@]+$/.test(cell) && cell.length <= 214;
}

// dist-tags only count if a header says versions. otherwise `host,ip` becomes a package called host
function looksLikeVersion(cell, labeled) {
  if (!cell || /\s{2,}/.test(cell)) return false;
  if (semver.valid(cell) || semver.validRange(cell)) return true;
  return labeled && /^[a-z][a-z0-9-]{0,30}$/i.test(cell);
}

// what one row says, or { other } for a type with no rules here, or null when it is not a package and version.
// the type's own review checks the name and version properly, this only keeps obvious junk out
function rowOf({ purl, type, name, spec }, labeled) {
  let eco = 'npm';
  let n = String(name || '').trim();
  let v = String(spec || '').trim();
  const p = purl ? fromPurl(purl) : null;
  if (p && p.other) return { other: p.type || 'unknown' };
  if (p) {
    eco = p.ecosystem;
    n = p.name;
    v = v || p.version;
  } else if (type) {
    const id = aliases.typeOf(type);
    // images are not packages with versions, a tag is not a release
    if (!id || id === 'oci') return { other: String(type).trim().toLowerCase().slice(0, 40) };
    eco = id;
  }
  if (eco === 'npm') {
    return looksLikeName(n) && looksLikeVersion(v, labeled) ? { name: n, spec: v } : null;
  }
  // no version is a dependency on any version, the way a bare name in requirements.txt is
  if (!n || n.length > MAX_NAME || v.length > MAX_SPEC || /\s{2,}/.test(v)) return null;
  return { ecosystem: eco, name: n, spec: v };
}

// gathers rows, folds repeats and counts what was left out
function collector(section) {
  const rows = [];
  const seen = new Set();
  const otherTypes = new Set();
  const out = { rows, unparsed: 0, otherEcosystems: 0, otherTypes: [], repeats: 0 };
  return {
    add(got) {
      if (!got) {
        out.unparsed += 1;
        return;
      }
      if (got.other) {
        out.otherEcosystems += 1;
        otherTypes.add(got.other);
        return;
      }
      const key = `${got.ecosystem || 'npm'}\u0000${got.name}\u0000${got.spec}`;
      if (seen.has(key)) {
        out.repeats += 1;
        return;
      }
      seen.add(key);
      rows.push({ ...got, section });
    },
    done() {
      out.otherTypes = [...otherTypes];
      return out;
    }
  };
}

// ---------------------------------------------------------------- tables

function parseTable(text) {
  let at = null;
  let found = null;
  let plain = null;
  for (const line of String(text).split('\n')) {
    const trimmed = line.trim();
    //blank lines and # comments, people annotate these by hand
    if (!trimmed || trimmed.startsWith('#')) continue;
    const raw = tableCells(line);

    // header names the columns, else first two
    if (!at && !found && !plain) {
      const lower = raw.map((c) => c.toLowerCase());
      const col = (list) => lower.findIndex((c) => list.includes(c));
      const cols = { name: col(NAME_COLUMNS), version: col(VERSION_COLUMNS), type: col(TYPE_COLUMNS), purl: col(PURL_COLUMNS) };
      if ((cols.name >= 0 && cols.version >= 0 && cols.name !== cols.version) || cols.purl >= 0) {
        at = cols;
        found = collector('table:package-version');
        continue;
      }
    }
    if (at) {
      // with a header the columns stay where it says, an empty cell is still a cell
      const cell = (i) => (i >= 0 ? raw[i] || '' : '');
      const purl = cell(at.purl);
      found.add(rowOf({ purl: purl.startsWith('pkg:') ? purl : '', type: cell(at.type), name: cell(at.name), spec: cell(at.version) }, true));
      continue;
    }
    plain = plain || collector('table:two-columns');
    const cells = raw.filter((c) => c !== '');
    plain.add(cells.length < 2 ? null : rowOf({ name: cells[0], spec: cells[1] }, false));
  }
  const out = (found || plain || collector('table')).done();
  // mostly failed = some other file. one parsed line would look like a real review
  if (out.unparsed > out.rows.length) out.rows = [];
  return out;
}

// ---------------------------------------------------------------- JSON records

const pick = (obj, keys) => {
  for (const k of Object.keys(obj)) {
    if (!keys.includes(k.toLowerCase())) continue;
    const v = obj[k];
    if (typeof v === 'string' || typeof v === 'number') return String(v);
  }
  return '';
};

const isRecord = (r) => r && typeof r === 'object' && !Array.isArray(r) &&
  ((pick(r, NAME_COLUMNS) && pick(r, VERSION_COLUMNS)) || pick(r, PURL_COLUMNS).startsWith('pkg:'));

// a JSON list of package records, bare or under a key like "software", or null when the document is not one
function records(doc) {
  let list = Array.isArray(doc) ? doc : null;
  if (!list && doc && typeof doc === 'object') {
    for (const k of Object.keys(doc)) {
      if (LIST_KEYS.includes(k.toLowerCase()) && Array.isArray(doc[k])) {
        list = doc[k];
        break;
      }
    }
  }
  if (!list || !list.length || !list.slice(0, 20).some(isRecord)) return null;
  const c = collector('inventory:record');
  for (const r of list) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) {
      c.add(null);
      continue;
    }
    const purl = pick(r, PURL_COLUMNS);
    c.add(rowOf({ purl: purl.startsWith('pkg:') ? purl : '', type: pick(r, TYPE_COLUMNS), name: pick(r, NAME_COLUMNS), spec: pick(r, VERSION_COLUMNS) }, true));
  }
  const out = c.done();
  return out.unparsed > out.rows.length ? { ...out, rows: [] } : out;
}

module.exports = { parseTable, records, tableCells, splitCsv };
