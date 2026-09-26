// What a rule is allowed to say, per kind of registry.
// Author: Tim Rice
//
// npm names keep case and scopes, PyPI folds and uses pip ranges. npm's checks would refuse
// `>=2.31,<3` and happily take `^2.31`. Everything writing a rule goes through here so nothing disagrees.

const semver = require('semver');
const db = require('../db');
const ecosystems = require('../ecosystems');
const pypiName = require('../ecosystems/pypi/name');
const pypiVersion = require('../ecosystems/pypi/version');
const ociName = require('../ecosystems/oci/name');
const kinds = require('../registry/kinds');
const { fail } = require('../lib/errors');
const { str } = require('../lib/validate');

// Uppercase allowed: old npm packages (JSONStream, Base64) still have it. lowercasing used to
// turn JSONStream into jsonstream, a different package by a different author. oops
const NPM_PATTERN_RE = /^(?:@[A-Za-z0-9*_-][A-Za-z0-9._*-]*\/)?[A-Za-z0-9*_-][A-Za-z0-9._*-]*$/;

// no scopes, a star goes anywhere
const PYPI_PATTERN_RE = /^[A-Za-z0-9*](?:[A-Za-z0-9._*-]*[A-Za-z0-9*])?$/;

// a tag with stars allowed in it. a digest is checked on its own, it can't hold one
const OCI_TAG_GLOB_RE = /^[A-Za-z0-9_*][A-Za-z0-9._\-*]{0,127}$/;

// blank = npm, like every older caller and file meant.
// switched off ecosystem: adding is refused, restoring keeps the rules for later
function ruleEcosystem(value, options = {}) {
  const id = value === undefined || value === null || String(value).trim() === ''
    ? 'npm'
    : String(value).trim().toLowerCase();
  const eco = ecosystems.get(id);
  if (!eco) fail(400, 'that is not a kind of registry this box knows about');
  if (options.mustBeOn && eco.setting && !db.settings.getBool(eco.setting)) {
    fail(400, `${eco.name} is switched off in Settings, so rules for it cannot be added`);
  }
  return eco.id;
}

function checkPattern(pattern, ecosystem = 'npm') {
  const p = String(pattern || '').trim();
  if (!p || p.length > 255) fail(400, 'that pattern is empty or too long');
  if (p === '*') return p;

  if (ecosystem === 'pypi') {
    if (p.length > pypiName.MAX_LENGTH || !PYPI_PATTERN_RE.test(p)) {
      fail(400, 'a PyPI pattern can only hold letters, digits, dots, dashes, underscores and *, and cannot start or end on a separator');
    }
    if ((p.match(/\*/g) || []).length > 5) fail(400, 'that is too many wildcards, keep it to five');
    // saved folded, so Flask and flask can't be two rules arguing
    return pypiName.normalize(p);
  }

  if (ecosystem === 'oci') {
    if (p.length > ociName.MAX_NAME || !ociName.validPattern(p)) {
      fail(400, 'an image pattern can only hold lower case repository characters, / and *');
    }
    if ((p.match(/\*/g) || []).length > 5) fail(400, 'that is too many wildcards, keep it to five');
    return ociName.foldPattern(p);
  }

  // the newer types say what a pattern of theirs looks like. case is kept, matching decides about case
  const kind = kinds.get(ecosystem);
  if (kind) {
    if (p.length > kind.rulePattern.max || !kind.rulePattern.re.test(p)) fail(400, kind.rulePattern.message);
    if ((p.match(/\*/g) || []).length > 5) fail(400, 'that is too many wildcards, keep it to five');
    return p;
  }

  //case is kept, not folded. npm treats it as part of the name
  if (!NPM_PATTERN_RE.test(p)) fail(400, 'a pattern can only hold package name characters and *');
  // a wall of stars becomes a nasty regex, and nobody legitimately needs that many
  if ((p.match(/\*/g) || []).length > 5) fail(400, 'that is too many wildcards, keep it to five');
  return p;
}

// ~=2 matches nothing. pip refuses it, so do we
const COMPATIBLE_TOO_SHORT_RE = /~=\s*(?:\d+!)?\d+\s*(?:,|$)/;

function checkRange(range, ecosystem = 'npm') {
  const r = str(range, 128, 'version range');
  // empty string, not null, so the unique key on the rules table actually works
  if (!r) return '';

  if (ecosystem === 'pypi') {
    // our || format, not pip's. an empty side is refused, `2.31.0 ||` must not mean every release
    const alternatives = r.split('||').map((part) => part.trim());
    const bad = alternatives.some((part) => !part || !pypiVersion.validSpecifierSet(part) || COMPATIBLE_TOO_SHORT_RE.test(part));
    if (bad) {
      fail(400, `"${r}" is not a version specifier pip would understand. It takes forms like 2.31.0, ==2.31.*, ~=2.31.0 or >=2.31,<3`);
    }
    const tidy = alternatives.join(' || ');
    if (tidy.length > 128) fail(400, 'version range is too long, max 128 characters');
    return tidy;
  }

  if (ecosystem === 'oci') {
    // there is nothing to reason about in a tag, so a range is just the tags and digests it names
    const parts = r.split('||').map((part) => part.trim());
    const bad = parts.some((part) => !part || !(ociName.isDigest(part) || OCI_TAG_GLOB_RE.test(part)));
    if (bad) fail(400, `"${r}" is not a tag, a tag with a * in it, or a sha256 digest`);
    if (parts.some((part) => (part.match(/\*/g) || []).length > 5)) fail(400, 'that is too many wildcards, keep it to five');
    const tidy = parts.join(' || ');
    if (tidy.length > 128) fail(400, 'version range is too long, max 128 characters');
    return tidy;
  }

  const kind = kinds.get(ecosystem);
  if (kind) {
    if (!kind.version.validRange(r)) fail(400, `"${r}" is not a ${ecosystems.get(ecosystem).name} version or range. ${kind.rangeHelp}`);
    return r.split('||').map((part) => part.trim()).join(' || ');
  }

  if (!semver.validRange(r)) fail(400, `"${r}" is not a version range npm would understand`);
  return r;
}

// exact versions a range names, one per || side. real ranges name none.
// python pins can be bare or ==, wildcards and comparisons aren't pins
function exactPins(range, ecosystem = 'npm') {
  // a tag is not a version any advisory feed can look up, and a digest even less so. images get scanned later
  if (ecosystem === 'oci') return [];
  const out = [];
  for (const raw of String(range || '').split('||')) {
    const token = raw.trim();
    if (!token) continue;
    if (ecosystem === 'pypi') {
      const m = /^(?:==\s*)?([^\s,*<>=!~]+)$/.exec(token);
      if (m && pypiVersion.valid(m[1])) out.push(m[1]);
    } else if (kinds.get(ecosystem)) {
      out.push(...(kinds.get(ecosystem).exactPins(token) || []));
    } else if (semver.valid(token)) {
      out.push(token);
    }
  }
  return out;
}

module.exports = { ruleEcosystem, checkPattern, checkRange, exactPins };
