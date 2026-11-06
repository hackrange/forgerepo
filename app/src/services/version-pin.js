// A request for "any" version gets pinned to the version that is current right now, never a rule that allows every
// version forever. the next release has to be asked for, and checked, on its own.
// Author: Tim Rice

const { fail } = require('../lib/errors');

// all the ways people (and installs) spell "whatever". latest counts too, it's a label that moves
const ANY = new Set(['', '*', 'x', 'x.x.x', 'latest', 'any', '>=0', '>=0.0.0']);

function isAnyRange(range) {
  return ANY.has(String(range === undefined || range === null ? '' : range).trim().toLowerCase());
}

// any = every version, exact = a list of versions (1.2.3 || 1.4.5, ==2.31.0, a tag), range = everything else (^1.2.0, 1.x).
// an image's tag pattern stays as it is, there's no list of its tags to pick the newest from
function rangeKind(range, ecosystem) {
  const eco = ecosystem || 'npm';
  if (isAnyRange(range)) return 'any';
  if (eco === 'oci') return 'exact';
  return require('../warm').pinsFor(range, eco) ? 'exact' : 'range';
}

// the version an install would get today: npm's latest tag, pip's newest stable release, the newest listed release
// for the rest, all minus anything still cooling off. an image gets the digest latest points at, a tag can move
async function currentPin(ecosystem, name, range = '') {
  const eco = ecosystem || 'npm';
  if (eco === 'oci') {
    let got;
    try {
      got = await require('../registry/oci/upstream').getManifest(name, 'latest');
    } catch (err) {
      fail(409, `could not find what ${name}:latest is right now (${String(err.message || err).slice(0, 120)}), ask for a tag instead`);
    }
    if (!got || !got.digest) fail(409, `${name} has no latest tag to pin to, ask for a tag instead`);
    return { range: got.digest, version: got.digest, said: `latest, which is ${got.digest.slice(0, 19)}... right now` };
  }
  const chosen = await preview(eco, name, range);
  if (!chosen.version) fail(409, `could not pin ${name}${range ? ` ${range}` : ''} to a version: ${chosen.why}`);
  return { range: require('./auto-approve').rangeFor(eco, [chosen.version]), version: chosen.version, said: chosen.said };
}

// what "any version" of a package comes out as right now, in words for the person who asked. never throws
async function preview(ecosystem, name, asked = '') {
  const eco = ecosystem || 'npm';
  const auto = require('./auto-approve');
  const kind = rangeKind(asked, eco);
  if (kind === 'exact') return { kind, version: null, said: null, why: null };
  if (eco === 'oci') return { kind, version: null, said: 'the image latest points at when it is approved, pinned by its digest', why: null };
  const range = kind === 'range' ? String(asked).trim() : '';
  const inRange = range ? ` in ${range}` : '';
  let c;
  try {
    c = await auto.chooseCurrent(eco, name, range);
  } catch (err) {
    return { version: null, why: `the current version could not be looked up (${String(err.message || err).slice(0, 120)})` };
  }
  if (c.cooling) return { kind, version: null, why: `${c.cooling}. A person has to review a version that is still cooling off` };
  if (c.stop || c.wait) return { kind, version: null, why: c.stop || c.wait };
  const version = c.versions[0];
  const skipped = (c.skipped || []).map((s) => `${s.version} (${(s.worst || 'unrated').toLowerCase()})`);
  let said = version;
  if (c.clean === true) said = `${version}, the newest${inRange} with no known advisories${skipped.length ? `, newer ${skipped.join(', ')} have advisories` : ''}`;
  else if (c.clean === false) said = `${version}, the newest${inRange}, every recent release${inRange} has advisories so a person decides`;
  else said = `${version}, the newest${inRange}, the advisory feed did not answer so a person decides`;
  return { kind, version, said, clean: c.clean, skipped: c.skipped || [] };
}

// the range an approval writes: what was asked for, unless that was "any", then the current version
// the range an approval writes: an exact list as asked, otherwise the one version that is current and clean (in the range)
async function pinFor(row, range) {
  const eco = row.ecosystem || 'npm';
  const kind = rangeKind(range, eco);
  if (kind === 'exact') return { range, pinned: false };
  const pin = await currentPin(eco, row.package_name, kind === 'range' ? String(range).trim() : '');
  return { range: pin.range, pinned: true, said: pin.said };
}

module.exports = { ANY, isAnyRange, rangeKind, currentPin, pinFor, preview };
