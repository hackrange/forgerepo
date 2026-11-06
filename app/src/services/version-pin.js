// A request for "any" version gets pinned to the version that is current right now, never a rule that allows every
// version forever. the next release has to be asked for, and checked, on its own.
// Author: Tim Rice

const { fail } = require('../lib/errors');

// all the ways people (and installs) spell "whatever". latest counts too, it's a label that moves
const ANY = new Set(['', '*', 'x', 'x.x.x', 'latest', 'any', '>=0', '>=0.0.0']);

function isAnyRange(range) {
  return ANY.has(String(range === undefined || range === null ? '' : range).trim().toLowerCase());
}

// the version an install would get today: npm's latest tag, pip's newest stable release, the newest listed release
// for the rest, all minus anything still cooling off. an image gets the digest latest points at, a tag can move
async function currentPin(ecosystem, name) {
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
  const chosen = await preview(eco, name);
  if (!chosen.version) fail(409, `could not pin ${name} to a version: ${chosen.why}`);
  return { range: require('./auto-approve').rangeFor(eco, [chosen.version]), version: chosen.version, said: chosen.said };
}

// what "any version" of a package comes out as right now, in words for the person who asked. never throws
async function preview(ecosystem, name) {
  const eco = ecosystem || 'npm';
  const auto = require('./auto-approve');
  if (eco === 'oci') return { version: null, said: 'the image latest points at when it is approved, pinned by its digest', why: null };
  let c;
  try {
    c = await auto.chooseCurrent(eco, name);
  } catch (err) {
    return { version: null, why: `the current version could not be looked up (${String(err.message || err).slice(0, 120)})` };
  }
  if (c.cooling) return { version: null, why: `${c.cooling}. A person has to review a version that is still cooling off` };
  if (c.stop || c.wait) return { version: null, why: c.stop || c.wait };
  const version = c.versions[0];
  const skipped = (c.skipped || []).map((s) => `${s.version} (${(s.worst || 'unrated').toLowerCase()})`);
  let said = version;
  if (c.clean === true) said = `${version}, the newest with no known advisories${skipped.length ? `, newer ${skipped.join(', ')} have advisories` : ''}`;
  else if (c.clean === false) said = `${version}, the newest, every recent release has advisories so a person decides`;
  else said = `${version}, the newest, the advisory feed did not answer so a person decides`;
  return { version, said, clean: c.clean, skipped: c.skipped || [] };
}

// the range an approval writes: what was asked for, unless that was "any", then the current version
async function pinFor(row, range) {
  if (!isAnyRange(range)) return { range, pinned: false };
  const pin = await currentPin(row.ecosystem || 'npm', row.package_name);
  return { range: pin.range, pinned: true, said: pin.said };
}

module.exports = { ANY, isAnyRange, currentPin, pinFor, preview };
