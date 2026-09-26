// Debian packages from APT mirrors, as the rest of the box needs to know them. See registry/kinds.js.
// Author: Tim Rice
//
// the advisory feeds (Debian:12, Ubuntu:22.04:LTS) file advisories under the SOURCE package: libssl3 is openssl. the
// source of each .deb is kept with it when it is downloaded, and the feed is the one of the mirror it came from

const db = require('../../db');
const debName = require('../../ecosystems/apt/name');
const debVersion = require('../../ecosystems/apt/version');
const mirrorOptions = require('../shared/mirror-options');

const upstream = () => require('./upstream');

// the feed, source package and source version to ask about, or null when it can not be told
async function feedOf(name, version) {
  const ups = (await require('../shared/upstreams').all('apt')).filter((u) => u.options.advisories);
  const row = await db.one("SELECT upstream, metadata FROM artifacts WHERE ecosystem = 'apt' AND package_name = ? AND version = ? LIMIT 1", [name, version]);
  let meta = {};
  try {
    meta = row && row.metadata ? JSON.parse(row.metadata) : {};
  } catch (err) {
    meta = {};
  }
  const from = row ? ups.find((u) => u.name === row.upstream) : null;
  const feeds = [...new Set(ups.map((u) => u.options.advisories))];
  const ecosystem = from ? from.options.advisories : feeds.length === 1 ? feeds[0] : null;
  if (!ecosystem) return null;
  return {
    ecosystem,
    name: typeof meta.source === 'string' && debName.valid(meta.source) ? meta.source : name,
    version: typeof meta.sourceVersion === 'string' && debVersion.valid(meta.sourceVersion) ? meta.sourceVersion : version
  };
}

module.exports = {
  id: 'apt',
  label: 'the Debian package',
  csvTypes: ['apt', 'deb', 'debian', 'ubuntu', 'dpkg'],
  validName: (n) => debName.valid(n),
  badName: 'that is not a Debian package name, like libssl3',
  killKey: (n) => String(n || '').trim(),
  canonical: async (n) => String(n || '').trim(),
  spell: (n, v) => `${n} ${v}`,
  version: debVersion,
  rulePattern: {
    re: /^[a-z0-9*][a-z0-9+.*-]*$/,
    max: debName.MAX,
    message: 'a Debian pattern is a package name like libssl3, lower case, with a * where you want to match anything, like python3-*'
  },
  rangeHelp: 'It takes forms like 3.0.11-1~deb12u2, >=3.0.11 or << 3.0.12, with || between alternatives',
  upstreamPattern: { re: /^$/, example: '', message: 'an APT mirror is a whole archive, so it has no pattern' },
  mirror: true,
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^(?:==?\s*)?(\S+)$/.exec(t);
      if (!m || !debVersion.valid(m[1])) return null;
      out.push(m[1]);
    }
    return out.length ? [...new Set(out)] : null;
  },
  osv: {
    // never sent as it is, each version is asked about in its own mirror's feed, under its source package
    ecosystem: 'Debian',
    fixKey: (n) => `apt:${n}`,
    ecosystemOf: feedOf,
    matches: (e) => /^(Debian|Ubuntu)(:|$)/.test(e)
  },
  async versions(name) {
    const seen = new Map();
    for (const { p } of await upstream().everywhere(name)) if (!seen.has(p.version)) seen.set(p.version, { version: p.version, listed: true, published: null });
    if (!seen.size) throw Object.assign(new Error(`${name} is not in any APT mirror index here yet (run apt update through one first)`), { status: 404 });
    return { id: name, versions: [...seen.values()] };
  },
  async fetch(name, version) {
    const all = (await upstream().everywhere(name)).filter(({ p }) => p.version === version);
    if (!all.length) throw Object.assign(new Error(`${name} ${version} is not in any APT mirror index here`), { status: 404 });
    const first = all[0].up.name;
    const out = [];
    const seen = new Set();
    for (const { up, p } of all.filter((x) => x.up.name === first)) {
      if (seen.has(p.filename)) continue;
      seen.add(p.filename);
      out.push(await upstream().getPackage(up, p));
    }
    return out;
  },
  // Depends and Pre-Depends, as apt itself reads them: alternatives separated by |, the first one counts, and the
  // version each asks for in brackets after the name
  async dependencies(name, version) {
    const all = (await upstream().everywhere(name)).filter(({ p }) => p.version === version);
    if (!all.length) return null;
    const out = [];
    const seen = new Set();
    for (const part of String((all[0].p || {}).depends || '').split(',')) {
      const first = part.split('|')[0].trim();
      if (!first) continue;
      const m = /^([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9-]+)?\s*(?:\(([^)]*)\))?/.exec(first);
      if (!m || seen.has(m[1])) continue;
      seen.add(m[1]);
      out.push({ name: m[1], range: (m[2] || '').trim(), scope: 'required' });
    }
    return out.slice(0, 500);
  },
  async license() {
    const spdx = require('../../policy/licenses/spdx');
    // a Debian package keeps its license in /usr/share/doc/*/copyright inside the package, not in the index
    return { ...spdx.fromText(''), note: 'the APT index names no license, it is in the package\'s copyright file' };
  }
};
