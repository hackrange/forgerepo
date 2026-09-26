// RPM packages, as the rest of the box needs to know them. See registry/kinds.js.
// Author: Tim Rice
//
// a package can be in several mirrors (BaseOS and AppStream, or AlmaLinux and Rocky). the advisory feed is the one of
// the mirror a version came from: OSV files AlmaLinux 9's openssl apart from Rocky Linux 9's

const db = require('../../db');
const rpmName = require('../../ecosystems/rpm/name');
const rpmVersion = require('../../ecosystems/rpm/version');
const mirrorOptions = require('../shared/mirror-options');

const upstream = () => require('./upstream');

// the feed of the mirror a version was kept from, or of the only mirror with a feed. null when it can not be told
async function feedOf(name, version) {
  const ups = (await require('../shared/upstreams').all('rpm')).filter((u) => u.options.advisories);
  const row = await db.one("SELECT upstream FROM artifacts WHERE ecosystem = 'rpm' AND package_name = ? AND version = ? AND upstream IS NOT NULL LIMIT 1", [name, version]);
  const from = row ? ups.find((u) => u.name === row.upstream) : null;
  if (from) return from.options.advisories;
  const feeds = [...new Set(ups.map((u) => u.options.advisories))];
  return feeds.length === 1 ? feeds[0] : null;
}

module.exports = {
  id: 'rpm',
  label: 'the RPM package',
  csvTypes: ['rpm', 'yum', 'dnf', 'rhel', 'almalinux', 'rocky', 'centos', 'fedora'],
  validName: (n) => rpmName.valid(n),
  badName: 'that is not an RPM package name, like openssl-libs',
  killKey: (n) => String(n || '').trim(),
  canonical: async (n) => String(n || '').trim(),
  spell: (n, v) => `${n} ${v}`,
  version: rpmVersion,
  rulePattern: {
    re: /^[A-Za-z0-9_+*][A-Za-z0-9._+*-]*$/,
    max: rpmName.MAX,
    message: 'an RPM pattern is a package name like openssl-libs, with a * where you want to match anything, like python3*'
  },
  rangeHelp: 'It takes forms like 3.0.7-24.el9, 1:3.0.7-24.el9, >=3.0.7 or <3.0.7-27.el9, with || between alternatives',
  // a mirror is a whole repository, it has no pattern
  upstreamPattern: { re: /^$/, example: '', message: 'an RPM mirror is a whole repository, so it has no pattern' },
  mirror: true,
  // 3.0.7-24.el9 or =1:3.0.7-24.el9, nothing with a range in it. null when a side is not exact
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^(?:==?\s*)?(\S+)$/.exec(t);
      if (!m || !rpmVersion.valid(m[1])) return null;
      out.push(m[1]);
    }
    return out.length ? [...new Set(out)] : null;
  },
  osv: {
    // never sent as it is, each version is asked about in its own mirror's feed
    ecosystem: 'RPM',
    fixKey: (n) => `rpm:${n}`,
    version: (v) => rpmVersion.withEpoch(v) || v,
    ecosystemOf: feedOf,
    matches: (e) => mirrorOptions.FEEDS.rpm.includes(e) || /^(AlmaLinux|Rocky Linux|Red Hat)(:|$)/.test(e)
  },
  async versions(name) {
    const seen = new Map();
    for (const { p } of await upstream().everywhere(name)) if (!seen.has(p.version)) seen.set(p.version, { version: p.version, listed: true, published: p.published });
    if (!seen.size) throw Object.assign(new Error(`${name} is not in any RPM mirror here`), { status: 404 });
    return { id: name, versions: [...seen.values()] };
  },
  // every architecture of the version the mirrors have, from the first mirror that has it
  async fetch(name, version) {
    const all = (await upstream().everywhere(name)).filter(({ p }) => p.version === version);
    if (!all.length) throw Object.assign(new Error(`${name} ${version} is not in any RPM mirror here`), { status: 404 });
    const first = all[0].up.name;
    const out = [];
    for (const { up, p } of all.filter((x) => x.up.name === first)) out.push(await upstream().getPackage(up, p));
    return out;
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    const hit = (await upstream().everywhere(name)).find(({ p }) => p.version === version);
    if (!hit) return { ...spdx.fromText(''), note: 'that version is not in any mirror' };
    // Fedora and EL write SPDX now, older packages Fedora's own short names. spdx reads what it can
    return hit.p.license ? spdx.fromText(hit.p.license, 'rpm header') : { ...spdx.fromText(''), note: 'the package names no license' };
  }
};
