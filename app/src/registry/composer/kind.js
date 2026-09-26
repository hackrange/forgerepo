// Composer packages, as the rest of the box needs to know them. See registry/kinds.js.
// Author: Tim Rice

const composerName = require('../../ecosystems/composer/name');
const composerVersion = require('../../ecosystems/composer/version');

const upstream = () => require('./upstream');

module.exports = {
  id: 'composer',
  label: 'the Composer package',
  csvTypes: ['composer', 'php', 'packagist'],
  validName: (n) => composerName.valid(n),
  badName: 'that is not a Composer package name, written vendor/package like monolog/monolog',
  killKey: (n) => composerName.fold(n),
  canonical: async (n) => composerName.fold(n),
  spell: (n, v) => `${n} ${v}`,
  version: composerVersion,
  rulePattern: {
    re: /^[A-Za-z0-9*][A-Za-z0-9_.*-]*(?:\/[A-Za-z0-9*][A-Za-z0-9_.*-]*)?$/,
    max: composerName.MAX,
    message: 'a Composer pattern is a package name like monolog/monolog, with a * where you want to match anything, like symfony/*'
  },
  rangeHelp: 'It takes the forms composer.json uses, like 3.5.0, ^3.5, ~3.5, 3.5.* or >=3.5 <4.0, with || between alternatives',
  upstreamPattern: { re: /^[A-Za-z0-9*][A-Za-z0-9_.*/-]*$/, example: 'acme/*', message: 'a Composer pattern looks like a package name, like acme/*, with a * where you want to match anything' },
  // 3.5.0, =3.5.0 or ==3.5.0, nothing with a range in it. null when a side is not exact
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split(/\|\|?/)) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^(?:==?\s*)?(\S+)$/.exec(t);
      if (!m || !composerVersion.valid(m[1])) return null;
      out.push(m[1]);
    }
    return out.length ? [...new Set(out)] : null;
  },
  osv: { ecosystem: 'Packagist', fixKey: (n) => `composer:${composerName.fold(n)}` },
  async versions(name) {
    const { doc } = await upstream().metadata(name);
    return { id: doc.name, versions: doc.versions.map((r) => ({ version: r.version, listed: true, published: r.time || null })) };
  },
  async fetch(id, version) {
    return [await upstream().getArchive(id, version)];
  },
  // require, without the php version, the ext- extensions and composer's own entries: those are not packages
  async dependencies(name, version) {
    const { doc } = await upstream().metadata(name);
    const rel = (doc.versions || []).find((r) => r.version === version);
    if (!rel) return null;
    const req = rel.require && typeof rel.require === 'object' ? rel.require : {};
    return Object.entries(req)
      .filter(([n]) => n.includes('/') && !n.startsWith('ext-') && !n.startsWith('composer-') && !n.startsWith('composer/'))
      .map(([n, range]) => ({ name: n.toLowerCase(), range: String(range || ''), scope: 'required' }))
      .slice(0, 500);
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    const { doc } = await upstream().metadata(name);
    const rel = upstream().release(doc, version);
    if (!rel) return { ...spdx.fromText(''), note: 'that version is not in the metadata' };
    // composer.json lists licenses as alternatives, any one of them may be chosen
    const list = (Array.isArray(rel.license) ? rel.license : [rel.license]).filter((l) => typeof l === 'string' && l.trim());
    return list.length ? spdx.fromText(list.length > 1 ? `(${list.join(' OR ')})` : list[0], 'composer.json') : { ...spdx.fromText(''), note: 'the package names no license' };
  }
};
