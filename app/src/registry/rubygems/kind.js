// Ruby gems, as the rest of the box needs to know them. See registry/kinds.js.
// Author: Tim Rice

const gemName = require('../../ecosystems/rubygems/name');
const gemVersion = require('../../ecosystems/rubygems/version');

const upstream = () => require('./upstream');

module.exports = {
  id: 'rubygems',
  label: 'the Ruby gem',
  csvTypes: ['rubygems', 'gem', 'gems', 'ruby', 'bundler'],
  validName: (n) => gemName.valid(n),
  badName: 'that is not a gem name, like rack or rails',
  // rubygems.org keeps a gem's case (RedCloth), and so does a kill
  killKey: (n) => String(n || '').trim(),
  canonical: async (n) => String(n || '').trim(),
  spell: (n, v) => `${n} ${v}`,
  version: gemVersion,
  rulePattern: {
    re: /^[A-Za-z0-9_*][A-Za-z0-9._*-]*$/,
    max: gemName.MAX,
    message: 'a gem pattern is a gem name like rack, with a * where you want to match anything, like rails-*'
  },
  rangeHelp: 'It takes forms like 3.1.8, ~> 3.1, >= 3.0, < 4 or 3.1.*, with || between alternatives',
  upstreamPattern: { re: /^[A-Za-z0-9_*][A-Za-z0-9._*-]*$/, example: 'acme-*', message: 'a gem pattern looks like a gem name, like acme-*, with a * where you want to match anything' },
  // 3.1.8 or = 3.1.8, nothing with a range in it. null when a side is not exact
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^(?:=\s*)?(\S+)$/.exec(t);
      if (!m || !gemVersion.valid(m[1])) return null;
      out.push(m[1]);
    }
    return out.length ? [...new Set(out)] : null;
  },
  osv: { ecosystem: 'RubyGems', fixKey: (n) => `rubygems:${n}` },
  // every version the source lists, pushed when its first file was. a yanked version is gone from the list
  async versions(name) {
    const { doc } = await upstream().info(name);
    const by = new Map();
    for (const f of doc.files) {
      const had = by.get(f.version);
      if (!had || (f.published && (!had.published || f.published < had.published))) by.set(f.version, { version: f.version, listed: true, published: f.published });
    }
    return { id: name, versions: [...by.values()] };
  },
  // every file of a version: the plain gem and the platform builds, ten at most
  async fetch(id, version) {
    const { doc } = await upstream().info(id);
    const out = [];
    for (const f of doc.files.filter((x) => x.version === version).slice(0, 10)) out.push(await upstream().getGem(id, f));
    return out;
  },
  // an info line is "1.2.3 rack:>= 2.0,rake:~> 13|checksum:...". the part before the bar is its runtime dependencies
  async dependencies(name, version) {
    const { doc } = await upstream().info(name);
    const f = (doc.files || []).find((x) => x.version === version && !x.platform) || (doc.files || []).find((x) => x.version === version);
    if (!f || !f.line) return null;
    const head = String(f.line).split('|')[0];
    const space = head.indexOf(' ');
    if (space === -1) return [];
    return head.slice(space + 1).split(',').map((part) => {
      const c = part.indexOf(':');
      return c > 0 ? { name: part.slice(0, c).trim(), range: part.slice(c + 1).trim(), scope: 'required' } : null;
    }).filter(Boolean).slice(0, 500);
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    const names = await upstream().licenses(name, version);
    if (!names) return { ...spdx.fromText(''), note: 'the gem source has no license list to read' };
    return spdx.fromMaven(names);
  }
};
