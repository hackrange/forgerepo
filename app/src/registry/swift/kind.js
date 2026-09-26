// Swift packages, as the rest of the box needs to know them. See registry/kinds.js.
// Author: Tim Rice

const swiftName = require('../../ecosystems/swift/name');
const swiftVersion = require('../../ecosystems/swift/version');

const upstream = () => require('./upstream');

module.exports = {
  id: 'swift',
  label: 'the Swift package',
  csvTypes: ['swift', 'swiftpm', 'spm', 'swift package'],
  validName: (n) => swiftName.valid(n),
  badName: 'that is not a Swift package identity, written scope.name like apple.swift-log',
  killKey: (n) => swiftName.fold(n),
  canonical: async (n) => swiftName.fold(n),
  spell: (n, v) => `${n} ${v}`,
  version: swiftVersion,
  rulePattern: {
    re: /^[A-Za-z0-9*][A-Za-z0-9*-]*(?:\.[A-Za-z0-9_*][A-Za-z0-9_*-]*)?$/,
    max: 140,
    message: 'a Swift pattern is a package identity like apple.swift-log, with a * where you want to match anything, like apple.*'
  },
  rangeHelp: 'It takes forms like 1.6.1, ^1.6.0, ~1.6 or >=1.6 <2, with || between alternatives',
  upstreamPattern: { re: /^[A-Za-z0-9*][A-Za-z0-9*.-]*$/, example: 'acme.*', message: 'a Swift pattern looks like a package identity, like acme.*, with a * where you want to match anything' },
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      if (!swiftVersion.valid(t)) return null;
      out.push(t);
    }
    return out.length ? [...new Set(out)] : null;
  },
  // OSV knows Swift packages by their repository, github.com/apple/swift-nio, lower case
  osv: { ecosystem: 'SwiftURL', fixKey: (n) => { const m = /^github\.com\/([^/]+)\/([^/]+)$/i.exec(String(n)); return `swift:${(m ? `${m[1]}.${m[2]}` : String(n)).toLowerCase()}`; }, name: (n) => { const p = swiftName.split(n); return p ? `github.com/${p.scope}/${p.name}`.toLowerCase() : String(n); } },
  async versions(id) {
    const { doc } = await upstream().summary(id);
    return { id: doc.id, versions: doc.versions.map((r) => ({ version: r.version, listed: true, published: null })) };
  },
  async fetch(id, version) {
    return [await upstream().getArchive(id, version)];
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    return { ...spdx.fromText(''), note: 'a Swift package names no license in its manifest' };
  },
  // read out of the Package.swift in the archive: .package(id: "scope.name", ...) and .package(url: "...", ...)
  async dependencies(id, version) {
    const text = await upstream().manifestText(id, version);
    if (!text) return null;
    const out = [];
    for (const m of text.matchAll(/\.package\(\s*(id|url)\s*:\s*"([^"]+)"([^)]*)\)/g)) {
      const want = (m[3] || '').replace(/\s+/g, ' ').trim().replace(/^,\s*/, '').slice(0, 128);
      let name = m[2];
      if (m[1] === 'url') {
        const p = /^(?:https?:\/\/|git@)([^/:]+)[/:]([^/]+)\/([^/]+?)(?:\.git)?\/?$/.exec(m[2]);
        if (!p) continue;
        name = `${p[2]}.${p[3]}`;
      }
      out.push({ name, range: want, scope: 'required' });
    }
    return out.slice(0, 500);
  }
};
