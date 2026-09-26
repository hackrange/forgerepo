// CocoaPods, as the rest of the box needs to know it. See registry/kinds.js.
// Author: Tim Rice

const podName = require('../../ecosystems/cocoapods/name');
const podVersion = require('../../ecosystems/cocoapods/version');

const upstream = () => require('./upstream');

module.exports = {
  id: 'cocoapods',
  label: 'the pod',
  csvTypes: ['cocoapods', 'pod', 'pods', 'ios', 'swift pod'],
  validName: (n) => podName.valid(n),
  badName: 'that is not a pod name, like Alamofire',
  killKey: (n) => String(n || '').trim(),
  canonical: async (n) => String(n || '').trim(),
  spell: (n, v) => `${n} ${v}`,
  version: podVersion,
  rulePattern: {
    re: /^[A-Za-z0-9_+*][A-Za-z0-9_.+*-]*$/,
    max: podName.MAX,
    message: 'a pod pattern is a pod name like Alamofire, with a * where you want to match anything, like Firebase*'
  },
  rangeHelp: 'It takes forms like 5.9.1, ~> 5.9 or >= 5.0, < 6, with || between alternatives',
  upstreamPattern: { re: /^[A-Za-z0-9_+*][A-Za-z0-9_.+*-]*$/, example: 'Acme*', message: 'a CocoaPods pattern looks like a pod name, like Acme*, with a * where you want to match anything' },
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^(?:=\s*)?(\S+)$/.exec(t);
      if (!m || !podVersion.valid(m[1])) return null;
      out.push(m[1]);
    }
    return out.length ? [...new Set(out)] : null;
  },
  // there is no CocoaPods feed in OSV, so pods get no advisories of their own
  osv: null,
  async versions(name) {
    const list = await upstream().versions(name);
    return { id: name, versions: list.map((v) => ({ version: v, listed: true, published: null })) };
  },
  async fetch(id, version) {
    return [await upstream().getArchive(id, version)];
  },
  // the podspec's dependencies, each with whatever it asks for
  async dependencies(name, version) {
    const spec = await upstream().podspec(name, version);
    const deps = spec && spec.dependencies && typeof spec.dependencies === 'object' ? spec.dependencies : {};
    return Object.entries(deps)
      .map(([n, want]) => ({ name: String(n), range: (Array.isArray(want) ? want : [want]).filter((x) => typeof x === 'string').join(', '), scope: 'required' }))
      .slice(0, 500);
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    const spec = await upstream().podspec(name, version);
    const l = spec.license;
    const type = typeof l === 'string' ? l : l && typeof l.type === 'string' ? l.type : '';
    return type ? spdx.fromText(type, 'podspec') : { ...spdx.fromText(''), note: 'the podspec names no license' };
  }
};
