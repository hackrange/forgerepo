// NuGet, as the rest of the box needs to know it. See registry/kinds.js.
// Author: Tim Rice

const nugetName = require('../../ecosystems/nuget/name');
const nugetVersion = require('../../ecosystems/nuget/version');

const upstream = () => require('./upstream');

module.exports = {
  id: 'nuget',
  label: 'the NuGet package',
  csvTypes: ['nuget', 'dotnet', '.net', 'net', 'csharp', 'c#'],
  validName: (n) => nugetName.valid(n),
  badName: 'that is not a NuGet package id, like Newtonsoft.Json',
  // what a kill keys on: one package in any case
  killKey: (n) => String(n || '').trim().toLowerCase(),
  // the spelling the feed uses (Newtonsoft.Json), which the advisory feed needs
  canonical: (n) => upstream().canonical(n),
  spell: (n, v) => `${n} ${v}`,
  version: nugetVersion,
  rulePattern: {
    re: /^[A-Za-z0-9_*](?:[A-Za-z0-9._*-]*[A-Za-z0-9_*])?$/,
    max: nugetName.MAX,
    message: 'a NuGet pattern is a package id like Newtonsoft.Json, with a * where you want to match anything, like Microsoft.Extensions.*'
  },
  rangeHelp: 'It takes forms like 13.0.3, [13.0,14.0), 13.* or >=13.0 <14, with || between alternatives',
  upstreamPattern: { re: /^[A-Za-z0-9_*][A-Za-z0-9._\-*]*$/, example: 'Acme.*', message: 'a NuGet pattern looks like a package id, like Acme.*, with a * where you want to match anything' },
  // 13.0.3 or [13.0.3], nothing with a range in it. null when a side is not exact
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^\[?([^\s,[\]()*<>=]+)\]?$/.exec(t);
      if (!m || !nugetVersion.valid(m[1]) || t.startsWith('[') !== t.endsWith(']')) return null;
      out.push(nugetVersion.normalize(m[1]));
    }
    return out.length ? [...new Set(out)] : null;
  },
  osv: { ecosystem: 'NuGet', fixKey: (n) => `nuget:${String(n).toLowerCase()}` },
  // every version the feed lists: { id, versions: [{ version, listed, published }] }
  async versions(name) {
    const { doc } = await upstream().summary(name);
    return { id: doc.id, versions: doc.versions };
  },
  // download (and so keep and scan) what a version is made of
  async fetch(id, version) {
    const got = await upstream().getPackage(id, version);
    return [got];
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    const { doc } = await upstream().summary(name);
    const v = doc.versions.find((x) => x.version === nugetVersion.normalize(version));
    if (!v) return { ...spdx.fromText(''), note: 'that version is not in the metadata' };
    // older packages point at a license url or a file inside, there is no SPDX expression to read then
    return v.license ? spdx.fromText(v.license, 'licenseExpression') : { ...spdx.fromText(''), note: 'the package names no SPDX license expression, only a license url or file' };
  }
};
