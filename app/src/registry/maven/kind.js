// Maven, as the rest of the box needs to know it. See registry/kinds.js.
// Author: Tim Rice

const mavenName = require('../../ecosystems/maven/name');
const mavenVersion = require('../../ecosystems/maven/version');

const upstream = () => require('./upstream');

// each <tag>...</tag> of a pom, in order, as { start, inner, end }. the same matches /<tag>([\s\S]*?)<\/tag>/g gives,
// found with indexOf, since that lazy regex goes quadratic on a pom stuffed with openings that never close
function* elements(text, tag) {
  const open = `<${tag}>`;
  const close = `</${tag}>`;
  let at = 0;
  for (;;) {
    const start = text.indexOf(open, at);
    if (start < 0) return;
    const end = text.indexOf(close, start + open.length);
    if (end < 0) return;
    yield { start, inner: text.slice(start + open.length, end), end: end + close.length };
    at = end + close.length;
  }
}
const firstInner = (text, tag) => {
  for (const el of elements(text, tag)) return el.inner;
  return '';
};
const withoutElements = (text, tag) => {
  let out = '';
  let at = 0;
  for (const el of elements(text, tag)) {
    out += text.slice(at, el.start);
    at = el.end;
  }
  return out + text.slice(at);
};

module.exports = {
  id: 'maven',
  label: 'the Maven package',
  csvTypes: ['maven', 'java', 'gradle', 'jar', 'jvm', 'kotlin'],
  validName: (n) => mavenName.valid(n),
  badName: 'that is not a Maven package, written groupId:artifactId like com.fasterxml.jackson.core:jackson-databind',
  // a repository path is case sensitive, and so is a coordinate
  killKey: (n) => String(n || '').trim(),
  canonical: async (n) => String(n || '').trim(),
  spell: (n, v) => `${n}:${v}`,
  version: mavenVersion,
  rulePattern: {
    re: /^[A-Za-z0-9_*][A-Za-z0-9_.*-]*(?::[A-Za-z0-9_*][A-Za-z0-9_.*-]*)?$/,
    max: mavenName.MAX,
    message: 'a Maven pattern is groupId:artifactId, with a * where you want to match anything, like org.apache.maven.plugins:* or com.acme.*'
  },
  rangeHelp: 'It takes forms like 2.17.2, [2.17,2.18), 2.17.* or >=2.17 <2.18, with || between alternatives',
  upstreamPattern: { re: /^[A-Za-z0-9_*][A-Za-z0-9_.*:-]*$/, example: 'com.acme.*', message: 'a Maven pattern looks like groupId:artifactId, like com.acme.*, with a * where you want to match anything' },
  // 2.17.2 or [2.17.2], nothing with a range in it. null when a side is not exact
  exactPins(range) {
    const out = [];
    for (const raw of String(range || '').split('||')) {
      const t = raw.trim();
      if (!t) continue;
      const m = /^\[?([^\s,[\]()*<>=]+)\]?$/.exec(t);
      if (!m || !mavenVersion.valid(m[1]) || t.startsWith('[') !== t.endsWith(']')) return null;
      out.push(m[1]);
    }
    return out.length ? [...new Set(out)] : null;
  },
  osv: { ecosystem: 'Maven', fixKey: (n) => `maven:${n}` },
  // a Maven listing has no listed flag, every release is listed. publish times only for the newest few
  async versions(name) {
    const { doc } = await upstream().metadata(name);
    return { id: name, versions: doc.versions.map((v) => ({ version: v, listed: true, published: (doc.times || {})[v] || null })) };
  },
  // the pom always, and the jar when there is one (a pom packaged module has none)
  async fetch(id, version) {
    const c = mavenName.split(id);
    const out = [await upstream().getFile(id, version, `${c.artifactId}-${version}.pom`)];
    try {
      out.push(await upstream().getFile(id, version, `${c.artifactId}-${version}.jar`));
    } catch (err) {
      if (err.status !== 404) throw err;
    }
    return out;
  },
  async license(name, version) {
    const spdx = require('../../policy/licenses/spdx');
    const names = await upstream().pomLicenses(name, version);
    return spdx.fromMaven(names);
  },
  // what the pom asks for. dependencyManagement is only defaults for children, not what this one needs, and a version
  // written as a property is filled in from the pom's own properties. test and provided are marked optional.
  // pomText already stops at 4 MB, and everything below is linear in that
  async dependencies(name, version) {
    const text = withoutElements(await upstream().pomText(name, version), 'dependencyManagement');
    const props = {};
    for (const p of firstInner(text, 'properties').matchAll(/<([A-Za-z0-9_.-]+)>([^<]*)<\/\1>/g)) props[p[1]] = p[2].trim();
    const fill = (v) => String(v || '').replace(/\$\{([^}]+)\}/g, (all, key) => (key === 'project.version' || key === 'version' ? version : (props[key] !== undefined ? props[key] : all)));
    const tag = (block, t) => ((new RegExp(`<${t}>([^<]*)</${t}>`).exec(block) || [])[1] || '').trim();
    const out = [];
    const block = firstInner(text, 'dependencies');
    for (const { inner: d } of elements(block, 'dependency')) {
      const g = tag(d, 'groupId');
      const a = tag(d, 'artifactId');
      if (!g || !a || g.includes('${')) continue;
      const scope = tag(d, 'scope').toLowerCase();
      const range = fill(tag(d, 'version'));
      out.push({ name: `${g}:${a}`, range: range.includes('${') ? '' : range, scope: scope === 'test' || scope === 'provided' || tag(d, 'optional') === 'true' ? 'optional' : 'required' });
    }
    return out.slice(0, 500);
  }
};
