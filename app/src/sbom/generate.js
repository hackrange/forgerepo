// SBOMs out of what the cache knows, as CycloneDX 1.5 JSON or SPDX 2.3 JSON.
// Author: Tim Rice
// no db and no clock in here: the caller hands over the time, so the same input always comes out the same

const crypto = require('node:crypto');

const FORMATS = ['cyclonedx', 'spdx'];

// the purl type and path of each package type. names as this box keeps them: maven group:artifact, composer
// vendor/name, swift scope.name, a pod's subspec after a slash. rpm and deb have no vendor here, so none is written
const esc = encodeURIComponent;
const PURLS = {
  npm: (n) => ['npm', n.startsWith('@') && n.includes('/') ? `${esc(n.slice(0, n.indexOf('/')))}/${esc(n.slice(n.indexOf('/') + 1))}` : esc(n)],
  pypi: (n) => ['pypi', esc(n)],
  nuget: (n) => ['nuget', esc(n)],
  maven: (n) => ['maven', n.includes(':') ? `${esc(n.slice(0, n.indexOf(':')))}/${esc(n.slice(n.indexOf(':') + 1))}` : esc(n)],
  rubygems: (n) => ['gem', esc(n)],
  composer: (n) => ['composer', n.split('/').map(esc).join('/')],
  cocoapods: (n) => ['cocoapods', esc(n.split('/')[0])],
  swift: (n) => ['swift', n.includes('.') ? `${esc(n.slice(0, n.indexOf('.')))}/${esc(n.slice(n.indexOf('.') + 1))}` : esc(n)],
  rpm: (n) => ['rpm', esc(n)],
  apt: (n) => ['deb', esc(n)]
};

// pkg:npm/%40scope/name@1.0.0, pkg:pypi/requests@2.32.0, pkg:maven/org.slf4j/slf4j-api@2.0.13, pkg:oci/nginx@sha256%3A...
function purl(ecosystem, name, version) {
  if (ecosystem === 'oci') {
    // the purl spec names an image by its last segment, the version is the digest and a tag is a qualifier
    const text = String(name);
    const last = text.slice(text.lastIndexOf('/') + 1);
    const digest = version && /^sha256:[a-f0-9]{64}$/.test(version);
    const q = [`repository_url=${encodeURIComponent(text)}`, ...(version && !digest ? [`tag=${encodeURIComponent(version)}`] : [])];
    return `pkg:oci/${encodeURIComponent(last)}${digest ? `@${encodeURIComponent(version)}` : ''}?${q.join('&')}`;
  }
  const text = String(name);
  // a type this file has not heard of is written as generic, never passed off as npm
  const [type, path] = (Object.prototype.hasOwnProperty.call(PURLS, ecosystem) ? PURLS[ecosystem] : (n) => ['generic', esc(n)])(text);
  const sub = ecosystem === 'cocoapods' && text.includes('/') ? `#${text.split('/').slice(1).map(esc).join('/')}` : '';
  return `pkg:${type}/${path}${version ? `@${esc(version)}` : ''}${sub}`;
}

// a uuid shaped digest of what the document is about. same subject, same serial
function uuidFrom(text) {
  const hex = crypto.createHash('sha256').update(String(text)).digest('hex');
  const variant = ((parseInt(hex[16], 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

// a component nobody could pin to a cached version is still listed, by the range it asked for
function refOf(c) {
  if (c.purl) return c.purl;
  // an application is not a package, it gets no purl
  if (c.kind === 'application') return `urn:forgerepo:application:${encodeURIComponent(c.name)}${c.scope ? `:${encodeURIComponent(c.scope)}` : ''}`;
  if (c.version) return purl(c.ecosystem, c.name, c.version);
  const bare = purl(c.ecosystem, c.name);
  return `${bare}${bare.includes('?') ? '&' : '?'}range=${encodeURIComponent(c.range || '*')}`;
}

function serialOf(subject) {
  return uuidFrom([subject.kind, subject.ecosystem || '', subject.name, subject.version || '', ...(subject.sha256s || []), subject.scope || ''].join('\n'));
}

// what an image scan calls a package's feed, to the purl type, vendor and distro of an OS package
function osPurl(type, name, version, feed) {
  const f = String(feed || '');
  let m;
  let ns = '';
  let distro = '';
  if ((m = /^Debian:(\d+)/.exec(f))) [ns, distro] = ['debian', `debian-${m[1]}`];
  else if ((m = /^Ubuntu:([\d.]+)/.exec(f))) [ns, distro] = ['ubuntu', `ubuntu-${m[1]}`];
  else if ((m = /^Alpine:v?([\d.]+)/.exec(f))) [ns, distro] = ['alpine', `alpine-${m[1]}`];
  else if (f === 'Wolfi') ns = 'wolfi';
  else if (f === 'Chainguard') ns = 'chainguard';
  else if ((m = /^Red Hat:enterprise_linux:(\d+)/.exec(f))) [ns, distro] = ['redhat', `rhel-${m[1]}`];
  else if ((m = /^Rocky Linux:(\d+)/.exec(f))) [ns, distro] = ['rocky', `rocky-${m[1]}`];
  else if ((m = /^AlmaLinux:(\d+)/.exec(f))) [ns, distro] = ['almalinux', `almalinux-${m[1]}`];
  const q = [];
  // a deb scan records the source package, which purl marks with arch=source
  if (type === 'deb') q.push('arch=source');
  if (distro) q.push(`distro=${distro}`);
  return `pkg:${type}/${ns ? `${ns}/` : ''}${esc(name)}${version ? `@${esc(version)}` : ''}${q.length ? `?${q.join('&')}` : ''}`;
}

function cycloneComponent(c, type) {
  const out = { type, 'bom-ref': refOf(c) };
  const name = String(c.name);
  if (c.ecosystem === 'npm' && name.startsWith('@') && name.includes('/')) {
    out.group = name.slice(0, name.indexOf('/'));
    out.name = name.slice(name.indexOf('/') + 1);
  } else if ((c.ecosystem === 'maven' && name.includes(':')) || (c.ecosystem === 'composer' && name.includes('/'))) {
    const cut = c.ecosystem === 'maven' ? name.indexOf(':') : name.indexOf('/');
    out.group = name.slice(0, cut);
    out.name = name.slice(cut + 1);
  } else {
    out.name = name;
  }
  if (c.version) {
    out.version = c.version;
    if (c.purl) out.purl = c.purl;
    else if (c.ecosystem) out.purl = purl(c.ecosystem, c.name, c.version);
  }
  if (c.scope) out.scope = c.scope;
  if (c.sha256s && c.sha256s.length) out.hashes = c.sha256s.map((h) => ({ alg: 'SHA-256', content: h }));
  if (c.license) out.licenses = [{ expression: c.license }];
  else if (c.licenseName) out.licenses = [{ license: { name: c.licenseName } }];
  const props = [];
  if (!c.version && c.range) props.push({ name: 'forgerepo:range', value: c.range });
  for (const f of c.files || []) props.push({ name: 'forgerepo:file', value: `${f.filename} sha256:${f.sha256}` });
  for (const [k, v] of Object.entries(c.properties || {})) props.push({ name: `forgerepo:${k}`, value: String(v) });
  if (props.length) out.properties = props;
  // what is inside it, an image's packages
  if (Array.isArray(c.contains) && c.contains.length) out.components = c.contains.map((x) => cycloneComponent(x, 'library'));
  return out;
}

function cyclonedx({ subject, components, notes, toolVersion, now }) {
  const top = cycloneComponent(subject, subject.kind === 'application' ? 'application' : subject.kind === 'image' ? 'container' : 'library');
  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${serialOf(subject)}`,
    version: 1,
    metadata: {
      timestamp: now,
      tools: { components: [{ type: 'application', name: 'ForgeRepo', version: String(toolVersion || '') }] },
      component: top
    },
    components: components.map((c) => cycloneComponent(c, 'library')),
    dependencies: [{ ref: top['bom-ref'], dependsOn: [...new Set(components.map(refOf))] }]
  };
  if (notes && notes.length) doc.metadata.properties = notes.map((n) => ({ name: 'forgerepo:note', value: n }));
  return doc;
}

// SPDX wants a URI that is unique per document, it never has to resolve
function spdx({ subject, components, notes, toolVersion, now, namespace }) {
  const pkg = (c, id) => {
    const out = {
      SPDXID: id,
      name: String(c.name),
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: c.license || 'NOASSERTION',
      copyrightText: 'NOASSERTION'
    };
    if (c.version) out.versionInfo = c.version;
    if (c.sha256s && c.sha256s.length) out.checksums = c.sha256s.map((h) => ({ algorithm: 'SHA256', checksumValue: h }));
    if (c.version && (c.purl || c.ecosystem)) {
      out.externalRefs = [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: c.purl || purl(c.ecosystem, c.name, c.version) }];
    }
    const comment = [];
    if (!c.license && c.licenseName) comment.push(`license as published: ${c.licenseName}`);
    if (!c.version && c.range) comment.push(`not pinned, asks for ${c.range}`);
    if (c.scope === 'optional') comment.push('optional');
    for (const f of c.files || []) comment.push(`file ${f.filename} sha256:${f.sha256}`);
    if (comment.length) out.comment = comment.join('; ');
    return out;
  };
  const serial = serialOf(subject);
  const packages = [pkg(subject, 'SPDXRef-Subject'), ...components.map((c, i) => pkg(c, `SPDXRef-Package-${i + 1}`))];
  // an image contains its packages rather than depending on them. the subject's own contents hang off the subject
  const inside = subject.kind === 'image' ? 'CONTAINS' : 'DEPENDS_ON';
  const relationships = [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Subject' }]
    .concat(components.map((c, i) => ({ spdxElementId: 'SPDXRef-Subject', relationshipType: inside, relatedSpdxElement: `SPDXRef-Package-${i + 1}` })));
  components.forEach((c, i) => {
    (Array.isArray(c.contains) ? c.contains : []).forEach((x, j) => {
      const id = `SPDXRef-Package-${i + 1}-${j + 1}`;
      packages.push(pkg(x, id));
      relationships.push({ spdxElementId: `SPDXRef-Package-${i + 1}`, relationshipType: 'CONTAINS', relatedSpdxElement: id });
    });
  });
  const doc = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${subject.name}${subject.version ? `@${subject.version}` : ''}`,
    documentNamespace: `${String(namespace || 'https://forgerepo.invalid').replace(/\/+$/, '')}/spdx/${serial}`,
    creationInfo: { created: String(now).replace(/\.\d{3}Z$/, 'Z'), creators: [`Tool: ForgeRepo-${toolVersion || ''}`] },
    packages,
    relationships
  };
  if (notes && notes.length) doc.comment = notes.join(' ');
  return doc;
}

function build(format, input) {
  return format === 'spdx' ? spdx(input) : cyclonedx(input);
}

module.exports = { FORMATS, purl, osPurl, uuidFrom, refOf, cyclonedx, spdx, build };
