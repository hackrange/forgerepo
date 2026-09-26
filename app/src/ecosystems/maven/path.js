// Reading a Maven repository path: which package, which version, which file, and which checksum of it if any.
// Author: Tim Rice
//
// com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml is the version list of
// com.fasterxml.jackson.core:jackson-databind, and .../2.17.2/jackson-databind-2.17.2.jar one of its files. a file has
// to be named after its own artifact and version, so a path can not reach anything else. anything that does not read
// cleanly is null

const name = require('./name');
const version = require('./version');

const CHECKSUMS = ['sha1', 'md5', 'sha256', 'sha512'];
// what a release carries. .asc is a signature, handed on as its own file
const EXTENSIONS = ['jar', 'pom', 'war', 'ear', 'aar', 'module', 'zip', 'tar.gz', 'tgz', 'klib', 'json', 'xml', 'txt', 'asc', 'exe', 'so', 'nbm', 'hpi', 'jpi'];
const SEGMENT_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+-]*$/;
const CLASSIFIER_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;

function checksumOf(file) {
  for (const c of CHECKSUMS) if (file.endsWith(`.${c}`)) return { base: file.slice(0, -(c.length + 1)), checksum: c };
  return { base: file, checksum: null };
}

// a file of artifactId at version: artifactId-version[-classifier].ext
function fileParts(file, artifactId, v) {
  const lead = `${artifactId}-${v}`;
  if (!file.startsWith(lead)) return null;
  const rest = file.slice(lead.length);
  const ext = EXTENSIONS.find((e) => rest === `.${e}` || (rest.endsWith(`.${e}`) && rest.startsWith('-')));
  if (!ext) return null;
  const classifier = rest === `.${ext}` ? '' : rest.slice(1, -(ext.length + 1));
  if (classifier && !CLASSIFIER_RE.test(classifier)) return null;
  return { classifier, ext };
}

function parse(path) {
  const raw = String(path || '');
  if (!raw.startsWith('/') || raw.length > 1024 || raw.includes('//') || raw.includes('\\')) return null;
  const segs = raw.slice(1).split('/');
  if (segs.some((s) => !SEGMENT_RE.test(s) || s === '.' || s === '..')) return null;
  const last = segs[segs.length - 1];
  const { base, checksum } = checksumOf(last);

  // group/artifact/maven-metadata.xml: the version list
  if (base === 'maven-metadata.xml' && segs.length >= 3) {
    const artifactId = segs[segs.length - 2];
    const groupId = segs.slice(0, -2).join('.');
    // a version folder's metadata is a snapshot's, and this box serves releases only
    if (version.isSnapshot(artifactId)) return { kind: 'snapshot' };
    const n = name.join(groupId, artifactId);
    return name.valid(n) ? { kind: 'metadata', name: n, checksum } : null;
  }
  if (segs.length < 4) return null;
  const v = segs[segs.length - 2];
  const artifactId = segs[segs.length - 3];
  const groupId = segs.slice(0, -3).join('.');
  const n = name.join(groupId, artifactId);
  if (!name.valid(n) || !version.valid(v)) return null;
  if (version.isSnapshot(v)) return { kind: 'snapshot' };
  const parts = fileParts(base, artifactId, v);
  if (!parts) return null;
  return { kind: 'file', name: n, version: v, filename: base, classifier: parts.classifier, ext: parts.ext, checksum };
}

module.exports = { CHECKSUMS, EXTENSIONS, parse, fileParts };
