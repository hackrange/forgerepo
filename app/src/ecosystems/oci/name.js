// Image names, tags and digests, spelled the way a registry does.
// Author: Tim Rice
//
// a repository name is lower case path segments (library/nginx, org/team/app). a reference is either a tag or a digest,
// and the two are never confused: a digest is content, a tag is a label somebody can move tomorrow

const SEGMENT = '[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*';
const NAME_RE = new RegExp(`^${SEGMENT}(?:/${SEGMENT})*$`);
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
// a pattern is a name with * allowed in place of a segment or part of one
const PATTERN_RE = /^[a-z0-9*][a-z0-9._\-*/]*$/;

const MAX_NAME = 255;

// names are compared lower case, with any leading or trailing slash dropped
// by hand, not /\/+$/, which crawls on a long run of slashes
function fold(text) {
  const s = String(text || '').trim();
  let a = 0;
  let b = s.length;
  while (a < b && s[a] === '/') a++;
  while (b > a && s[b - 1] === '/') b--;
  return s.slice(a, b).toLowerCase();
}

function foldPattern(pattern) {
  return fold(pattern);
}

function valid(text) {
  const name = fold(text);
  return !!name && name.length <= MAX_NAME && NAME_RE.test(name) && !name.includes('..');
}

function validPattern(pattern) {
  const p = foldPattern(pattern);
  return !!p && p.length <= MAX_NAME && PATTERN_RE.test(p) && !p.includes('..') && !p.includes('//');
}

const isDigest = (reference) => DIGEST_RE.test(String(reference || '').trim());
const validTag = (reference) => TAG_RE.test(String(reference || '').trim());

// what a client asked for: a digest pins content, a tag has to be resolved and can move
function reference(text) {
  const ref = String(text || '').trim();
  if (isDigest(ref)) return { digest: ref, tag: null };
  if (validTag(ref)) return { digest: null, tag: ref };
  return null;
}

// Docker Hub keeps its own images under library/, so nginx and library/nginx are one repository
function official(text) {
  const name = fold(text);
  return name.includes('/') ? name : `library/${name}`;
}

module.exports = { MAX_NAME, fold, foldPattern, valid, validPattern, validTag, isDigest, reference, official };
