// Maven coordinates: groupId:artifactId, the way OSV and people write them, and the path they live under.
// Author: Tim Rice
// a group is dotted words, an artifact one word. nothing in either can climb out of its folder

const MAX = 255;
const GROUP_RE = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;
const ARTIFACT_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

function split(name) {
  const s = String(name || '').trim();
  const i = s.indexOf(':');
  if (i <= 0 || s.indexOf(':', i + 1) !== -1) return null;
  const groupId = s.slice(0, i);
  const artifactId = s.slice(i + 1);
  if (!GROUP_RE.test(groupId) || !ARTIFACT_RE.test(artifactId) || artifactId.includes('..') || s.length > MAX) return null;
  return { groupId, artifactId };
}

const valid = (name) => !!split(name);
const join = (groupId, artifactId) => `${groupId}:${artifactId}`;

// com.fasterxml.jackson.core:jackson-databind -> com/fasterxml/jackson/core/jackson-databind
function pathOf(name) {
  const c = split(name);
  return c ? `${c.groupId.split('.').join('/')}/${c.artifactId}` : null;
}

module.exports = { MAX, GROUP_RE, ARTIFACT_RE, split, valid, join, pathOf };
