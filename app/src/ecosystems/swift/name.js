// Swift package identities, the scope.name the package registry protocol uses (SE-0292).
// Author: Tim Rice
//
// the scope is who publishes it, the name the package: apple.swift-argument-parser. identities are compared without
// case. on GitHub the scope is the owner and the name the repository, which is how this box finds the code

const SCOPE_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|[-_](?=[A-Za-z0-9])){0,99}$/;

function split(id) {
  const s = String(id || '').trim();
  const i = s.indexOf('.');
  if (i <= 0) return null;
  const scope = s.slice(0, i);
  const name = s.slice(i + 1);
  return SCOPE_RE.test(scope) && NAME_RE.test(name) ? { scope, name } : null;
}

const valid = (id) => !!split(id);
const validScope = (s) => SCOPE_RE.test(String(s || ''));
const validName = (n) => NAME_RE.test(String(n || ''));
const fold = (id) => String(id || '').trim().toLowerCase();

module.exports = { split, valid, validScope, validName, fold };
