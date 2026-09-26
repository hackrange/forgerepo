// The package types that came after npm, PyPI and images, each described once in registry/<type>/kind.js: how its
// names and versions are checked, how a version list and a version's files are fetched, how the advisory feed spells
// it, how its license is read. the rules, requests, kill switch, auto approve, Cache now and the rest ask here instead
// of each growing a branch per type.
// Author: Tim Rice

// loaded on first use, a kind pulls in its registry code and that must not happen while the database is still loading
const LOADERS = {
  nuget: () => require('./nuget/kind'),
  maven: () => require('./maven/kind'),
  rubygems: () => require('./rubygems/kind'),
  cocoapods: () => require('./cocoapods/kind'),
  swift: () => require('./swift/kind'),
  composer: () => require('./composer/kind'),
  rpm: () => require('./rpm/kind'),
  apt: () => require('./apt/kind')
};

const loaded = new Map();

function get(id) {
  const key = String(id || '');
  if (!Object.prototype.hasOwnProperty.call(LOADERS, key)) return null;
  if (!loaded.has(key)) loaded.set(key, LOADERS[key]());
  return loaded.get(key);
}

const ids = () => Object.keys(LOADERS);

module.exports = { get, ids };
