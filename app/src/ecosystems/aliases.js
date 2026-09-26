// The words people use for a package type in a spreadsheet or another tool's export: nuget, .net, python, gem...
// Author: Tim Rice
// the kill switch CSV and the file review both read them, so they live here once

const BUILT_IN = {
  npm: 'npm', node: 'npm', nodejs: 'npm', 'node.js': 'npm', javascript: 'npm', js: 'npm', yarn: 'npm', pnpm: 'npm',
  pypi: 'pypi', python: 'pypi', pip: 'pypi', py: 'pypi', poetry: 'pypi', pipenv: 'pypi', uv: 'pypi',
  oci: 'oci', docker: 'oci', image: 'oci', images: 'oci', container: 'oci', 'container image': 'oci'
};

let words = null;

// built on first use, the kinds must not load while the database is still loading
function all() {
  if (!words) {
    const kinds = require('../registry/kinds');
    words = { ...BUILT_IN, ...Object.fromEntries(kinds.ids().flatMap((id) => [[id, id], ...kinds.get(id).csvTypes.map((t) => [t, id])])) };
  }
  return words;
}

// the ecosystem id a word means, or null
function typeOf(word) {
  const key = String(word || '').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(all(), key) ? all()[key] : null;
}

module.exports = { typeOf, all };
