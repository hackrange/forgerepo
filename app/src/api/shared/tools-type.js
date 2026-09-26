// Portal API, per ecosystem name and version rules for the tools pages.
// Author: Tim Rice

const semver = require('semver');
const upstream = require('../../registry/npm/upstream');
const ecosystems = require('../../ecosystems');
const pypiName = require('../../ecosystems/pypi/name');
const pypiVersion = require('../../ecosystems/pypi/version');
const ociName = require('../../ecosystems/oci/name');

// per-ecosystem name/version rules. nothing named = npm
function toolsType(ecosystem) {
  // an image was falling through to npm's rules, so latest was "not a version range npm would understand"
  if (ecosystem === 'oci') {
    return {
      id: 'oci',
      adapter: ecosystems.adapter('oci'),
      validName: (n) => ociName.valid(n),
      badName: 'that is not a valid image name. it takes forms like nginx, bitnami/redis or org/team/app',
      name: (n) => ociName.fold(n),
      validVersion: (v) => ociName.validTag(v) || ociName.isDigest(v),
      spell: (n, v) => (ociName.isDigest(v) ? `${n}@${v}` : `${n}:${v}`),
      // no dependency tree and no version list to walk. an image is looked at when it is pulled
      walks: false
    };
  }
  const kind = require('../../registry/kinds').get(ecosystem);
  if (kind) {
    return {
      id: kind.id,
      adapter: ecosystems.adapter(kind.id),
      validName: (n) => kind.validName(n),
      badName: kind.badName,
      name: (n) => n,
      validVersion: (v) => kind.version.valid(v),
      spell: kind.spell,
      // no dependency tree walk for the newer types yet, what they pull in is checked when it is downloaded
      walks: false
    };
  }
  if (ecosystem === 'pypi') {
    return {
      id: 'pypi',
      adapter: ecosystems.adapter('pypi'),
      validName: (n) => pypiName.valid(n),
      badName: 'that is not a valid project name',
      name: (n) => pypiName.normalize(n),
      validVersion: (v) => pypiVersion.valid(v),
      spell: (n, v) => `${n}==${v}`
    };
  }
  return {
    id: 'npm',
    adapter: ecosystems.adapter('npm'),
    validName: (n) => upstream.validName(n),
    badName: 'that is not a valid package name',
    name: (n) => n,
    validVersion: (v) => !!semver.valid(v),
    spell: (n, v) => `${n}@${v}`
  };
}

module.exports = { toolsType };
