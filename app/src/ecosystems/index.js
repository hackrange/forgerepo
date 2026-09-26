// The ecosystems this box knows about. The ones after images are also described in registry/kinds.js.
// Author: Tim Rice
// npm is always on, PyPI and images hide behind a setting

const npm = require('./npm');
const pypi = require('./pypi');
const oci = require('./oci');
const nuget = require('./nuget');
const maven = require('./maven');
const rubygems = require('./rubygems');
const cocoapods = require('./cocoapods');
const swift = require('./swift');
const composer = require('./composer');
const rpm = require('./rpm');
const apt = require('./apt');

const ALL = [
  { id: 'npm', name: 'npm', label: 'npm registry', adapter: npm, setting: null },
  { id: 'pypi', name: 'PyPI', label: 'PyPI registry', adapter: pypi, setting: 'pypi_enabled' },
  { id: 'oci', name: 'images', label: 'container images', adapter: oci, setting: 'oci_enabled' },
  { id: 'nuget', name: 'NuGet', label: 'NuGet feed', adapter: nuget, setting: 'nuget_enabled' },
  { id: 'maven', name: 'Maven', label: 'Maven repository', adapter: maven, setting: 'maven_enabled' },
  { id: 'rubygems', name: 'RubyGems', label: 'RubyGems source', adapter: rubygems, setting: 'rubygems_enabled' },
  { id: 'cocoapods', name: 'CocoaPods', label: 'CocoaPods CDN', adapter: cocoapods, setting: 'cocoapods_enabled' },
  { id: 'swift', name: 'Swift', label: 'Swift package registry', adapter: swift, setting: 'swift_enabled' },
  { id: 'composer', name: 'Composer', label: 'Composer repository', adapter: composer, setting: 'composer_enabled' },
  { id: 'rpm', name: 'RPM', label: 'RPM mirror', adapter: rpm, setting: 'rpm_enabled' },
  { id: 'apt', name: 'APT', label: 'APT mirror', adapter: apt, setting: 'apt_enabled' }
];

const BY_ID = new Map(ALL.map((e) => [e.id, e]));

function get(id) {
  return BY_ID.get(String(id || '')) || null;
}

function adapter(id) {
  const e = get(id);
  return e ? e.adapter : null;
}

// which ones are switched on, given something that can read a setting
function enabled(isOn) {
  return ALL.filter((e) => !e.setting || isOn(e.setting));
}

module.exports = { ALL, get, adapter, enabled };
