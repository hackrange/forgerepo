// ForgeRepo portal: package types.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';

// The server says which types are switched on. This only knows how to draw them,
// a type it has never heard of gets npm's hints and its own id as a name
var HINTS = {
  npm: { spec: '@', icon: 'npm', example: 'express', pattern: '@acme/*', version: '1.2.3', range: 'optional version range', url: 'https://registry.example.com' },
  pypi: { spec: '==', icon: 'pypi', example: 'requests', pattern: 'acme-*', version: '2.31.0', range: 'optional, like >=2.31,<3', url: 'https://pypi.org' },
  oci: { spec: ':', icon: 'box', example: 'nginx or bitnami/redis', pattern: 'acme/*', version: 'latest', range: 'optional tags, like latest, 1.27.* or a sha256 digest', url: 'https://registry-1.docker.io' },
  nuget: { spec: ' ', icon: 'nuget', example: 'Newtonsoft.Json', pattern: 'Acme.*', version: '13.0.3', range: 'optional, like 13.0.3, [13.0,14.0) or 13.*', url: 'https://api.nuget.org/v3/index.json' },
  apt: { spec: ' ', icon: 'apt', example: 'libssl3', pattern: '', version: '3.0.11-1~deb12u2', range: 'optional, like 3.0.11-1~deb12u2 or >=3.0.11', url: 'https://deb.debian.org/debian' },
  rpm: { spec: ' ', icon: 'rpm', example: 'openssl-libs', pattern: '', version: '3.0.7-27.el9', range: 'optional, like 3.0.7-27.el9 or >=3.0.7', url: 'https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os' },
  composer: { spec: ' ', icon: 'composer', example: 'monolog/monolog', pattern: 'acme/*', version: '3.5.0', range: 'optional, like 3.5.0, ^3.5 or >=3.5 <4.0', url: 'https://repo.packagist.org' },
  swift: { spec: ' ', icon: 'swift', example: 'apple.swift-log', pattern: 'acme.*', version: '1.6.1', range: 'optional, like 1.6.1, ^1.6.0 or >=1.6 <2', url: 'https://github.com' },
  cocoapods: { spec: ' ', icon: 'cocoapods', example: 'Alamofire', pattern: 'Acme*', version: '5.9.1', range: 'optional, like 5.9.1 or ~> 5.9', url: 'https://cdn.cocoapods.org' },
  rubygems: { spec: ' ', icon: 'rubygems', example: 'rack', pattern: 'acme-*', version: '3.1.8', range: 'optional, like 3.1.8, ~> 3.1 or >= 3.0, < 4', url: 'https://rubygems.org' },
  maven: { spec: ':', icon: 'maven', example: 'com.fasterxml.jackson.core:jackson-databind', pattern: 'com.acme.*', version: '2.17.2', range: 'optional, like 2.17.2, [2.17,2.18) or 2.17.*', url: 'https://repo1.maven.org/maven2' }
};

function ecoList() {
  return state.ecosystems || [];
}

function ecoHints(id) {
  return HINTS[id] || HINTS.npm;
}

// names for switched off types too, old rows still carry them
function ecoName(id) {
  id = id || 'npm';
  var t = ecoList().filter(function (x) { return x.id === id; })[0];
  return t ? t.name : ((state.ecosystemNames || {})[id] || id);
}

// npm rows have always been shown bare, anything else says what it is
function ecoPrefix(id) {
  return !id || id === 'npm' ? '' : ecoName(id) + ' ';
}

// the marks people know each ecosystem by, in their own colors, so a row says what it is at a glance.
// drawn here rather than fetched, the portal loads nothing from outside
var MARKS = {
  npm: [['#CB3837', 'M0 2a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2z'], ['#fff', 'M3 4h10v8h-2.6V6.6H8v5.4H3z']],
  pypi: [
    ['#3776AB', 'M7.9 1C4.8 1 5 2.4 5 2.4v1.5h3v.5H3.7S1.6 4.1 1.6 7.4c0 3.2 1.8 3.1 1.8 3.1h1.1V8.9s-.1-1.8 1.8-1.8h3c1.8 0 1.7-1.7 1.7-1.7V2.8S11.3 1 7.9 1zM6.2 2.1a.6.6 0 1 1 0 1.1.6.6 0 0 1 0-1.1z'],
    ['#FFD43B', 'M8.1 15c3.1 0 2.9-1.4 2.9-1.4v-1.5H8v-.5h4.3s2.1.3 2.1-3.1c0-3.2-1.8-3.1-1.8-3.1h-1.1v1.6s.1 1.8-1.8 1.8h-3c-1.8 0-1.7 1.7-1.7 1.7v2.6S4.7 15 8.1 15zm1.7-1.1a.6.6 0 1 1 0-1.1.6.6 0 0 1 0 1.1z']
  ],
  // Debian's red swirl, simply a ring with a gap
  apt: [['#A80030', 'M8 1a7 7 0 1 1-6.6 9.3l2-.7A4.9 4.9 0 1 0 8 3.1z']],
  // a red box, the package, with its white lid
  rpm: [['#CC0000', 'M1 4.5 8 1l7 3.5v7L8 15l-7-3.5z'], ['#fff', 'M8 2.6 13.2 5.2 8 7.8 2.8 5.2zM2.5 6.3l5 2.5v5.1l-5-2.5z']],
  // PHP's purple, with a white note for the conductor Composer is named after
  composer: [['#777BB4', 'M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0z'], ['#fff', 'M10.5 3.5v6.3a2.2 2.2 0 1 1-1.2-2V5.2L6.6 5.9v5.4a2.2 2.2 0 1 1-1.2-2V4.9z']],
  // Swift's orange tile with its white swift in flight
  swift: [['#F05138', 'M0 3a3 3 0 0 1 3-3h10a3 3 0 0 1 3 3v10a3 3 0 0 1-3 3H3a3 3 0 0 1-3-3z'], ['#fff', 'M12.6 10.9c.9-2.6-.4-5.7-3.1-7.6 1.1 1.6 1.6 3.6 1 5.2C8.9 7.4 6.4 5.3 4.4 3.8c1 1.4 2.1 2.5 3.2 3.6-1.6-.9-3.7-2.4-4.6-3.3 1.4 2.2 3.4 4.2 5.5 5.6-1.9.8-4 .6-5.8-.5 1.7 2.1 4.4 3.3 7.1 2.8 1-.2 1.9.1 2.6.9.3-.8.4-1.4.2-2z']],
  // CocoaPods' red circle with its white pod shape
  cocoapods: [['#EE3322', 'M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0z'], ['#fff', 'M4.2 5.2h5.3c1.6 0 2.8 1.2 2.8 2.8s-1.2 2.8-2.8 2.8H4.2zm1.6 1.5v2.6h3.7c.7 0 1.3-.6 1.3-1.3s-.6-1.3-1.3-1.3z']],
  // a red ruby, cut the way the gem logo is
  rubygems: [['#E9573F', 'M4 1.5h8l3.5 4-7.5 9.5-7.5-9.5z'], ['#fff', 'M4.6 2.6h6.8l2.3 2.6H2.3zM3 6.3h10l-5 6.3z']],
  // a Maven feather in Apache red, simplified to a slanted blade
  maven: [['#C71A36', 'M0 2a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2z'],
    ['#fff', 'M11.9 2.6c-3.4.9-6 3.9-7 7.5l-.8 3.3.9.3.9-2.7c1.9-.1 3.6-1 4.7-2.5l-1.8-.2 2.3-1c.6-1.4.9-3 .8-4.7z']],
  // NuGet's blue square with its two dots
  nuget: [['#004880', 'M0 2a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2z'],
    ['#fff', 'M2.8 4.6a1.7 1.7 0 1 0 3.4 0a1.7 1.7 0 1 0-3.4 0zM6 10.2a3.8 3.8 0 1 0 7.6 0a3.8 3.8 0 1 0-7.6 0z']],
  oci: [['#1D63ED', 'M15.6 7.2c-.4-.3-1.3-.4-2-.3-.1-.7-.5-1.3-1.1-1.8l-.3-.2-.2.3c-.3.5-.4 1.2-.3 1.8 0 .3.2.6.4.9-.5.3-1.1.3-1.6.3H.5l-.1.3c-.1 1.2.1 2.4.6 3.5.5.9 1.3 1.6 2.2 2 1.1.4 2.3.6 3.5.5 1 0 2-.2 2.9-.5 1.4-.5 2.6-1.4 3.5-2.6.8-1 1.3-2.2 1.6-3.4h.2c.7 0 1.3-.3 1.7-.8l.1-.2-.2-.1zM2 6.5h1.4v1.3H2zm1.8 0h1.4v1.3H3.8zm1.8 0H7v1.3H5.6zm1.8 0h1.4v1.3H7.4zm-3.6-1.7h1.4v1.3H3.8zm1.8 0H7v1.3H5.6zm1.8 0h1.4v1.3H7.4zm0-1.7h1.4v1.3H7.4zm1.8 3.4h1.4v1.3H9.2z']]
};
var SVGNS = 'http://www.w3.org/2000/svg';

function ecoIcon(id) {
  id = id || 'npm';
  var svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('class', 'eco-mark');
  svg.setAttribute('role', 'img');
  // labeled for screen readers, but no <title> inside: that would put "npm" in front of the name when the text is
  // copied or read. the hover hint sits on the span around it
  svg.setAttribute('aria-label', ecoName(id));
  (MARKS[id] || [['currentColor', 'M2 2h12v12H2z']]).forEach(function (m) {
    var path = document.createElementNS(SVGNS, 'path');
    path.setAttribute('fill', m[0]);
    path.setAttribute('fill-rule', 'evenodd');
    path.setAttribute('d', m[1]);
    svg.appendChild(path);
  });
  return svg;
}

// the mark and the type's name, for Type columns
function ecoTag(id) {
  return h('span', { class: 'eco-tag', title: ecoName(id) }, [ecoIcon(id), ecoName(id)]);
}

// the mark and a package name, for the name cell of any list
function ecoPkg(id, name, title) {
  return h('span', { class: 'eco-pkg', title: title || ecoName(id) }, [ecoIcon(id), h('span', { class: 'mono' }, [name || ''])]);
}

function ecoSpec(id, name, version) {
  // an image digest is spelled name@sha256:..., a tag name:tag
  if (id === 'oci' && /^sha256:/.test(String(version))) return name + '@' + version;
  return name + ecoHints(id || 'npm').spec + version;
}

// placeholders that follow a type picker. fields: [[input, { npm: '..', pypi: '..', oci: '..' }], ...]
function ecoPlaceholders(select, fields) {
  function apply() {
    var id = select ? select.value : 'npm';
    fields.forEach(function (f) { f[0].placeholder = f[1][id] || f[1].npm; });
  }
  if (select) select.addEventListener('change', apply);
  apply();
}

// a picker only when there's something to pick. opts.all adds an everything option
function ecoSelect(types, opts) {
  opts = opts || {};
  types = types || ecoList();
  if (types.length < 2) return null;
  var chosen = opts.value || (opts.all ? '' : 'npm');
  var options = types.map(function (t) {
    return h('option', { value: t.id, selected: t.id === chosen }, [opts.label ? (t.label || t.name) : t.name]);
  });
  if (opts.all) options.unshift(h('option', { value: '', selected: chosen === '' }, [opts.all]));
  var select = h('select', null, options);
  if (opts.onchange) select.addEventListener('change', opts.onchange);
  return select;
}

export { ecoHints, ecoIcon, ecoList, ecoName, ecoPkg, ecoPlaceholders, ecoPrefix, ecoSelect, ecoSpec, ecoTag };
