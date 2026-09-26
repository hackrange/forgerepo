// ForgeRepo portal: consumers.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';
import { clear, notice, table, when } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';
import { ecoPkg, ecoPlaceholders, ecoPrefix, ecoSelect } from './ecosystems.js';

function viewConsumers(body) {
  var types = state.ecosystems || [];
  section(body, 'Consumers',
    'Who took a package, a version, a file or an advisory: which applications and environments, which people and pipelines, from which addresses, and when. ' +
    'Search a package name (narrowed to a version or range if you like), a sha256, or a CVE, GHSA or PYSEC id.');
  var type = ecoSelect(types);
  var q = h('input', { type: 'text', placeholder: 'lodash, a sha256, or CVE-2021-44228' });
  var version = h('input', { type: 'text', placeholder: 'optional version or range' });
  ecoPlaceholders(type, [
    [q, { npm: 'lodash, a sha256, or CVE-2021-44228', pypi: 'requests, a sha256, or PYSEC-2024-1', oci: 'nginx, a sha256, or CVE-2024-6119' }],
    [version, { npm: 'optional version or range', pypi: 'optional release or specifier', oci: 'optional tag or sha256 digest' }]
  ]);
  var out = h('div', null, []);
  var go = function () {
    var text = q.value.trim();
    if (!text) return;
    clear(out);
    out.appendChild(h('p', { class: 'hint' }, ['Looking...']));
    api('GET', '/consumers?q=' + encodeURIComponent(text) + '&ecosystem=' + (type ? type.value : 'npm') +
      (version.value.trim() ? '&version=' + encodeURIComponent(version.value.trim()) : ''))
      .then(function (d) { clear(out); consumersResult(out, d); })
      .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
  };
  q.addEventListener('keydown', function (e) { if (e.key === 'Enter') go(); });
  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Search']),
    h('div', { class: 'row' }, [
      type ? h('div', null, [h('label', null, ['Type']), type]) : null,
      h('div', null, [h('label', null, ['Package, sha256 or advisory']), q]),
      h('div', null, [h('label', null, ['Versions']), version])
    ]),
    h('p', { class: 'hint' }, ['Type and versions only matter for a package name.']),
    h('div', null, [h('button', { type: 'button', onclick: go }, ['Search'])]),
    out
  ]));

  // what one application pulled, as a document someone else's tooling can read
  var app = h('input', { type: 'text', placeholder: 'Checkout', maxlength: '128' });
  var env = h('input', { type: 'text', placeholder: 'optional, like production', maxlength: '128' });
  var sbomFor = function (format) {
    var name = app.value.trim();
    if (!name) return alert('Name the application.');
    download('/sbom/application?application=' + encodeURIComponent(name) + '&format=' + format +
      (env.value.trim() ? '&environment=' + encodeURIComponent(env.value.trim()) : ''),
    name + (env.value.trim() ? '-' + env.value.trim() : '') + (format === 'spdx' ? '.spdx.json' : '.cdx.json'));
  };
  body.appendChild(h('fieldset', null, [
    h('legend', null, ['SBOM of an application']),
    h('p', { class: 'hint' }, ['Every version the application downloaded through this registry, with the SHA-256 of each file still in the cache.']),
    h('div', { class: 'row' }, [
      h('div', null, [h('label', null, ['Application']), app]),
      h('div', null, [h('label', null, ['Environment']), env])
    ]),
    h('div', null, [
      h('button', { type: 'button', onclick: function () { sbomFor('cyclonedx'); } }, ['CycloneDX']),
      h('button', { type: 'button', onclick: function () { sbomFor('spdx'); } }, ['SPDX'])
    ])
  ]));
}

function consumersResult(out, d) {
  var s = d.summary;
  var what = d.query.kind === 'hash' ? 'the file with that sha256' : d.query.kind === 'advisory' ? d.query.advisory : d.query.name + (d.query.version ? ' ' + d.query.version : '');
  var since = d.since ? ' Downloads are remembered from ' + when(d.since) + '.' : '';
  if (!d.targets.length) {
    out.appendChild(notice((d.query.kind === 'hash' ? 'No cached file has that sha256.' : d.query.kind === 'advisory'
      ? 'No version this registry has seen carries ' + d.query.advisory + '.' : 'Nobody has downloaded ' + what + '.') + since, 'info'));
    return;
  }
  if (d.query.kind !== 'package') {
    out.appendChild(h('h3', null, [d.query.kind === 'hash' ? 'That sha256 is' : d.query.advisory + ' is on']));
    out.appendChild(table(['Package', 'Version', d.query.kind === 'hash' ? 'File' : 'Severity'], d.targets.map(function (t) {
      return [ecoPkg(t.ecosystem, t.package_name), t.version,
        d.query.kind === 'hash' ? h('span', { class: 'mono' }, [t.filename]) : String(t.severity || '').toLowerCase()];
    })));
  }
  if (!s.downloads) {
    out.appendChild(notice('Nobody has downloaded ' + what + '.' + since, 'ok'));
    return;
  }
  out.appendChild(notice(s.downloads + ' download(s) of ' + s.versions + ' version(s) by ' + s.applications + ' application(s), ' +
    s.productionApplications + ' of them in production, ' + s.users + ' developer(s) and ' + s.pipelines + ' pipeline(s) from ' + s.addresses +
    ' address(es). Last on ' + when(s.lastDownload) + '.' + since + (d.truncated ? ' Only the newest consumers are listed.' : ''),
    s.productionApplications ? 'warn' : 'info'));

  out.appendChild(h('h3', null, ['Where it is']));
  out.appendChild(table(['Application', 'Environment', 'Versions', { label: 'Downloads', num: true }, 'Last download'], d.applications.map(function (a) {
    return [a.application || h('span', { class: 'muted' }, ['no application']),
      h('span', null, [a.environment || '', a.production ? h('span', { class: 'badge deny' }, ['production']) : null]),
      a.versions.join(', '), String(a.downloads), when(a.lastSeen)];
  })));

  out.appendChild(h('h3', null, ['Every consumer']));
  out.appendChild(table(['Package', 'Version', 'Application', 'Environment', 'Who', 'CI', 'Address', { label: 'Downloads', num: true }, 'First', 'Last'],
    d.consumers.map(function (c) {
      var who = [c.user, c.token ? 'token ' + c.token : null].filter(Boolean).join(', ');
      return [ecoPkg(c.ecosystem, c.name), c.version, c.application || '', c.environment || '',
        who || h('span', { class: 'muted' }, ['nobody signed in']), c.ci || '', h('span', { class: 'mono' }, [c.ip || '']),
        String(c.downloads), when(c.firstSeen), when(c.lastSeen)];
    })));
}

export { viewConsumers };
