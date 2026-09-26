// ForgeRepo portal: check and resolve.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';
import { can, clear, notice, table } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { scopeLists, scopePick } from './rules.js';
import { ecoHints, ecoSelect, ecoSpec } from './ecosystems.js';
import { reviewFileSection, runResolve } from './review.js';

function spelled(ecosystem, name, version) {
  if (!version) return name;
  return ecoSpec(ecosystem, name, version);
}

// PyPI release info. all text, and the project url is never linked since the publisher wrote it
function releaseDetail(m) {
  if (m.error) return h('p', { class: 'hint' }, ['Could not read what this release is: ' + m.error]);
  var none = function () { return h('span', { class: 'muted' }, ['none']); };
  var list = function (items) {
    return items && items.length ? h('ul', null, items.map(function (x) { return h('li', { class: 'mono' }, [x]); })) : none();
  };
  var size = function (n) {
    return n == null ? '' : n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';
  };
  var license = m.licenseExpression || (m.license && !m.license.isText ? m.license.value : null);
  var rows = [
    ['Release', (m.name || '') + ' ' + (m.version || '') + (m.yanked ? '  (yanked' + (m.yankedReason ? ': ' + m.yankedReason : '') + ')' : '')],
    ['Summary', m.summary || none()],
    ['Requires-Python', m.requiresPython || h('span', { class: 'muted' }, ['any'])],
    ['License', license || (m.license && m.license.isText
      ? h('span', { title: m.license.value }, ['license text, no identifier'])
      : (m.licenseClassifiers.length ? m.licenseClassifiers.join(', ') : none()))],
    ['Requires-Dist', list(m.requiresDist)],
    ['Provides-Extra', m.providesExtra.length ? m.providesExtra.join(', ') : none()],
    ['Project-URL', m.projectUrls.length ? h('ul', null, m.projectUrls.map(function (u) {
      return h('li', null, [u.label + ': ', h('span', { class: 'mono' }, [u.url])]);
    })) : none()],
    ['Files', m.files && m.files.length ? h('ul', null, m.files.map(function (f) {
      return h('li', null, [h('span', { class: 'mono' }, [f.filename]), ' ' + f.kind + (f.size != null ? ', ' + size(f.size) : '') +
        (f.uploaded ? ', uploaded ' + String(f.uploaded).slice(0, 10) : '') + (f.yanked ? ', yanked' : '')]);
    })) : none()],
    ['Read from', m.source]
  ];
  var facts = h('dl', { class: 'facts' }, []);
  rows.forEach(function (r) {
    facts.appendChild(h('dt', null, [r[0]]));
    facts.appendChild(h('dd', null, [r[1]]));
  });
  var box = h('fieldset', null, [h('legend', null, ['What this release is']), facts]);
  if (m.classifiers && m.classifiers.length) {
    box.appendChild(h('details', null, [
      h('summary', null, ['Classifiers (' + m.classifiers.length + ')']),
      list(m.classifiers)
    ]));
  }
  return box;
}

// every version and whether a client gets offered it right now, newest first
function candidatesTable(d) {
  var box = h('fieldset', null, [h('legend', null, ['Every version of ' + d.name])]);
  box.appendChild(h('p', { class: 'hint' }, [
    (d.scope && (d.scope.application || d.scope.environment) ? 'As a token for ' + [d.scope.application, d.scope.environment].filter(Boolean).join(' in ') + '. ' : '') +
    'Safe version resolution is ' + (d.safeResolution ? 'on, leaving out ' + d.threshold.toLowerCase() + ' advisories and worse' : 'off') +
    '. Quarantine is ' + d.quarantineMode + '. ' + (d.cooloffHours ? 'New versions cool off for ' + d.cooloffHours + ' hours. ' : '') +
    (d.total > d.shown ? 'Showing the newest ' + d.shown + ' of ' + d.total + ' versions.' : d.total + ' version(s).')
  ]));
  var cls = { approved: 'allow', blocked: 'deny', quarantined: 'deny', excluded: 'warn', cooling: 'warn' };
  box.appendChild(table(['Version', 'Status', 'Why'], d.candidates.map(function (c) {
    return [
      h('span', { class: 'mono' }, [c.version]),
      h('span', { class: cls[c.status] || null }, [c.status]),
      c.reasons.length ? c.reasons.join('; ') : h('span', { class: 'muted' }, ['-'])
    ];
  })));
  return box;
}

function viewTools(body) {
  section(body, 'Check a package', 'See what the rules say, and what a package will drag in with it.');
  var types = state.ecosystems || [];

  function followType(select, input) {
    if (!select) return;
    select.addEventListener('change', function () {
      input.placeholder = ecoHints(select.value).example;
    });
  }

  var checkType = ecoSelect(types);
  var name = h('input', { type: 'text', placeholder: 'express' });
  var version = h('input', { type: 'text', placeholder: 'optional exact version' });
  var out = h('div', null, []);
  followType(checkType, name);
  // answer as a token for this application and environment would get it. filled in once the lists load
  var asRow = h('div', { class: 'row' }, []);
  var asApp = null;
  var asEnv = null;
  scopeLists().then(function (sc) {
    if (!sc.applications.length && !sc.environments.length) return;
    asApp = scopePick(sc.applications, '', 'no application');
    asEnv = scopePick(sc.environments, '', 'no environment');
    asRow.appendChild(h('div', null, [h('label', null, ['As application']), asApp]));
    asRow.appendChild(h('div', null, [h('label', null, ['In environment']), asEnv]));
  });
  var asQuery = function () {
    return (asApp && asApp.value ? '&application=' + encodeURIComponent(asApp.value) : '') +
      (asEnv && asEnv.value ? '&environment=' + encodeURIComponent(asEnv.value) : '');
  };
  var asWords = function (s) {
    if (!s || (!s.application && !s.environment)) return '';
    return ' for ' + [s.application, s.environment].filter(Boolean).join(' in ');
  };

  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Single package']),
    h('div', { class: 'row' }, [
      checkType ? h('div', null, [h('label', null, ['Type']), checkType]) : null,
      h('div', null, [h('label', null, ['Package']), name]),
      h('div', null, [h('label', null, ['Version']), version])
    ]),
    asRow,
    h('button', {
      onclick: function () {
        var eco = checkType ? checkType.value : 'npm';
        api('GET', '/tools/check?ecosystem=' + eco + '&name=' + encodeURIComponent(name.value.trim()) +
          (version.value.trim() ? '&version=' + encodeURIComponent(version.value.trim()) : '') + asQuery())
          .then(function (d) {
            clear(out);
            out.appendChild(notice(
              spelled(d.ecosystem, d.name, d.version) + ' is ' + (d.allowed ? 'allowed' : 'blocked') + asWords(d.scope) + '. ' + d.reason,
              d.allowed ? 'ok' : 'err'
            ));
            if (d.lookalike) {
              out.appendChild(notice('The name looks like ' + d.lookalike.lookalike + ' (' + d.lookalike.technique + '). Check it is the package you meant, this is how typosquatting works.', 'err'));
            }
            var l = d.license;
            if (l && l.error) out.appendChild(notice('License: ' + l.error, 'info'));
            else if (l) {
              out.appendChild(notice('License of ' + l.version + ': ' + (l.expression || 'none this registry can read') +
                (l.mode === 'off' ? '. License checks are off, so no version is held back for its license.' : ', ' + l.verdict + '. ' + l.reason),
              l.verdict === 'allowed' ? 'ok' : l.verdict === 'blocked' ? 'err' : 'info'));
            }
            if (d.metadata) out.appendChild(releaseDetail(d.metadata));
          })
          .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
      }
    }, ['Check it']),
    h('button', {
      onclick: function () {
        var eco = checkType ? checkType.value : 'npm';
        clear(out);
        out.appendChild(h('p', { class: 'hint' }, ['Asking the registry for every version...']));
        api('GET', '/tools/candidates?ecosystem=' + eco + '&name=' + encodeURIComponent(name.value.trim()) + asQuery())
          .then(function (d) { clear(out); out.appendChild(candidatesTable(d)); })
          .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
      }
    }, ['Show every version'])
  ]));
  body.appendChild(out);

  // every role can review a file, the tree walk needs developer or up
  reviewFileSection(body);

  if (!can('tools:resolve')) return;

  var depType = ecoSelect(types);
  var depName = h('input', { type: 'text', placeholder: 'express' });
  var depRange = h('input', { type: 'text', value: 'latest' });
  var depth = h('input', { type: 'number', value: '12', min: '0', max: '25' });
  var depOut = h('div', null, []);
  followType(depType, depName);

  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Dependency tree']),
    h('p', { class: 'hint' }, ['Walks what the package needs and flags anything the rules would stop. Worth doing before you approve something.']),
    depType ? h('p', { class: 'hint' }, [
      'For PyPI, Versions takes latest or a specifier like >=2.31,<3, and the walk follows what each release ' +
      'lists as its requirements, leaving out the ones only an extra asks for. For an image, Versions is one tag or ' +
      'digest, and the tree is its platform images, their layers and every package found inside them.'
    ]) : null,
    h('div', { class: 'row' }, [
      depType ? h('div', null, [h('label', null, ['Type']), depType]) : null,
      h('div', null, [h('label', null, ['Package']), depName]),
      h('div', null, [h('label', null, ['Versions']), depRange]),
      h('div', null, [h('label', null, ['Depth']), depth])
    ]),
    h('button', {
      onclick: function () {
        runResolve(depName.value.trim(), depRange.value.trim(), depth.value, depOut, depType ? depType.value : 'npm');
      }
    }, ['Walk the tree'])
  ]));
  body.appendChild(depOut);

  window.__resolveTarget = { name: depName, range: depRange, out: depOut, type: depType };
}

export { viewTools };
