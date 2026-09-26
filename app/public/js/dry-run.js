// ForgeRepo portal: dry run.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';
import { clear, notice, table } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { scopeLists, scopePick } from './rules.js';
import { ecoPkg, ecoPlaceholders, ecoPrefix, ecoSelect } from './ecosystems.js';

function viewDryrun(body) {
  var types = state.ecosystems || [];
  return Promise.all([scopeLists(), api('GET', '/settings').catch(function () { return null; })]).then(function (res) {
    var scopes = res[0];
    // only admins can read settings. anyone else leaves the lists blank and the server uses today's
    var loaded = !!res[1];
    var s = loaded ? (res[1].settings || res[1]) : {};
    section(body, 'Dry run',
      'See what a change would break before switching it on. Recent downloads are replayed against the proposed rule, ' +
      'vulnerability threshold or license lists, and counted by package, application, developer and pipeline. Nothing is saved and nothing is enforced.');

    var kind = h('select', null, [
      h('option', { value: 'rule' }, ['A new rule']),
      h('option', { value: 'severity' }, ['Leave out vulnerable versions']),
      h('option', { value: 'license' }, ['Different license lists'])
    ]);
    var days = h('input', { type: 'number', value: '30', min: '1', max: '90' });
    var type = ecoSelect(types);
    var ruleKind = h('select', null, [h('option', { value: 'deny' }, ['deny']), h('option', { value: 'allow' }, ['allow'])]);
    var pattern = h('input', { type: 'text', placeholder: 'event-stream, or @scope/*' });
    var range = h('input', { type: 'text', placeholder: 'every version, or a range' });
    ecoPlaceholders(type, [
      [pattern, { npm: 'event-stream, or @scope/*', pypi: 'requests, or acme-*', oci: 'nginx, or acme/*' }],
      [range, { npm: 'every version, or a range', pypi: 'every release, or a specifier', oci: 'every tag, or latest, or 1.27.*' }]
    ]);
    var appPick = scopePick(scopes.applications, '', 'every application');
    var envPick = scopePick(scopes.environments, '', 'every environment');
    var severity = h('select', null, ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].map(function (v) {
      return h('option', { value: v }, [v === 'CRITICAL' ? 'critical only' : v.toLowerCase() + (v === 'LOW' ? ' and worse (every advisory)' : ' and worse')]);
    }));
    var area = function (v) { return h('textarea', { rows: '5', spellcheck: 'false' }, [v || '']); };
    var allowed = area(s.license_allowed); var review = area(s.license_review); var blocked = area(s.license_blocked);
    var verdicts = function (v) {
      return h('select', null, ['allowed', 'review', 'blocked'].map(function (o) { return h('option', { value: o, selected: v === o }, [o]); }));
    };
    var unlisted = verdicts(s.license_unlisted); var unknown = verdicts(s.license_unknown);
    var out = h('div', null, []);

    var ruleBox = h('div', null, [
      h('div', { class: 'row' }, [
        type ? h('div', null, [h('label', null, ['Type']), type]) : null,
        h('div', null, [h('label', null, ['Kind']), ruleKind]),
        h('div', null, [h('label', null, ['Package or pattern']), pattern]),
        h('div', null, [h('label', null, ['Versions']), range])
      ]),
      (scopes.applications.length || scopes.environments.length) ? h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Only for application']), appPick]),
        h('div', null, [h('label', null, ['Only in environment']), envPick])
      ]) : null
    ]);
    var sevBox = h('div', null, [h('label', null, ['Leave out versions with a known advisory rated']), severity,
      h('p', { class: 'hint' }, ['CVSS 7.0 to 8.9 is high, 9.0 and up is critical. Versions with a waiver covering every advisory are not counted.'])]);
    var licBox = h('div', null, [
      h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Allowed']), allowed]),
        h('div', null, [h('label', null, ['Needs review']), review]),
        h('div', null, [h('label', null, ['Blocked']), blocked])
      ]),
      h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['A license on no list']), unlisted]),
        h('div', null, [h('label', null, ['No license found']), unknown])
      ]),
      h('p', { class: 'hint' }, [(loaded ? 'Filled in with the current lists. ' : 'A list left blank stays as it is today. ') +
        'Only downloads allowed today that these lists would hold are counted, and only files whose license has been read.'])
    ]);
    var show = function () {
      ruleBox.hidden = kind.value !== 'rule';
      sevBox.hidden = kind.value !== 'severity';
      licBox.hidden = kind.value !== 'license';
    };
    kind.addEventListener('change', show);
    show();

    var run = h('button', { type: 'button' }, ['Run it']);
    run.addEventListener('click', function () {
      clear(out);
      var payload = { type: kind.value, days: days.value };
      if (kind.value === 'rule') {
        payload.ecosystem = type ? type.value : 'npm'; payload.kind = ruleKind.value; payload.pattern = pattern.value.trim();
        payload.version_range = range.value.trim(); payload.application_id = appPick.value; payload.environment_id = envPick.value;
      } else if (kind.value === 'severity') {
        payload.severity = severity.value;
      } else {
        [['allowed', allowed], ['review', review], ['blocked', blocked]].forEach(function (x) {
          if (loaded || x[1].value.trim()) payload[x[0]] = x[1].value;
        });
        if (loaded) { payload.unlisted = unlisted.value; payload.unknown = unknown.value; }
      }
      run.disabled = true;
      out.appendChild(h('p', { class: 'hint' }, ['Replaying downloads...']));
      api('POST', '/dryrun', payload).then(function (d) {
        clear(out);
        dryrunResult(out, d.result);
      }).catch(function (e) {
        clear(out);
        out.appendChild(notice(e.message, 'err'));
      }).then(function () { run.disabled = false; });
    });

    body.appendChild(h('fieldset', null, [
      h('legend', null, ['Proposed change']),
      h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Try']), kind]),
        h('div', null, [h('label', null, ['Days of downloads']), days])
      ]),
      ruleBox, sevBox, licBox,
      h('div', null, [run]),
      out
    ]));
  });
}

function dryrunResult(out, r) {
  var sum = r.summary;
  var verb = r.direction === 'allow' ? 'let through' : 'refused';
  out.appendChild(h('h3', null, ['Over the last ' + r.days + ' day' + (r.days === 1 ? '' : 's')]));
  if (!sum.downloads) {
    out.appendChild(notice('Nothing downloaded in that time would have been ' + verb + '. ' + r.scanned + ' download(s) were replayed.', 'info'));
    return;
  }
  out.appendChild(notice(sum.downloads + ' of ' + r.scanned + ' download(s) would have been ' + verb + '.' +
    (r.truncated ? ' Only the newest ' + r.scanned + ' were replayed.' : ''), r.direction === 'allow' ? 'info' : 'warn'));
  out.appendChild(table(['Affected', { label: 'Count', num: true }], [
    ['Packages', String(sum.packages)],
    ['Versions', String(sum.versions)],
    ['Applications', String(sum.applications)],
    ['Applications in production', String(sum.productionApplications)],
    ['Developers', String(sum.developers)],
    ['CI pipelines', String(sum.pipelines)],
    ['Downloads', String(sum.downloads)],
    ['Downloads with no token, so nobody to name', String(sum.unattributed)]
  ]));
  out.appendChild(h('p', { class: 'hint' }, ['Production means an environment ticked as production in Settings, Applications. Pipelines are downloads whose client said it runs in CI.']));

  out.appendChild(h('h3', null, ['Packages']));
  out.appendChild(table(['Package', 'Versions', { label: 'Downloads', num: true }, 'Applications', 'Why'], r.packages.map(function (p) {
    return [ecoPkg(p.ecosystem, p.name),
      p.versions.map(function (v) { return v.version; }).join(', '), String(p.downloads), p.applications.join(', '),
      p.versions.length ? p.versions[0].reason : ''];
  })));
  if (r.applications.length) {
    out.appendChild(h('h3', null, ['Applications']));
    out.appendChild(table(['Application', 'Environments', { label: 'Downloads', num: true }, ''], r.applications.map(function (a) {
      return [a.name, a.environments.join(', '), String(a.downloads), a.production ? h('span', { class: 'badge deny' }, ['production']) : ''];
    })));
  }
  if (r.developers.length) {
    out.appendChild(h('h3', null, ['Developers']));
    out.appendChild(table(['User', { label: 'Downloads', num: true }], r.developers.map(function (d) { return [d.username, String(d.downloads)]; })));
  }
  if (r.pipelines.length) {
    out.appendChild(h('h3', null, ['CI pipelines']));
    out.appendChild(table(['CI', 'Token', 'Application', { label: 'Downloads', num: true }], r.pipelines.map(function (c) {
      return [c.ci, c.token || '', c.application || '', String(c.downloads)];
    })));
  }
}

export { viewDryrun };
