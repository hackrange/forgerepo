// ForgeRepo portal: resolutions.
// Author: Tim Rice

import { h } from './dom.js';
import { notice, pager, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { ecoName, ecoPkg } from './ecosystems.js';
import { route } from './routing.js';

var resolutionsPage = 1;
var resolutionsFilter = { q: '' };

function leftOutCell(r) {
  if (!r.excluded || !r.excluded.length) return String(r.excluded_count || 0);
  return h('details', null, [
    h('summary', null, [r.excluded_count + ' version(s)']),
    h('ul', null, r.excluded.map(function (g) {
      var more = g.total > g.versions.length ? ' and ' + (g.total - g.versions.length) + ' more' : '';
      return h('li', null, [
        h('strong', null, [g.kind + ': ']), g.reason + ' - ',
        h('span', { class: 'mono' }, [g.versions.join(', ') + more])
      ]);
    }))
  ]);
}

function viewResolutions(body) {
  var query = '?page=' + resolutionsPage + (resolutionsFilter.q ? '&q=' + encodeURIComponent(resolutionsFilter.q) : '');
  return api('GET', '/resolutions' + query).then(function (d) {
    section(body, 'Resolutions', 'What npm and pip were offered when versions were left out, why each one was, ' +
      'and which version the client pulled next. The range a developer typed is not known, clients never send it.');
    body.appendChild(d.enabled
      ? notice('Safe version resolution is on, leaving out ' + d.threshold.toLowerCase() + ' advisories and worse.', 'ok')
      : notice('Safe version resolution is off, so nothing new is logged. It is under Settings, Policy.', 'info'));

    var q = h('input', { type: 'text', value: resolutionsFilter.q, placeholder: 'package name' });
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        resolutionsFilter.q = q.value.trim();
        resolutionsPage = 1;
        route();
      }
    }, [
      h('div', null, [h('label', null, ['Search']), q]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    body.appendChild(table(
      ['When', 'Package', 'Application', 'Environment', { label: 'Offered', num: true }, 'Left out', 'Pulled'],
      d.resolutions.map(function (r) {
        return [
          when(r.ts),
          ecoPkg(r.ecosystem, r.package_name),
          r.application || h('span', { class: 'muted' }, ['unassigned']),
          r.environment || h('span', { class: 'muted' }, ['unassigned']),
          String(r.offered_count),
          leftOutCell(r),
          r.selected_version
            ? h('span', { class: 'mono' }, [r.selected_version])
            : h('span', { class: 'muted' }, ['nothing yet'])
        ];
      })
    ));
    body.appendChild(pager(d.page, d.total, d.limit, function (p) { resolutionsPage = p; route(); }));
  });
}

export { viewResolutions };
