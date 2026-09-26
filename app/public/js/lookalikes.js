// ForgeRepo portal: lookalike packages.
// Author: Tim Rice

import { h, link } from './dom.js';
import { can, notice, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { ecoName, ecoPkg } from './ecosystems.js';
import { route } from './routing.js';

var typosquatStatus = 'open';

function viewTyposquats(body) {
  return api('GET', '/typosquats?status=' + typosquatStatus).then(function (d) {
    section(body, 'Lookalike packages',
      'Packages whose names imitate a well known one, like lodahs for lodash or python-numpy for numpy. That is how typosquatting works: ' +
      'someone publishes the lookalike and waits for a typo. Dismiss one once you know it is a real package, and it stops being flagged.');
    body.appendChild(notice(
      d.mode === 'off' ? 'Typosquat checks are off. Switch them on under Settings, Policy.'
        : d.mode === 'block' ? 'Lookalike names are refused, and the install that asked opens a request saying why.'
          : 'Lookalike names are still served, logged here, and npm prints a warning during install.',
      d.mode === 'off' ? 'info' : 'ok'
    ));
    var c = d.counts || {};
    var tabsRow = h('div', { class: 'pager' }, []);
    [['open', 'Flagged (' + (c.open || 0) + ')'], ['dismissed', 'Dismissed (' + (c.dismissed || 0) + ')']].forEach(function (t) {
      tabsRow.appendChild(t[0] === typosquatStatus ? h('strong', null, [t[1]]) : link(t[1], function () { typosquatStatus = t[0]; route(); }));
    });
    body.appendChild(tabsRow);
    var write = can('rules:write');
    body.appendChild(table(['Last seen', 'Package', 'Looks like', 'How', 'What happened', { label: 'Requests', num: true }, ''], d.findings.map(function (f) {
      var act = write ? link(f.status === 'open' ? 'not a typosquat' : 'flag again', function () {
        if (f.status === 'open' && !confirm('Mark ' + f.package_name + ' as a real package? It stops being flagged as a lookalike of ' + f.looks_like + '.')) return;
        api('POST', '/typosquats/' + f.id + '/' + (f.status === 'open' ? 'dismiss' : 'reopen'), {}).then(route).catch(function (e) { alert(e.message); });
      }) : '';
      return [
        when(f.last_seen),
        h('span', { class: 'deny' }, [ecoPkg(f.ecosystem, f.package_name)]),
        h('span', { class: 'mono' }, [f.looks_like]),
        f.technique,
        f.status === 'dismissed' ? h('span', { class: 'muted' }, ['dismissed by ' + (f.dismissed_by || 'someone')]) : h('span', { class: f.last_action === 'blocked' ? 'deny' : 'warn' }, [f.last_action]),
        String(f.hits),
        act
      ];
    })));
  });
}

export { viewTyposquats };
