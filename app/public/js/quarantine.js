// ForgeRepo portal: quarantine.
// Author: Tim Rice

import { h, link } from './dom.js';
import { can, notice, pager, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { ecoName, ecoPkg } from './ecosystems.js';
import { route } from './routing.js';

var quarantinePage = 1;
var quarantineFilter = { status: 'open', q: '' };

function resolveHold(hd, action) {
  var question = action === 'release'
    ? 'Release ' + hd.filename + ' from quarantine? It gets served normally again.'
    : 'Reject ' + hd.filename + '? It is refused from now on, whichever mode quarantine is in.';
  var noteText = prompt(question + '\n\nA note for the audit trail (optional):', '');
  if (noteText === null) return;
  api('POST', '/quarantine/' + hd.id + '/' + action, { note: noteText })
    .then(route)
    .catch(function (e) { alert(e.message); });
}

function viewQuarantine(body) {
  var query = '?page=' + quarantinePage + '&status=' + encodeURIComponent(quarantineFilter.status) +
    (quarantineFilter.q ? '&q=' + encodeURIComponent(quarantineFilter.q) : '');
  return api('GET', '/quarantine' + query).then(function (d) {
    section(body, 'Quarantine', 'Exact files held back until someone decides. Integrity alerts put files here, ' +
      'and an admin can hold any file from its detail on the Artifacts page.');
    body.appendChild(notice('Mode: ' + d.mode + (d.mode === 'strict'
      ? '. Held files are refused and left out of npm and PyPI metadata.'
      : '. Held files are still served, with a warning during npm installs.') +
      (d.open ? ' ' + d.open + ' open hold(s).' : ' Nothing is held right now.'), d.open ? 'err' : 'ok'));

    var status = h('select', null, ['open', 'released', 'rejected', 'all'].map(function (s) {
      return h('option', { value: s, selected: quarantineFilter.status === s }, [s]);
    }));
    var q = h('input', { type: 'text', value: quarantineFilter.q, placeholder: 'package or file' });
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        quarantineFilter.status = status.value;
        quarantineFilter.q = q.value.trim();
        quarantinePage = 1;
        route();
      }
    }, [
      h('div', null, [h('label', null, ['Status']), status]),
      h('div', null, [h('label', null, ['Search']), q]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    var canResolve = can('cache:purge');
    body.appendChild(table(
      ['Placed', 'Package', 'Version', 'File', 'Why', 'By', 'Status', ''],
      d.holds.map(function (hd) {
        var actions = h('span', { class: 'actions' }, []);
        if (canResolve && hd.status !== 'released') {
          actions.appendChild(link('release', function () { resolveHold(hd, 'release'); }));
          if (hd.status === 'open') actions.appendChild(link('reject', function () { resolveHold(hd, 'reject'); }));
        }
        return [
          when(hd.created_at),
          ecoPkg(hd.ecosystem, hd.package_name),
          hd.version,
          h('span', { class: 'mono' }, [hd.filename]),
          hd.reason + ' (' + hd.source + ')',
          hd.created_by || 'system',
          h('span', { class: hd.status === 'released' ? 'allow' : 'deny', title: hd.note || '' },
            [hd.status + (hd.resolved_by ? ' by ' + hd.resolved_by : '')]),
          actions
        ];
      })
    ));
    body.appendChild(pager(d.page, d.total, d.limit, function (p) { quarantinePage = p; route(); }));
  });
}

export { viewQuarantine };
