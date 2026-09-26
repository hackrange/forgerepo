// ForgeRepo portal: integrity alerts.
// Author: Tim Rice

import { h, link } from './dom.js';
import { can, notice, pager, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { ecoName, ecoPkg } from './ecosystems.js';
import { route } from './routing.js';

var integrityPage = 1;
var integrityFilter = { status: 'open', q: '' };

function shortDigest(d) {
  d = String(d || '');
  return d.length > 20 ? d.slice(0, 16) + '...' : d;
}

function resolveIntegrity(ev, action) {
  var question = action === 'dismiss'
    ? 'Keep the original ' + ev.filename + ' and close this alert?'
    : ev.kind === 'content'
      ? 'Accept the new bytes for ' + ev.filename + '? They become the copy this box serves.'
      : 'Accept the change to ' + ev.filename + '? The cached copy is dropped and the newly published file downloads on the next install.';
  var noteText = prompt(question + '\n\nA note for the audit trail (optional):', '');
  if (noteText === null) return;
  api('POST', '/integrity/' + ev.id + '/' + action, { note: noteText })
    .then(route)
    .catch(function (e) { alert(e.message); });
}

function viewIntegrity(body) {
  var query = '?page=' + integrityPage + '&status=' + encodeURIComponent(integrityFilter.status) +
    (integrityFilter.q ? '&q=' + encodeURIComponent(integrityFilter.q) : '');
  return api('GET', '/integrity' + query).then(function (d) {
    section(body, 'Integrity alerts', 'Releases a registry changed after this box had already seen them. ' +
      'A published npm or PyPI file is never supposed to change, so each one needs a person to look at it.');
    body.appendChild(d.open
      ? notice(d.open + ' open alert(s). Nothing was swapped on its own.', 'err')
      : notice('No open alerts.', 'ok'));

    var status = h('select', null, ['open', 'accepted', 'dismissed', 'all'].map(function (s) {
      return h('option', { value: s, selected: integrityFilter.status === s }, [s]);
    }));
    var q = h('input', { type: 'text', value: integrityFilter.q, placeholder: 'package or file' });
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        integrityFilter.status = status.value;
        integrityFilter.q = q.value.trim();
        integrityPage = 1;
        route();
      }
    }, [
      h('div', null, [h('label', null, ['Status']), status]),
      h('div', null, [h('label', null, ['Search']), q]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    var canResolve = can('cache:purge');
    body.appendChild(table(
      ['Last seen', 'Package', 'Version', 'File', 'What changed', 'Was', 'Now', { label: 'Seen', num: true }, 'Status', ''],
      d.events.map(function (ev) {
        var actions = h('span', { class: 'actions' }, []);
        if (canResolve && ev.status === 'open') {
          actions.appendChild(link('accept', function () { resolveIntegrity(ev, 'accept'); }));
          actions.appendChild(link('keep original', function () { resolveIntegrity(ev, 'dismiss'); }));
        }
        return [
          when(ev.last_seen),
          ecoPkg(ev.ecosystem, ev.package_name),
          ev.version,
          h('span', { class: 'mono' }, [ev.filename]),
          ev.kind === 'content' ? 'downloaded bytes' : 'published digest',
          h('span', { class: 'mono', title: ev.expected }, [shortDigest(ev.expected)]),
          h('span', { class: 'mono', title: ev.observed }, [shortDigest(ev.observed)]),
          String(ev.occurrences),
          h('span', { class: ev.status === 'open' ? 'deny' : ev.status === 'accepted' ? 'allow' : 'muted', title: ev.note || '' },
            [ev.status + (ev.resolved_by ? ' by ' + ev.resolved_by : '')]),
          actions
        ];
      })
    ));
    body.appendChild(pager(d.page, d.total, d.limit, function (p) { integrityPage = p; route(); }));
  });
}

export { viewIntegrity };
