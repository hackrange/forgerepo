// ForgeRepo portal: applications and environments.
// Author: Tim Rice

import { h, link } from './dom.js';
import { clear, notice, table, when } from './ui.js';
import { api } from './api.js';
import { route } from './routing.js';

// applications and environments share one editor. DRY for once.
var UNASSIGNED = '(none)';

// live entries plus none. a retired one stays selected if the token already has it
function labelOptions(entries, selectedId) {
  var opts = [h('option', { value: '' }, ['unassigned'])];
  (entries || []).forEach(function (e) {
    if (e.retired && e.id !== selectedId) return;
    opts.push(h('option', {
      value: String(e.id),
      selected: e.id === selectedId ? 'selected' : null
    }, [e.name + (e.retired ? ' (retired)' : '')]));
  });
  return opts;
}

function unassigned() {
  return h('span', { class: 'muted' }, ['unassigned']);
}

// these save straight away, they're rows not settings
function labelEditor(body, path, d, opts) {
  body.appendChild(h('h3', null, [opts.title]));
  body.appendChild(h('p', { class: 'hint' }, [opts.hint]));

  if (d.writable) {
    var name = h('input', { type: 'text', placeholder: opts.placeholder });
    var note = h('input', { type: 'text', placeholder: 'optional, what it is' });
    var prod = opts.production ? h('input', { type: 'checkbox' }) : null;
    var out = h('div', null, []);
    body.appendChild(h('div', { class: 'row' }, [
      h('div', null, [h('label', null, ['Name']), name]),
      h('div', null, [h('label', null, ['Note']), note]),
      prod ? h('div', null, [h('label', null, [prod, 'Production'])]) : null,
      h('div', null, [h('button', {
        type: 'button',
        onclick: function () {
          if (!name.value.trim()) return;
          var fields = { name: name.value.trim(), note: note.value.trim() };
          if (prod) fields.production = prod.checked ? '1' : '0';
          api('POST', '/' + path, fields)
            .then(route)
            .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
        }
      }, ['Add'])])
    ]));
    body.appendChild(out);
  }

  var cols = ['Name', 'Note', { label: 'Live tokens', num: true }, 'Status', 'Added', ''];
  if (opts.production) cols.splice(2, 0, 'Production');
  body.appendChild(table(
    cols,
    d.entries.map(function (e) {
      var actions = [];
      if (d.writable) {
        actions.push(link(e.retired ? 'bring back' : 'retire', function () {
          api('PATCH', '/' + path + '/' + e.id, { retired: e.retired ? '0' : '1' })
            .then(route).catch(function (err) { alert(err.message); });
        }));
        actions.push(document.createTextNode(' '));
        actions.push(link('rename', function () {
          var next = prompt('Rename ' + e.name + ' to what? Every token pointing at it follows the new name. ' +
            'Traffic already written keeps the old one, because that is what was true at the time.', e.name);
          if (next === null || !next.trim()) return;
          api('PATCH', '/' + path + '/' + e.id, { name: next.trim() })
            .then(route).catch(function (err) { alert(err.message); });
        }));
        actions.push(document.createTextNode(' '));
        actions.push(link('delete', function () {
          if (!confirm('Delete ' + e.name + '? This is refused while any token still points at it.')) return;
          api('DELETE', '/' + path + '/' + e.id)
            .then(route).catch(function (err) { alert(err.message); });
        }, 'deny'));
      }
      var cells = [
        e.name,
        e.note || '',
        e.live_tokens || 0,
        h('span', { class: e.retired ? 'muted' : 'allow' }, [e.retired ? 'retired' : 'in use']),
        when(e.created_at),
        h('span', null, actions)
      ];
      if (opts.production) {
        var tick = h('input', { type: 'checkbox', checked: e.production ? 'checked' : null, 'aria-label': 'production' });
        if (!d.writable) tick.setAttribute('disabled', 'disabled');
        tick.addEventListener('change', function () {
          api('PATCH', '/' + path + '/' + e.id, { production: tick.checked ? '1' : '0' })
            .then(route).catch(function (err) { tick.checked = !tick.checked; alert(err.message); });
        });
        cells.splice(2, 0, tick);
      }
      return cells;
    })
  ));
}

export { UNASSIGNED, labelEditor, labelOptions, unassigned };
