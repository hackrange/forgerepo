// ForgeRepo portal: audit.
// Author: Tim Rice

import { h, link } from './dom.js';
import { clear, pager, table, when } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';
import { route } from './routing.js';

var auditPage = 1;
var auditFilter = { action: '', user: '', result: '' };

function auditQuery() {
  return (auditFilter.action ? '&action=' + encodeURIComponent(auditFilter.action) : '') +
    (auditFilter.user ? '&user=' + encodeURIComponent(auditFilter.user) : '') +
    (auditFilter.result ? '&result=' + auditFilter.result : '');
}

// a state is json, unless it was cut short or never was. either way it is only ever shown as text
function parseState(text) {
  if (!text) return null;
  try {
    var v = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : { value: v };
  } catch (e) {
    return { '(as recorded)': text };
  }
}

function shown(v) {
  if (v === undefined) return h('span', { class: 'muted' }, ['not set']);
  if (v === null || v === '') return h('span', { class: 'muted' }, ['empty']);
  return h('span', { class: 'mono' }, [typeof v === 'object' ? JSON.stringify(v) : String(v)]);
}

// before and after, key by key, the changed ones marked
function drawChanges(box, e) {
  clear(box);
  var before = parseState(e.before_state) || {};
  var after = parseState(e.after_state) || {};
  var keys = Object.keys(before).concat(Object.keys(after).filter(function (k) { return !(k in before); }));
  box.appendChild(h('h3', null, [e.action + ' ' + (e.target || ''), h('small', null, [link('close', function () { clear(box); })])]));
  box.appendChild(h('p', { class: 'hint' }, [when(e.ts) + ', ' + (e.username || 'anonymous') + (e.ip ? ' from ' + e.ip : '') + ', ' + e.result + '.']));
  box.appendChild(table(['Field', 'Before', 'After'], keys.map(function (k) {
    var same = JSON.stringify(before[k]) === JSON.stringify(after[k]);
    return [h('span', { class: same ? 'muted' : null }, [k]), shown(before[k]), shown(after[k])];
  })));
}

function viewAudit(body) {
  return api('GET', '/audit?page=' + auditPage + '&limit=100' + auditQuery()).then(function (d) {
    section(body, 'Audit trail', 'Who changed what in this portal, what it was before and after, and every sign in attempt, kept whether it worked or not.');

    var action = h('input', { type: 'text', value: auditFilter.action, placeholder: 'login, rule., settings' });
    var user = h('input', { type: 'text', value: auditFilter.user, placeholder: 'username' });
    var result = h('select', null, [['', 'any result'], ['success', 'worked'], ['failure', 'failed'], ['denied', 'refused']].map(function (o) {
      return h('option', { value: o[0], selected: auditFilter.result === o[0] ? 'selected' : null }, [o[1]]);
    }));
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (ev) {
        ev.preventDefault();
        auditFilter.action = action.value.trim();
        auditFilter.user = user.value.trim();
        auditFilter.result = result.value;
        auditPage = 1;
        route();
      }
    }, [
      h('div', null, [h('label', null, ['Action starts with']), action]),
      h('div', null, [h('label', null, ['Who']), user]),
      h('div', null, [h('label', null, ['Result']), result]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])]),
      h('div', null, [
        h('button', { type: 'button', onclick: function () { download('/audit/export?format=csv' + auditQuery(), 'forgerepo-audit.csv'); } }, ['Export CSV']),
        h('button', { type: 'button', onclick: function () { download('/audit/export?format=json' + auditQuery(), 'forgerepo-audit.json'); } }, ['Export JSON'])
      ])
    ]));

    var changes = h('div', { class: 'audit-changes', 'aria-live': 'polite' }, []);
    body.appendChild(changes);
    body.appendChild(table(['When', 'Who', 'From', 'Action', 'Target', 'Result', 'Detail', ''], d.entries.map(function (e) {
      var hasStates = e.before_state || e.after_state;
      return [
        when(e.ts), e.username || 'anonymous', e.ip || '', e.action, e.target || '',
        h('span', { class: e.result === 'success' ? null : 'deny' }, [e.result === 'success' ? 'worked' : e.result === 'failure' ? 'failed' : 'refused']),
        e.detail || '',
        hasStates ? link('before and after', function () { drawChanges(changes, e); changes.scrollIntoView({ block: 'start', behavior: 'smooth' }); }) : ''
      ];
    })));
    body.appendChild(pager(d.page, d.total, d.limit, function (p) { auditPage = p; route(); }));
  });
}

export { viewAudit };
