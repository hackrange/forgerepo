// ForgeRepo portal: waivers.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { clear, notice, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { scopeLabel, scopeLists, scopePick } from './rules.js';
import { ecoIcon, ecoPlaceholders, ecoPrefix, ecoSelect } from './ecosystems.js';
import { route } from './routing.js';

var WAIVER_KINDS = [
  ['advisory', 'A known advisory', 'Serve a version that safe resolution would leave out. Name the advisory ids, a new advisory is never covered.'],
  ['license', 'A license', 'Stop license enforcement holding this license on these versions. Covers everyone, the hold is on the file.'],
  ['cooloff', 'Cooling off', 'Serve versions that are still inside the cooling off period.']
];

function waiverWhat(w) {
  return ecoPrefix(w.ecosystem) + w.package_name + (w.version_range ? ' ' + w.version_range : ' (every version)');
}

// shown as text, a link in here is somebody else's to follow
function waiverRef(w) {
  return w.reference ? h('span', { class: 'mono' }, [w.reference]) : '';
}

function viewWaivers(body) {
  var types = state.ecosystems || [];
  return Promise.all([api('GET', '/waivers'), scopeLists()]).then(function (res) {
    var d = res[0];
    var scopes = res[1];
    section(body, 'Waivers',
      'A waiver is a written down, time boxed "yes, we know" for one finding on one package: an advisory safe resolution would leave out, ' +
      'a license enforcement would hold, or a version still cooling off. Every waiver expires, at most ' + d.maxDays + ' days after it is granted, ' +
      'and then the finding applies again. The kill switch, malware and integrity alerts can never be waived.');

    if (d.canAsk) {
      var kind = h('select', null, WAIVER_KINDS.map(function (k) { return h('option', { value: k[0] }, [k[1]]); }));
      var type = ecoSelect(types);
      var name = h('input', { type: 'text', placeholder: 'lodash' });
      var range = h('input', { type: 'text', placeholder: '4.17.20, or a range' });
      ecoPlaceholders(type, [
        [name, { npm: 'lodash', pypi: 'requests', oci: 'acme/app, or nginx' }],
        [range, { npm: '4.17.20, or a range', pypi: '2.31.0, or a specifier', oci: 'a tag, a tag with a *, or a sha256 digest' }]
      ]);
      var subject = h('input', { type: 'text', placeholder: 'GHSA-xxxx-xxxx-xxxx, PYSEC-2024-1' });
      var subjectLabel = h('label', null, ['Advisory ids']);
      var load = h('button', { type: 'button' }, ['Look them up']);
      var appPick = scopePick(scopes.applications, '', 'every application');
      var envPick = scopePick(scopes.environments, '', 'every environment');
      var days = h('input', { type: 'number', value: String(Math.min(30, d.maxDays)), min: '1', max: String(d.maxDays) });
      var reason = h('input', { type: 'text', maxlength: '1000', placeholder: 'why this is acceptable for now, and what happens next' });
      var reference = h('input', { type: 'text', maxlength: '255', placeholder: 'SEC-1234, a change number or a link' });
      var hint = h('p', { class: 'hint' }, ['']);
      var out = h('div', null, []);
      var subjectRow = h('div', null, [subjectLabel, subject, load]);
      var scopeRow = h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Only for application']), appPick]),
        h('div', null, [h('label', null, ['Only in environment']), envPick])
      ]);
      var describeKind = function () {
        var k = WAIVER_KINDS.filter(function (x) { return x[0] === kind.value; })[0];
        hint.textContent = k[2];
        subjectRow.hidden = kind.value === 'cooloff';
        load.hidden = kind.value !== 'advisory';
        subjectLabel.textContent = kind.value === 'license' ? 'License' : 'Advisory ids';
        subject.placeholder = kind.value === 'license' ? 'GPL-3.0-only, or unknown' : 'GHSA-xxxx-xxxx-xxxx, PYSEC-2024-1';
        scopeRow.hidden = kind.value === 'license' || (!scopes.applications.length && !scopes.environments.length);
      };
      kind.addEventListener('change', describeKind);
      load.addEventListener('click', function () {
        clear(out);
        api('GET', '/waivers/advisories?ecosystem=' + (type ? type.value : 'npm') + '&name=' + encodeURIComponent(name.value.trim()) + '&version=' + encodeURIComponent(range.value.trim()))
          .then(function (r) {
            if (!r.ids.length) return out.appendChild(notice('No advisories are recorded against that exact version.', 'info'));
            subject.value = r.ids.join(', ');
            out.appendChild(notice(r.ids.length + ' advisory id(s) filled in, worst ' + String(r.severity).toLowerCase() + '. ' + (r.summary || ''), 'info'));
          }).catch(function (e) { out.appendChild(notice(e.message, 'err')); });
      });
      describeKind();
      var send = function (grant) {
        clear(out);
        api('POST', '/waivers', {
          kind: kind.value, ecosystem: type ? type.value : 'npm', package_name: name.value.trim(), version_range: range.value.trim(),
          subject: kind.value === 'cooloff' ? '' : subject.value.trim(), application_id: kind.value === 'license' ? '' : appPick.value,
          environment_id: kind.value === 'license' ? '' : envPick.value, days: days.value, reason: reason.value.trim(), reference: reference.value.trim(), grant: grant
        }).then(route).catch(function (e) { out.appendChild(notice(e.message, 'err')); });
      };
      body.appendChild(h('fieldset', null, [
        h('legend', null, [d.canGrant ? 'Grant or ask for a waiver' : 'Ask for a waiver']),
        h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Waive']), kind]),
          type ? h('div', null, [h('label', null, ['Type']), type]) : null,
          h('div', null, [h('label', null, ['Package']), name]),
          h('div', null, [h('label', null, ['Versions']), range]),
          h('div', null, [h('label', null, ['Days']), days])
        ]),
        hint,
        subjectRow,
        scopeRow,
        h('label', null, ['Reason']), reason,
        h('label', null, ['Ticket or reference (optional)']), reference,
        h('div', null, [
          h('button', { type: 'button', onclick: function () { send(false); } }, ['Ask for it']),
          d.canGrant ? h('button', { type: 'button', onclick: function () {
            if (confirm('Grant this waiver now, without anyone else looking at it? It is recorded against your name.')) send(true);
          } }, ['Grant it now']) : null
        ]),
        out
      ]));
    }

    var scopeOf = function (w) {
      return w.kind === 'license' ? 'everyone' : scopeLabel(w.application_name, w.environment_name, w.application_id, w.environment_id);
    };

    if (d.scope === 'mine') body.appendChild(notice('These are the waivers you asked for. Waivers other people asked for are only shown to those who decide them.', 'info'));
    body.appendChild(h('h3', null, ['Waiting for a decision']));
    if (!d.pending.length) body.appendChild(h('p', { class: 'hint' }, ['Nothing is waiting.']));
    else {
      body.appendChild(table(['Waives', 'Package', 'Naming', 'For', { label: 'Days', num: true }, 'Asked by', 'Reason', 'Ticket', ''], d.pending.map(function (w) {
        return [w.kind, h('span', { class: 'eco-pkg' }, [ecoIcon(w.ecosystem), h('span', { class: 'mono' }, [waiverWhat(w)])]), w.subject || '', scopeOf(w), String(w.days), (w.requested_by || '') + ', ' + when(w.requested_at), w.reason, waiverRef(w),
          d.canGrant ? h('span', { class: 'actions' }, [
            link('approve', function () {
              var n = prompt('Approve for how many days? At most ' + d.maxDays + '.', String(w.days));
              if (n === null) return;
              api('POST', '/waivers/' + w.id + '/approve', { days: n }).then(route).catch(function (e) { alert(e.message); });
            }),
            link('reject', function () {
              var why = prompt('Why is it turned down?', '');
              if (!why) return;
              api('POST', '/waivers/' + w.id + '/reject', { note: why }).then(route).catch(function (e) { alert(e.message); });
            }, 'deny')
          ]) : ''];
      })));
    }

    body.appendChild(h('h3', null, ['In effect']));
    if (!d.active.length) body.appendChild(h('p', { class: 'hint' }, ['No waiver is in effect.']));
    else {
      body.appendChild(table(['Waives', 'Package', 'Naming', 'For', 'Until', 'Granted by', 'Reason', 'Ticket', ''], d.active.map(function (w) {
        return [w.kind, h('span', { class: 'eco-pkg' }, [ecoIcon(w.ecosystem), h('span', { class: 'mono' }, [waiverWhat(w)])]), w.subject || '', scopeOf(w), when(w.expires_at), w.decided_by || '', w.reason, waiverRef(w),
          d.canGrant ? link('revoke', function () {
            var why = prompt('Revoke this waiver now? The finding applies again straight away. Why?', '');
            if (why === null) return;
            api('POST', '/waivers/' + w.id + '/revoke', { note: why }).then(route).catch(function (e) { alert(e.message); });
          }, 'deny') : ''];
      })));
    }

    if (d.history.length) {
      body.appendChild(h('h3', null, ['Finished']));
      body.appendChild(table(['Waives', 'Package', 'Naming', 'Status', 'By', 'When', 'Note', 'Ticket'], d.history.map(function (w) {
        return [w.kind, h('span', { class: 'eco-pkg' }, [ecoIcon(w.ecosystem), h('span', { class: 'mono' }, [waiverWhat(w)])]), w.subject || '', w.status === 'active' ? 'expired' : w.status,
          w.decided_by || 'system', when(w.decided_at || w.expires_at), w.decision_note || '', waiverRef(w)];
      })));
    }
  });
}

export { viewWaivers };
