// ForgeRepo portal: import and export.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';
import { can, clear, notice, table } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';

function viewTransfer(body) {
  section(body, 'Import and export', 'Move rules between boxes, or keep a copy somewhere safe.');

  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Export']),
    h('p', { class: 'hint' }, ['Rules go out as json or csv. The full config export adds the settings and both ip allow lists. Passwords, tokens and break glass keys are never included. Exports stream, so the size of the list is not a problem.']),
    h('button', { onclick: function () { download('/rules/export?format=json', 'forgerepo-rules.json'); } }, ['Rules as JSON']),
    h('button', { onclick: function () { download('/rules/export?format=csv', 'forgerepo-rules.csv'); } }, ['Rules as CSV']),
    can('backup:export') ? h('button', { onclick: function () { download('/export', 'forgerepo-config.json'); } }, ['Whole config']) : null
  ]));

  if (!can('rules:import')) return;

  var data = h('textarea', { placeholder: 'paste json or csv here, or pick a file below' });
  var file = h('input', { type: 'file', accept: '.json,.csv,text/csv,application/json' });
  file.addEventListener('change', function () {
    var f = file.files && file.files[0];
    if (!f) return;
    // no cap on rule count, just on how much text the api swallows
    var maxMB = state.maxImportMB || 64;
    if (f.size > maxMB * 1024 * 1024) {
      return alert('That file is ' + (f.size / 1048576).toFixed(1) + 'MB and the limit is ' + maxMB + 'MB.');
    }
    var reader = new FileReader();
    reader.onload = function () { data.value = String(reader.result); };
    reader.readAsText(f);
  });

  var mode = h('select', null, [
    h('option', { value: 'merge' }, ['merge, keep what is already there']),
    h('option', { value: 'replace' }, ['replace, wipe the rules of the types in the file first'])
  ]);
  var out = h('div', null, []);

  function send(dryRun) {
    api('POST', '/rules/import', { data: data.value, mode: mode.value, dry_run: dryRun })
      .then(function (d) {
        clear(out);
        out.appendChild(notice(
          dryRun
            ? 'That file would bring in ' + d.wouldImport + ' rules, with ' + d.errors.length + ' skipped.'
            : 'Brought in ' + d.imported + ' rules, skipped ' + d.errors.length + '.',
          d.errors.length ? 'err' : 'ok'
        ));
        if (d.errors.length) {
          out.appendChild(table(['Row', 'Pattern', 'Problem'], d.errors.slice(0, 50).map(function (e) {
            return [String(e.row || ''), e.pattern || '', e.error];
          })));
        }
      })
      .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
  }

  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Import rules']),
    h('p', { class: 'hint' }, ['CSV needs a header row with at least pattern and kind. Columns it understands: pattern, kind, version_range, note, priority, enabled.']),
    h('p', { class: 'hint' }, [
      'There is no limit on how many rules a file holds. It is written in batches inside one ' +
      'transaction, so a big list either lands whole or not at all. Try it first reports what ' +
      'would happen without writing anything.'
    ]),
    h('label', null, ['Pick a file']), file,
    h('label', null, ['Or paste it']), data,
    h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Mode']), mode])]),
    h('button', { onclick: function () { send(true); } }, ['Try it first']),
    h('button', { onclick: function () { if (confirm('Import for real?')) send(false); } }, ['Import'])
  ]));
  body.appendChild(out);

  if (!can('backup:import')) return;

  var cfg = h('textarea', { placeholder: 'paste a whole config export here' });
  var wantSettings = h('input', { type: 'checkbox' });
  var wantAcl = h('input', { type: 'checkbox' });
  var cfgOut = h('div', null, []);

  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Import a whole config']),
    h('label', null, ['Config json']), cfg,
    h('label', null, [wantSettings, 'bring the settings across too']),
    h('label', null, [wantAcl, 'bring the ip allow list across too']),
    h('button', {
      onclick: function () {
        if (!confirm('Import this config?')) return;
        api('POST', '/import', {
          data: cfg.value,
          rules: true,
          settings: wantSettings.checked,
          ip_acl: wantAcl.checked
        }).then(function (d) {
          clear(cfgOut);
          cfgOut.appendChild(notice(
            'Rules: ' + d.rules + '. Settings: ' + d.settings + '. Networks: ' + d.ip_acl + '. Problems: ' + d.errors.length + '.',
            d.errors.length ? 'err' : 'ok'
          ));
          // what was skipped and why, the count alone doesn't say which setting stayed as it was
          if (d.errors.length) {
            cfgOut.appendChild(table(['What', 'Problem'], d.errors.slice(0, 50).map(function (e) {
              var what = e.setting === true ? 'settings' : e.setting || e.cidr || e.pattern || '';
              return [h('span', { class: 'mono' }, [String(what)]), e.error];
            })));
          }
        }).catch(function (e) { clear(cfgOut); cfgOut.appendChild(notice(e.message, 'err')); });
      }
    }, ['Import config'])
  ]));
  body.appendChild(cfgOut);
}

export { viewTransfer };
