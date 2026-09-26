// ForgeRepo portal: kill switch.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { can, clear, notice, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { ecoName, ecoPkg, ecoPlaceholders, ecoPrefix, ecoSelect } from './ecosystems.js';
import { route } from './routing.js';

var KILL_KINDS = [
  ['package', 'A package', 'Leave versions empty to kill every version.'],
  ['hash', 'One file, by its sha256', 'Takes those exact bytes away under any name and registry they turn up with, including a copy that arrives later. ' +
    'For npm that is the version the tarball is, for PyPI only that file, the rest of the release stays.'],
  ['advisory', 'An advisory', 'Takes away every version the vulnerability scan has recorded against it, under any of its names (a GHSA, its PYSEC twin, its CVE). ' +
    'Versions the scan has not matched yet are covered as soon as it does, so run a scan if the advisory is brand new.']
];

// what one kill takes away, in words
function killWhat(k) {
  if (k.kind === 'hash') return h('span', { class: 'mono deny', title: k.subject }, ['file ' + k.subject.slice(0, 16) + '...']);
  if (k.kind === 'advisory') return h('span', { class: 'mono deny' }, [k.subject]);
  return h('span', { class: 'deny' }, [ecoPkg(k.ecosystem, k.package_name)]);
}

function killVersions(k) {
  if (!k.kind || k.kind === 'package') return k.version_range || 'every version';
  if (k.covers === undefined) return '';
  if (!k.covers) return h('span', { class: 'muted' }, ['nothing seen yet']);
  return k.covers + ' known: ' + (k.reach || []).map(function (r) { return ecoPrefix(r.ecosystem) + r.package + ' ' + r.version; }).join(', ') +
    (k.covers > (k.reach || []).length ? ', ...' : '');
}

function killType(k) {
  return !k.kind || k.kind === 'package' ? 'package' : (k.kind === 'hash' ? 'file' : 'advisory');
}

// hundreds at once from a CSV, for the day an advisory lists a whole campaign. admins only, previewed first
function bulkForm() {
  var file = h('input', { type: 'file', accept: '.csv,.txt,text/csv,text/plain' });
  var text = h('textarea', { rows: '6', placeholder: 'package,version,type\nevent-stream,3.3.6,npm\nrequests,2.31.0,pypi\nlibrary/nginx,1.25.3,docker\nflatmap-stream,,npm' });
  var reason = h('input', { type: 'text', placeholder: 'what happened, it is shown to everyone who gets refused' });
  var purge = h('input', { type: 'checkbox' });
  var out = h('div', null, []);
  file.addEventListener('change', function () {
    var f = file.files && file.files[0];
    if (!f) return;
    if (f.size > 2 * 1024 * 1024) return alert('That file is over 2 MB, split it up.');
    f.text().then(function (t) { text.value = t; });
  });
  function send(dry) {
    if (!text.value.trim()) return alert('Pick a CSV file or paste the rows.');
    if (!dry && !reason.value.trim()) return alert('Say why. The reason is shown to everyone who gets refused.');
    clear(out);
    out.appendChild(h('p', { class: 'hint' }, [dry ? 'Reading the rows...' : 'Killing them...']));
    return api('POST', '/killswitch/bulk', { csv: text.value, reason: reason.value.trim(), purge: purge.checked, dry_run: dry }).then(function (r) {
      clear(out);
      if (dry) {
        var ready = r.kills.filter(function (k) { return !k.already; });
        out.appendChild(notice(r.rows + ' row(s) read, ' + r.kills.length + ' package(s). ' + ready.length + ' to kill, ' +
          (r.kills.length - ready.length) + ' already killed' + (r.errors.length ? ', ' + r.errors.length + ' row(s) that cannot be read, listed below' : '') + '.',
          r.errors.length ? 'info' : 'ok'));
        out.appendChild(table(['Package', 'Versions', 'Rows', ''], r.kills.map(function (k) {
          return [ecoPkg(k.ecosystem, k.name), k.range || 'every version', k.lines.join(', '),
            k.already ? h('span', { class: 'muted' }, ['already killed']) : h('span', { class: 'deny' }, ['will be killed'])];
        })));
        if (r.errors.length) {
          out.appendChild(h('h3', null, ['Rows that cannot be read']));
          out.appendChild(table(['Line', 'Row', 'Why'], r.errors.map(function (e) { return [String(e.line), h('span', { class: 'mono' }, [e.text]), e.error]; })));
        }
        if (ready.length) {
          out.appendChild(h('button', {
            type: 'button', class: 'danger',
            onclick: function () {
              if (!reason.value.trim()) return alert('Say why. The reason is shown to everyone who gets refused.');
              if (!confirm('Kill ' + ready.length + ' package(s)? Every install of them stops right now, for everyone.')) return;
              send(false);
            }
          }, ['Kill ' + ready.length + ' package(s)']));
        }
      } else {
        out.appendChild(notice('Killed ' + r.killed.length + ' package(s).' + (r.skipped.length ? ' ' + r.skipped.length + ' were already killed.' : '') +
          (r.failed.length ? ' ' + r.failed.length + ' failed: ' + r.failed.slice(0, 5).map(function (k) { return k.name + ' (' + k.error + ')'; }).join(', ') : '') +
          ' Admins get one email with the list.', r.failed.length ? 'err' : 'ok'));
        setTimeout(route, 1500);
      }
    }).catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
  }
  return h('fieldset', null, [
    h('legend', null, ['Kill from a CSV']),
    h('p', { class: 'hint' }, [
      'For an advisory that lists a whole campaign. One row per package: package, version, type. Type is npm, pypi (or python) or oci (or docker). ' +
      'Leave the version empty to kill every version, or give a range. A header row can put the columns in any order. Up to 5000 rows. ' +
      'Check the file first: nothing is killed until you have seen the list.'
    ]),
    file, text,
    h('label', null, ['Reason']), reason,
    can('packages:purge') ? h('label', null, [purge, ' Also delete the cached copies now']) : null,
    h('div', null, [h('button', { type: 'button', onclick: function () { send(true); } }, ['Check the file'])]),
    out
  ]);
}

function viewKillswitch(body) {
  var types = state.ecosystems || [];
  return api('GET', '/killswitch').then(function (d) {
    section(body, 'Kill switch',
      'For the morning a package turns out to be compromised. A kill takes a package, some of its versions, one file by its hash, or everything an ' +
      'advisory is recorded against, away from every token, application and environment at once. It beats every allow rule, pin, scope and ' +
      'exemption, and audit only mode, until someone lifts it. Killed versions are left out of npm and PyPI metadata and refused by name, with your reason.');

    if (d.canKill) {
      var kind = h('select', null, KILL_KINDS.map(function (k) { return h('option', { value: k[0] }, [k[1]]); }));
      var type = ecoSelect(types);
      var name = h('input', { type: 'text', placeholder: 'event-stream' });
      var range = h('input', { type: 'text', placeholder: 'every version, or 3.3.6, or >=2.0.0 <2.3.1' });
      ecoPlaceholders(type, [
        [name, { npm: 'event-stream', pypi: 'ctx', oci: 'acme/app, or nginx' }],
        [range, { npm: 'every version, or 3.3.6, or >=2.0.0 <2.3.1', pypi: 'every release, or 0.2.6, or >=0.1,<0.3', oci: 'every tag, or latest, or 1.27.*, or a sha256 digest' }]
      ]);
      var subject = h('input', { type: 'text', spellcheck: 'false' });
      var subjectLabel = h('label', null, ['']);
      var reason = h('input', { type: 'text', maxlength: '500', placeholder: 'what happened, it is shown to everyone who gets refused' });
      var purge = h('input', { type: 'checkbox' });
      if (!can('packages:purge')) purge.setAttribute('disabled', 'disabled');
      var hint = h('p', { class: 'hint' }, ['']);
      var out = h('div', null, []);
      var packageRow = h('div', { class: 'row' }, [
        type ? h('div', null, [h('label', null, ['Type']), type]) : null,
        h('div', null, [h('label', null, ['Package']), name]),
        h('div', null, [h('label', null, ['Versions']), range])
      ]);
      var subjectRow = h('div', null, [subjectLabel, subject]);
      var describeKind = function () {
        var k = KILL_KINDS.filter(function (x) { return x[0] === kind.value; })[0];
        hint.textContent = k[2] + ' Admins and approvers get an email straight away, with who has pulled it recently.';
        packageRow.hidden = kind.value !== 'package';
        subjectRow.hidden = kind.value === 'package';
        subjectLabel.textContent = kind.value === 'hash' ? 'sha256 of the file' : 'Advisory id';
        subject.placeholder = kind.value === 'hash' ? '64 hex characters, as shown on the Artifacts page' : 'CVE-2021-44228, GHSA-xxxx-xxxx-xxxx or PYSEC-2024-1';
      };
      kind.addEventListener('change', describeKind);
      describeKind();

      body.appendChild(h('fieldset', { class: 'kill-form' }, [
        h('legend', null, ['Kill something']),
        h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Kill']), kind])]),
        packageRow,
        subjectRow,
        h('label', null, ['Reason']), reason,
        h('label', null, [purge, ' Also delete the cached copies now']),
        hint,
        h('button', {
          type: 'button',
          class: 'danger',
          onclick: function () {
            var byPackage = kind.value === 'package';
            if (byPackage && !name.value.trim()) return alert('Which package?');
            if (!byPackage && !subject.value.trim()) return alert(kind.value === 'hash' ? 'Which file? Paste its sha256.' : 'Which advisory?');
            if (!reason.value.trim()) return alert('Say why. The reason is shown to everyone who gets refused.');
            var what = byPackage ? name.value.trim() + (range.value.trim() ? ' ' + range.value.trim() : ' (every version)')
              : (kind.value === 'hash' ? 'every file with sha256 ' : 'everything recorded against ') + subject.value.trim();
            if (!confirm('Kill ' + what + '? Every install of it stops right now, for everyone.')) return;
            var payload = { kind: kind.value, reason: reason.value.trim(), purge: purge.checked };
            if (byPackage) {
              payload.ecosystem = type ? type.value : 'npm';
              payload.package_name = name.value.trim();
              payload.version_range = range.value.trim();
            } else {
              payload.subject = subject.value.trim();
            }
            api('POST', '/killswitch', payload).then(function (r) {
              killImpact = r.kill.id;
              route();
            }).catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
          }
        }, ['Kill it']),
        out
      ]));
    }

    if (can('settings:write')) body.appendChild(bulkForm());

    var impactBox = h('div', null, []);
    var showImpact = function (k) {
      clear(impactBox);
      if (!can('logs:read')) return;
      var byPackage = !k.kind || k.kind === 'package';
      impactBox.appendChild(h('p', { class: 'hint' }, ['Asking the traffic log...']));
      api('GET', '/killswitch/' + k.id + '/impact?days=30').then(function (r) {
        clear(impactBox);
        impactBox.appendChild(h('h3', null, ['Who pulled ' + (byPackage ? k.package_name + (k.version_range ? ' ' + k.version_range : '') : k.subject) + ' in the last 30 days']));
        if (!r.pulled.length) {
          impactBox.appendChild(notice('Nothing in the traffic log shows it being pulled in that time.', 'ok'));
          return;
        }
        var cols = ['Version', 'Token', 'Application', 'Environment', 'Address', { label: 'Downloads', num: true }, 'Last'];
        if (!byPackage) cols.unshift('Package');
        impactBox.appendChild(table(cols, r.pulled.map(function (p) {
          var cells = [h('span', { class: 'mono' }, [p.version || '?']), p.token || h('span', { class: 'muted' }, ['no token']), p.application || '', p.environment || '',
            h('span', { class: 'mono' }, [p.ip || '']), String(p.downloads), when(p.last)];
          if (!byPackage) cells.unshift(ecoPkg(p.ecosystem, p.package || ''));
          return cells;
        })));
      }).catch(function (e) { clear(impactBox); impactBox.appendChild(notice(e.message, 'err')); });
    };

    body.appendChild(h('h3', null, ['On the kill switch now']));
    if (!d.active.length) body.appendChild(h('p', { class: 'hint' }, ['Nothing is killed.']));
    else {
      body.appendChild(table(['Type', 'What', 'Versions', 'Reason', 'Killed by', 'When', { label: 'Files deleted', num: true }, ''], d.active.map(function (k) {
        var acts = h('span', { class: 'actions' }, [
          can('logs:read') ? link('who pulled it', function () { showImpact(k); }) : null,
          d.canKill ? link('lift', function () {
            var note = prompt('Lift the kill on ' + (k.kind && k.kind !== 'package' ? k.subject : k.package_name) + '? It goes back to what the rules say. Why?', '');
            if (note === null) return;
            api('POST', '/killswitch/' + k.id + '/lift', { note: note }).then(route).catch(function (e) { alert(e.message); });
          }, 'deny') : null
        ]);
        return [killType(k), killWhat(k), killVersions(k), k.reason, k.created_by || '', when(k.created_at), String(k.purged_files), acts];
      })));
    }
    body.appendChild(impactBox);
    if (killImpact) {
      var fresh = d.active.filter(function (k) { return k.id === killImpact; })[0];
      killImpact = null;
      if (fresh) showImpact(fresh);
    }

    if (d.lifted.length) {
      body.appendChild(h('h3', null, ['Lifted']));
      body.appendChild(table(['Type', 'What', 'Versions', 'Reason', 'Killed', 'Lifted', 'Why'], d.lifted.map(function (k) {
        return [killType(k), h('span', { class: 'mono' }, [k.kind && k.kind !== 'package' ? k.subject : k.package_name]),
          !k.kind || k.kind === 'package' ? k.version_range || 'every version' : '', k.reason,
          (k.created_by || '') + ', ' + when(k.created_at), (k.lifted_by || '') + ', ' + when(k.lifted_at), k.lift_note || ''];
      })));
    }
  });
}

var killImpact = null;

export { viewKillswitch };
