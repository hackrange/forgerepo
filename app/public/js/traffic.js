// ForgeRepo portal: traffic.
// Author: Tim Rice

import { h, link } from './dom.js';
import { ecoIcon } from './ecosystems.js';
import { bytes, clear, notice, pager, table, when } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';
import { UNASSIGNED, unassigned } from './labels.js';
import { route } from './routing.js';

var logsPage = 1;
var logsFilter = { action: '', package: '', application: '', environment: '' };
// api caps a page at 1000
var LOG_PAGE_SIZES = [100, 500, 1000];
var logsLimit = LOG_PAGE_SIZES[0];

// metadata requests name no version, so it's what npm fetched after or the latest tag as a guess.
// guesses are grayed out, the column's only useful if you can trust it
function pulled(e) {
  if (!e.pulled_version) return '';
  if (e.pulled_exact) return h('span', { class: 'mono' }, [e.pulled_version]);
  return h('span', {
    class: 'mono muted',
    title: 'nothing was downloaded against this request, so this is the latest version on offer, not a version npm took'
  }, [e.pulled_version + ' (latest)']);
}

function fact(dl, label, value) {
  if (value === null || value === undefined || value === '') return;
  dl.appendChild(h('dt', null, [label]));
  dl.appendChild(h('dd', null, [value]));
}

function listOf(items) {
  return h('ul', { class: 'plain' }, items.map(function (x) { return h('li', null, [x]); }));
}

// everything the box knows about one line, drawn as text
function drawDetail(box, d) {
  clear(box);
  var ev = d.evidence || {};
  box.appendChild(h('h3', null, [d.what, h('small', null, [link('close', function () { clear(box); })])]));
  var dl = h('dl', { class: 'facts' }, []);
  fact(dl, 'Why', d.why);
  fact(dl, 'Package', d.package ? h('span', { class: 'mono' }, [d.ecosystem + ':' + d.package + (d.version ? ' ' + d.version : '')]) : h('span', { class: 'mono' }, [d.request.method + ' ' + d.request.path]));
  fact(dl, 'When', when(d.when));
  fact(dl, 'What ForgeRepo did', d.action);
  fact(dl, 'Who', [d.who.user ? 'account ' + d.who.user : null, d.who.token ? 'token ' + d.who.token : null, d.who.ip, d.who.ci ? 'in ' + d.who.ci : null].filter(Boolean).join(', ') || 'nobody identified');
  fact(dl, 'Application', d.application || unassigned());
  fact(dl, 'Environment', d.environment || unassigned());
  if (ev.rule) {
    fact(dl, 'Rule', (ev.rule.kind === 'deny' ? 'deny ' : 'allow ') + ev.rule.pattern + (ev.rule.version_range ? ' ' + ev.rule.version_range : '') +
      ' at priority ' + ev.rule.priority + (ev.rule.note ? ': ' + ev.rule.note : '') + (ev.rule.created_by ? ' (by ' + ev.rule.created_by + ')' : ''));
  }
  if (ev.killSwitches && ev.killSwitches.length) {
    fact(dl, 'Kill switch', listOf(ev.killSwitches.map(function (k) {
      return (k.kind === 'package' ? 'the package' + (k.version_range ? ' ' + k.version_range : '') : k.kind + ' ' + k.subject) + ', by ' + (k.created_by || 'someone') + ' ' + when(k.created_at) + ': ' + k.reason;
    })));
  }
  if (ev.lookalike) {
    fact(dl, 'Lookalike', 'looks like ' + ev.lookalike.looks_like + ' (' + ev.lookalike.technique + '), ' + ev.lookalike.last_action + ', ' + ev.lookalike.hits + ' hit(s), ' + ev.lookalike.status);
  }
  if (ev.finding) {
    fact(dl, 'Known advisory', String(ev.finding.severity).toLowerCase() + ' ' + (ev.finding.cves || ev.finding.advisories) + (ev.finding.summary ? ': ' + ev.finding.summary : ''));
  }
  (ev.files || []).forEach(function (f) {
    var bits = [];
    f.scans.forEach(function (s) { bits.push('scan ' + s.scanner + ': ' + s.status + (s.signature ? ' (' + s.signature + ')' : '')); });
    f.holds.forEach(function (x) { bits.push('hold (' + x.source + ', ' + x.status + '): ' + x.reason); });
    f.integrity.forEach(function (x) { bits.push('integrity alert (' + x.kind + ', ' + x.status + '): now ' + x.observed); });
    if (f.license) bits.push('license ' + (f.license.expression || 'unknown') + ': ' + f.license.verdict);
    if (f.provenance) bits.push('provenance ' + f.provenance.status + (f.provenance.source_repository ? ' from ' + f.provenance.source_repository : ''));
    fact(dl, 'File ' + f.filename, [h('div', { class: 'mono' }, ['sha256 ' + (f.sha256 || '?')]), bits.length ? listOf(bits) : h('span', { class: 'muted' }, ['nothing held against it'])]);
  });
  if (ev.consumers && Number(ev.consumers.consumers)) {
    fact(dl, 'Already pulled', ev.consumers.downloads + ' download(s) by ' + ev.consumers.consumers + ' consumer(s) in ' + ev.consumers.applications + ' application(s), last ' + when(ev.consumers.last_seen));
  }
  if (ev.requests && ev.requests.length) {
    fact(dl, 'Waiting requests', listOf(ev.requests.map(function (r) {
      return '#' + r.id + ' ' + (r.version_range || 'any version') + ', from ' + (r.requested_by || r.token_name || r.source) + ', asked ' + r.hits + ' time(s)';
    })));
  }
  if (ev.sameInstall && ev.sameInstall.length) {
    fact(dl, 'Same install', listOf(ev.sameInstall.map(function (s) {
      return s.action + ' ' + s.status + ' ' + s.path + (s.reason ? ': ' + s.reason : '');
    })));
  }
  box.appendChild(dl);
  box.appendChild(notice('What to do: ' + d.next, d.kind === 'served' ? 'ok' : 'info'));
}

function showDetail(box, id) {
  clear(box);
  box.appendChild(h('p', { class: 'muted' }, ['Gathering the evidence...']));
  api('GET', '/logs/' + id).then(function (d) {
    drawDetail(box, d);
    box.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }).catch(function (e) { clear(box); box.appendChild(notice(e.message, 'err')); });
}

function logsQuery() {
  return (logsFilter.action ? '&action=' + logsFilter.action : '') +
    (logsFilter.package ? '&package=' + encodeURIComponent(logsFilter.package) : '') +
    (logsFilter.application ? '&application=' + encodeURIComponent(logsFilter.application) : '') +
    (logsFilter.environment ? '&environment=' + encodeURIComponent(logsFilter.environment) : '');
}

function viewLogs(body) {
  var query = '?page=' + logsPage + '&limit=' + logsLimit + logsQuery();

  return Promise.all([
    api('GET', '/logs' + query),
    api('GET', '/applications'),
    api('GET', '/environments')
  ]).then(function (results) {
    var d = results[0];
    section(body, 'Traffic', 'Every request a package manager made against this registry.');

    // retired entries still show, people come looking for those after the fact
    function filterFor(entries, chosen) {
      var opts = [
        h('option', { value: '' }, ['every one']),
        h('option', { value: UNASSIGNED, selected: chosen === UNASSIGNED ? 'selected' : null }, ['unassigned'])
      ];
      entries.forEach(function (e) {
        opts.push(h('option', {
          value: e.name,
          selected: chosen === e.name ? 'selected' : null
        }, [e.name]));
      });
      return h('select', null, opts);
    }
    var appFilter = filterFor(results[1].entries, logsFilter.application);
    var envFilter = filterFor(results[2].entries, logsFilter.environment);

    var pkg = h('input', { type: 'text', value: logsFilter.package, placeholder: 'package name' });
    var action = h('select', null, [
      h('option', { value: '' }, ['everything']),
      h('option', { value: 'deny', selected: logsFilter.action === 'deny' }, ['blocked only']),
      h('option', { value: 'allow', selected: logsFilter.action === 'allow' }, ['served only']),
      h('option', { value: 'error', selected: logsFilter.action === 'error' }, ['errors only']),
      h('option', { value: 'audit', selected: logsFilter.action === 'audit' }, ['would have blocked'])
    ]);
    // bigger page shifts things, back to page one
    var size = h('select', null, LOG_PAGE_SIZES.map(function (n) {
      return h('option', { value: String(n), selected: logsLimit === n }, [n + ' rows']);
    }));
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        logsFilter.package = pkg.value.trim();
        logsFilter.action = action.value;
        logsFilter.application = appFilter.value;
        logsFilter.environment = envFilter.value;
        logsLimit = Number(size.value) || LOG_PAGE_SIZES[0];
        logsPage = 1;
        route();
      }
    }, [
      h('div', null, [h('label', null, ['Package']), pkg]),
      h('div', null, [h('label', null, ['Application']), appFilter]),
      h('div', null, [h('label', null, ['Environment']), envFilter]),
      h('div', null, [h('label', null, ['Show']), action]),
      h('div', null, [h('label', null, ['Per page']), size]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    body.appendChild(h('fieldset', null, [
      h('legend', null, ['Export the traffic']),
      h('p', { class: 'hint' }, [
        'Every request the filter above matches, not just the page on screen. The file carries the ' +
        'application and environment on every row, and adds the install session id, which is the same ' +
        'on every request npm made in one go, so a metadata request and the tarball it led to can be ' +
        'lined up. Leave the filter empty and it is the whole log, which on a busy box is a large ' +
        'file, so narrow it down first if you can.'
      ]),
      h('div', null, [
        h('button', {
          type: 'button',
          onclick: function () { download('/logs/export?format=csv' + logsQuery(), 'forgerepo-traffic.csv'); }
        }, ['Export CSV']),
        h('button', {
          type: 'button',
          onclick: function () { download('/logs/export?format=json' + logsQuery(), 'forgerepo-traffic.json'); }
        }, ['Export JSON'])
      ])
    ]));

    var detailBox = h('div', { class: 'event-detail', 'aria-live': 'polite' }, []);
    body.appendChild(detailBox);

    body.appendChild(table(
      ['When', 'From', 'Application', 'Environment', 'Package', 'Version', 'Pulled version', 'Result', 'Why',
        { label: 'Size', num: true }, 'Cache', ''],
      d.entries.map(function (e) {
        return [
          when(e.ts),
          e.token_name ? e.ip + ' (' + e.token_name + ')' : e.ip,
          e.application || unassigned(),
          e.environment || unassigned(),
          e.package_name ? h('span', { class: 'eco-pkg' }, [ecoIcon(e.ecosystem), h('span', { class: 'mono' }, [e.package_name])]) : h('span', { class: 'mono' }, [e.path]),
          e.version || '',
          pulled(e),
          h('span', { class: e.action === 'deny' ? 'deny' : e.action === 'allow' ? 'allow' : null },
            [e.action + ' ' + e.status]),
          e.reason || '',
          e.bytes ? bytes(e.bytes) : '',
          e.cache_hit ? 'hit' : '',
          link(e.action === 'allow' ? 'details' : 'why', function () { showDetail(detailBox, e.id); })
        ];
      })
    ));
    body.appendChild(pager(d.page, d.total, d.limit, function (p) { logsPage = p; route(); }));
  });
}

export { viewLogs };
