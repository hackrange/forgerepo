// ForgeRepo portal: packages.
// Author: Tim Rice

import { h, link } from './dom.js';
import { ecoPkg } from './ecosystems.js';
import { bytes, can, modal, notice, pager, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { quickAllow } from './overview.js';
import { cacheMaintenance } from './cache-housekeeping.js';
import { route } from './routing.js';
import { state } from './state.js';
import { showArtifacts } from './artifacts.js';

var packagesPage = 1;
var packagesLimit = 50;
var packagesQuery = '';
var packagesType = 'npm';

function viewPackages(body) {
  var types = state.ecosystems || [];
  if (!types.some(function (t) { return t.id === packagesType; })) packagesType = 'npm';
  var query = '?page=' + packagesPage + '&limit=' + packagesLimit + (packagesQuery ? '&q=' + encodeURIComponent(packagesQuery) : '') +
    (packagesType !== 'npm' ? '&type=' + encodeURIComponent(packagesType) : '');
  return api('GET', '/packages' + query).then(function (d) {
    section(body, 'Packages', 'Everything this registry has been asked for, and what the rules say about it today.');
    // PyPI projects and images are listed from the files this box holds
    if (packagesType !== 'npm') return storedList(body, d);

    var search = h('input', { type: 'text', value: packagesQuery, placeholder: 'package name' });
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) { e.preventDefault(); packagesQuery = search.value.trim(); packagesPage = 1; route(); }
    }, [
      types.length > 1 ? h('div', null, [h('label', null, ['Type']), typePicker(types)]) : null,
      h('div', null, [h('label', null, ['Search']), search]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    var selected = {};
    var boxes = [];
    var canPurge = can('packages:purge');
    var canRule = can('rules:write');

    var selectAll = h('input', { type: 'checkbox', title: 'select everything on this page' });
    var counter = h('span', { class: 'muted' }, ['none selected']);

    function refreshCount() {
      var n = Object.keys(selected).length;
      counter.textContent = n ? n + ' of ' + d.packages.length + ' on this page selected' : 'none selected';
    }

    selectAll.addEventListener('change', function () {
      boxes.forEach(function (b) {
        b.checked = selectAll.checked;
        if (selectAll.checked) selected[b.value] = true;
        else delete selected[b.value];
      });
      refreshCount();
    });

    function bulk(action, question) {
      var names = Object.keys(selected);
      if (!names.length) return alert('Tick a few packages first.');
      if (question && !confirm(question.replace('%n', names.length))) return;
      api('POST', '/packages/actions', { names: names, action: action })
        .then(function (r) {
          if (r.freed) alert('Done for ' + r.affected + '. Freed ' + bytes(r.freed) + ' of disk.');
          else if (r.skipped && r.skipped.length) alert('Done for ' + r.affected + '. Skipped ' + r.skipped.length + '.');
          route();
        })
        .catch(function (e) { alert(e.message); });
    }

    body.appendChild(table(
      [{ label: selectAll }, 'Package', 'Status', { label: 'Hits', num: true }, { label: 'Blocked', num: true },
        { label: 'Cached', num: true }, 'Last used', 'Actions'],
      d.packages.map(function (p) {
        var tick = h('input', { type: 'checkbox', value: p.name });
        if (!canPurge && !canRule) tick.setAttribute('disabled', 'disabled');
        tick.addEventListener('change', function () {
          if (tick.checked) selected[p.name] = true;
          else delete selected[p.name];
          refreshCount();
        });
        boxes.push(tick);

        var actions = h('span', { class: 'actions' }, []);
        if (can('packages:purge')) {
          actions.appendChild(link('purge cache', function () {
            if (!confirm('Drop the cached copies of ' + p.name + '?')) return;
            api('POST', '/packages/purge', { name: p.name }).then(route).catch(function (e) { alert(e.message); });
          }));
        }
        if (can('rules:write') && !p.allowed) {
          actions.appendChild(link('allow it', function () { quickAllow(p.name); }));
        }
        return [
          tick,
          ecoPkg('npm', p.name),
          h('span', { class: p.allowed ? 'allow' : 'deny' }, [p.allowed ? 'allowed' : 'blocked']),
          String(p.hits),
          String(p.blocked_hits),
          p.cached_versions + ' (' + bytes(p.cached_bytes) + ')',
          when(p.last_access),
          actions
        ];
      })
    ));

    if ((canPurge || canRule) && d.packages.length) {
      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Do this to the ticked packages']),
        h('p', { class: 'hint' }, [
          'The box in the header ticks everything on this page, not the whole filtered set. ' +
          'Purge frees disk and the package downloads again next time. Forget also drops it off this list, ' +
          'and it reappears the moment somebody asks for it. Neither one changes whether it is allowed.'
        ]),
        counter,
        h('div', null, [
          canPurge ? h('button', { onclick: function () { bulk('purge', 'Purge the cached files for %n package(s)?'); } }, ['Purge cache']) : null,
          canRule ? h('button', { onclick: function () { bulk('allow', 'Write an allow rule for %n package(s)?'); } }, ['Allow']) : null,
          canRule ? h('button', { onclick: function () { bulk('deny', 'Write a deny rule for %n package(s)?'); } }, ['Deny']) : null,
          canPurge ? h('button', { class: 'danger', onclick: function () { bulk('forget', 'Forget %n package(s)? Cached files go too.'); } }, ['Forget']) : null
        ])
      ]));
    }

    body.appendChild(pager(d.page, d.total, d.limit, function (p) { packagesPage = p; route(); }));

    var sizePick = h('select', null, [50, 100, 500, 1000].map(function (n) {
      return h('option', { value: String(n), selected: packagesLimit === n }, [n + ' per page']);
    }));
    sizePick.addEventListener('change', function () {
      packagesLimit = parseInt(sizePick.value, 10);
      packagesPage = 1;
      route();
    });
    body.appendChild(h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Rows']), sizePick])]));

    if (can('cache:purge')) {
      body.appendChild(cacheMaintenance());
      body.appendChild(h('button', {
        class: 'danger',
        onclick: function () {
          if (!confirm('Throw away the whole cache? Packages get pulled again on the next install.')) return;
          api('POST', '/cache/purge', {}).then(route).catch(function (e) { alert(e.message); });
        }
      }, ['Empty the entire cache']));
    }
  });
}

function typePicker(types) {
  var pick = h('select', null, types.map(function (t) {
    return h('option', { value: t.id, selected: t.id === packagesType }, [t.name]);
  }));
  pick.addEventListener('change', function () { packagesType = pick.value; packagesPage = 1; route(); });
  return pick;
}

// PyPI projects and images: what is on disk, what the rules say, and a way to the files themselves
function storedList(body, d) {
  var types = state.ecosystems || [];
  var image = packagesType === 'oci';
  var search = h('input', { type: 'text', value: packagesQuery, placeholder: image ? 'image name, like python' : 'project name' });
  body.appendChild(h('form', {
    class: 'row',
    onsubmit: function (e) { e.preventDefault(); packagesQuery = search.value.trim(); packagesPage = 1; route(); }
  }, [
    h('div', null, [h('label', null, ['Type']), typePicker(types)]),
    h('div', null, [h('label', null, ['Search']), search]),
    h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
  ]));
  body.appendChild(h('p', { class: 'hint' }, [image
    ? 'Images with files on this box. Cached counts the tags held completely, every layer of every image in the list, which is what Cache now on the Rules page delivers. Pulls come from the traffic log, so they cover as long as it is kept.'
    : 'Projects with files on this box. Cached counts the releases held.']));
  body.appendChild(table(
    ['Package', 'Status', { label: image ? 'Pulls' : 'Downloads', num: true }, { label: 'Cached', num: true }, 'Last used', 'Actions'],
    d.packages.map(function (p) {
      // the "of n tags" half opens the whole list
      var cached = image
        ? [p.cached_versions + ' of ', p.known_tags
          ? link(p.known_tags + ' tag' + (p.known_tags === 1 ? '' : 's'), function () { showTags(p.name); })
          : '0 tags', ', ' + bytes(p.cached_bytes)]
        : [p.cached_versions + ' (' + bytes(p.cached_bytes) + ')'];
      return [
        ecoPkg(packagesType, p.name),
        h('span', { class: p.allowed ? 'allow' : 'deny', title: p.reason || '' }, [p.allowed ? 'allowed' : 'blocked']),
        String(p.hits || 0),
        h('span', { class: image && p.cached_versions < p.known_tags ? 'warn' : null }, cached),
        when(p.last_access),
        h('span', { class: 'actions' }, [link(p.files + ' file' + (Number(p.files) === 1 ? '' : 's'), function () { showArtifacts(packagesType, p.name); })])
      ];
    })
  ));
  body.appendChild(pager(d.page, d.total, d.limit, function (n) { packagesPage = n; route(); }));
}

// every tag of one image, allowed or not, and how much of each is on disk
function showTags(name) {
  var box = modal('Tags of ' + name, h('p', { class: 'muted' }, ['Loading...']));
  api('GET', '/packages/tags?name=' + encodeURIComponent(name)).then(function (d) {
    var ok = d.tags.filter(function (t) { return t.allowed; }).length;
    box.set(h('div', null, [
      h('p', { class: 'hint' }, [ok + ' of ' + d.tags.length + ' allowed by the rules as they stand now. Cached means every layer of every platform is on this box.']),
      table(['Tag', 'Status', 'Cached', 'Digest', 'Last checked'], d.tags.map(function (t) {
        return [
          h('code', null, [t.tag]),
          h('span', { class: t.allowed ? 'allow' : 'deny', title: t.reason || '' }, [t.allowed ? 'allowed' : 'blocked']),
          t.complete
            ? h('span', { class: 'allow' }, ['yes'])
            : h('span', { class: 'warn' }, [t.files ? t.held_files + ' of ' + t.files + ' files' : 'no']),
          h('code', { class: 'muted', title: t.digest || '' }, [t.digest ? t.digest.slice(7, 19) : '-']),
          when(t.checked_at)
        ];
      }))
    ]));
  }).catch(function (e) { box.set(notice(e.message, 'err')); });
}

export { viewPackages };
