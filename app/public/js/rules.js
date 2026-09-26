// ForgeRepo portal: rules.
// Author: Tim Rice

import { state } from './state.js';
import { ecoHints, ecoName, ecoPkg, ecoSelect } from './ecosystems.js';
import { h, link } from './dom.js';
import { can, clear, pager, table } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';
import { route } from './routing.js';

var rulesPage = 1;
var rulesLimit = 50;
var rulesFilter = { ecosystem: '', kind: '', q: '', cached: '', vuln: '', application: '', environment: '' };

// shared by the list and its export so they match
function rulesQuery() {
  return (rulesFilter.ecosystem ? '&ecosystem=' + rulesFilter.ecosystem : '') +
    (rulesFilter.kind ? '&kind=' + rulesFilter.kind : '') +
    (rulesFilter.cached ? '&cached=' + rulesFilter.cached : '') +
    (rulesFilter.vuln ? '&vuln=' + rulesFilter.vuln : '') +
    (rulesFilter.application ? '&application=' + encodeURIComponent(rulesFilter.application) : '') +
    (rulesFilter.environment ? '&environment=' + encodeURIComponent(rulesFilter.environment) : '') +
    (rulesFilter.q ? '&q=' + encodeURIComponent(rulesFilter.q) : '');
}

// pinned rules count exact versions on disk. 3 of 5 pins is NOT cached
function cacheCell(r) {
  //null means that kind of registry has nothing cached to count
  if (r.cached_versions === null || r.cached_versions === undefined) return h('span', { class: 'muted' }, ['n/a']);
  if (r.pattern.indexOf('*') >= 0) return h('span', { class: 'muted' }, ['n/a']);
  if (r.pinned_versions === null || r.pinned_versions === undefined) {
    return Number(r.cached_versions) > 0
      ? String(r.cached_versions)
      : h('span', { class: 'muted' }, ['none']);
  }
  var have = Number(r.cached_pins);
  var want = Number(r.pinned_versions);
  // an image can be half downloaded, the note says how far it got
  var note = r.cache_note ? h('div', { class: 'hint' }, [r.cache_note]) : null;
  if (!have) return h('span', { class: 'muted' }, ['0 of ' + want, note]);
  return h('span', { class: have >= want ? null : 'warn' }, [have + ' of ' + want, note]);
}

// pinned = check those versions, otherwise the name. wildcards name nothing, skip
function vulnCell(r) {
  if (r.pattern.indexOf('*') >= 0) return h('span', { class: 'muted' }, ['n/a']);
  var n = Number(r.vuln_findings) || 0;
  if (!n) return h('span', { class: 'muted' }, ['none']);
  var worst = String(r.vuln_worst || '').toLowerCase();
  return h('span', { class: r.vuln_worst === 'CRITICAL' || r.vuln_worst === 'HIGH' ? 'deny' : 'warn' },
    [n + (worst ? ' ' + worst : '')]);
}

// who a rule covers, in words
function scopeLabel(appName, envName, appId, envId) {
  var app = appId ? (appName || 'a deleted application') : null;
  var env = envId ? (envName || 'a deleted environment') : null;
  if (app && env) return app + ' in ' + env;
  if (app) return app + ', any environment';
  if (env) return env + ', any application';
  return 'everyone';
}

// one application or environment, or blank for everyone. retired only shows when it is already the pick
function scopePick(entries, current, blankLabel) {
  return h('select', null, [h('option', { value: '' }, [blankLabel])].concat((entries || []).filter(function (x) {
    return !x.retired || String(x.id) === String(current);
  }).map(function (x) {
    return h('option', { value: String(x.id), selected: String(current) === String(x.id) }, [x.name + (x.retired ? ' (retired)' : '')]);
  })));
}

function scopeLists() {
  return Promise.all([
    api('GET', '/applications').then(function (d) { return d.entries || []; }).catch(function () { return []; }),
    api('GET', '/environments').then(function (d) { return d.entries || []; }).catch(function () { return []; })
  ]).then(function (r) { return { applications: r[0], environments: r[1] }; });
}

function viewRules(body) {
  // only offer a type choice when there's more than one, and let go of a stale pick instead of hiding the list
  var types = state.ecosystems || [];
  var typeName = ecoName;
  if (rulesFilter.ecosystem && (types.length < 2 || !types.some(function (t) { return t.id === rulesFilter.ecosystem; }))) {
    rulesFilter.ecosystem = '';
  }
  var query = '?page=' + rulesPage + '&limit=' + rulesLimit + rulesQuery();

  return Promise.all([api('GET', '/rules' + query), scopeLists()]).then(function (res) {
    var d = res[0];
    var scopes = res[1];
    section(body, 'Rules',
      'The higher priority wins first. At the same priority a rule for one application or environment beats a rule ' +
      'for everyone, for the tokens it covers, then an exact name beats a wildcard, then a deny beats an allow. ' +
      'With nothing matching, ' + (state.policyMode === 'whitelist' ? 'the package is blocked.' : 'the package is allowed.'));

    if (can('rules:write')) body.appendChild(ruleForm(types, scopes));

    var typePick = ecoSelect(types, { all: 'All', value: rulesFilter.ecosystem });
    var search = h('input', { type: 'text', value: rulesFilter.q, placeholder: 'name or note' });
    var kind = h('select', null, [
      h('option', { value: '' }, ['both kinds']),
      h('option', { value: 'allow', selected: rulesFilter.kind === 'allow' }, ['allow only']),
      h('option', { value: 'deny', selected: rulesFilter.kind === 'deny' }, ['deny only'])
    ]);
    var cachedPick = h('select', null, [
      h('option', { value: '' }, ['any cache state']),
      h('option', { value: 'no', selected: rulesFilter.cached === 'no' }, ['not cached']),
      h('option', { value: 'yes', selected: rulesFilter.cached === 'yes' }, ['cached'])
    ]);
    var vulnPick = h('select', null, [
      h('option', { value: '' }, ['any advisory state']),
      h('option', { value: 'yes', selected: rulesFilter.vuln === 'yes' }, ['vulnerable']),
      h('option', { value: 'no', selected: rulesFilter.vuln === 'no' }, ['not vulnerable'])
    ]);
    var filterScope = function (entries, current, anyLabel) {
      var sel = scopePick(entries, current === 'none' ? '' : current, anyLabel);
      sel.insertBefore(h('option', { value: 'none', selected: current === 'none' }, ['only rules for everyone']), sel.children[1] || null);
      return sel;
    };
    var appFilter = scopes.applications.length ? filterScope(scopes.applications, rulesFilter.application, 'any application') : null;
    var envFilter = scopes.environments.length ? filterScope(scopes.environments, rulesFilter.environment, 'any environment') : null;
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        rulesFilter.ecosystem = typePick ? typePick.value : '';
        rulesFilter.q = search.value.trim();
        rulesFilter.kind = kind.value;
        rulesFilter.cached = cachedPick.value;
        rulesFilter.vuln = vulnPick.value;
        rulesFilter.application = appFilter ? appFilter.value : '';
        rulesFilter.environment = envFilter ? envFilter.value : '';
        rulesPage = 1;
        route();
      }
    }, [
      typePick ? h('div', null, [h('label', null, ['Type']), typePick]) : null,
      h('div', null, [h('label', null, ['Search']), search]),
      h('div', null, [h('label', null, ['Kind']), kind]),
      appFilter ? h('div', null, [h('label', null, ['Application']), appFilter]) : null,
      envFilter ? h('div', null, [h('label', null, ['Environment']), envFilter]) : null,
      h('div', null, [h('label', null, ['Cache']), cachedPick]),
      h('div', null, [h('label', null, ['Advisories']), vulnPick]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    // the combo people actually want: approved, but nothing on disk yet
    body.appendChild(h('p', { class: 'hint' }, [
      'Cache state counts the exact versions a rule pins, not just anything held for that name, ' +
      'so "2 of 5" means three approved versions would have to come from upstream. ',
      link('Show approved but not cached', function () {
        rulesFilter.kind = 'allow';
        rulesFilter.cached = 'no';
        rulesPage = 1;
        route();
      }),
      ' — tick those and use Cache now below. Wildcard rules are left out of ' +
      '"not cached", since there is no single name to look up and they cannot be warmed.'
    ]));

    // the other combo people want: approved AND known bad. yikes
    body.appendChild(h('p', { class: 'hint' }, [
      'Advisories counts what the last vulnerability scan found against the versions a rule ' +
      'covers, so a rule pinned to 4.17.21 is clean when the advisory is against 4.17.20. ',
      link('Show allowed but vulnerable', function () {
        rulesFilter.kind = 'allow';
        rulesFilter.vuln = 'yes';
        rulesPage = 1;
        route();
      }),
      ' — the ',
      link('Vulnerabilities page', function () { window.location.hash = '#cve'; }),
      ' has the advisory behind each one. Wildcard rules are left out of both answers, since ' +
      'there is no single name to look up, and a rule nothing has been scanned for reads as none.'
    ]));

    if (can('rules:export')) {
      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Export what the filter matched']),
        h('p', { class: 'hint' }, [
          'Every rule the filter above matches, not just this page. The columns are the ones ' +
          'the Import / export page writes, so the file imports straight back into any box.'
        ]),
        h('div', null, [
          h('button', {
            type: 'button',
            onclick: function () { download('/rules/export?format=csv' + rulesQuery(), 'forgerepo-rules.csv'); }
          }, ['Export CSV']),
          h('button', {
            type: 'button',
            onclick: function () { download('/rules/export?format=json' + rulesQuery(), 'forgerepo-rules.json'); }
          }, ['Export JSON'])
        ])
      ]));
    }

    // ---- tick boxes and the bulk action bar ----
    var selected = {};
    var boxes = [];
    var writable = can('rules:write');

    var selectAll = h('input', { type: 'checkbox', title: 'select everything on this page' });
    var counter = h('span', { class: 'muted' }, ['none selected']);

    var editBox = h('div', null, []);

    function openEditor(r) {
      var pattern = h('input', { type: 'text', value: r.pattern });
      var kind = h('select', null, [
        h('option', { value: 'allow', selected: r.kind === 'allow' }, ['allow']),
        h('option', { value: 'deny', selected: r.kind === 'deny' }, ['deny'])
      ]);
      var range = h('input', { type: 'text', value: r.version_range || '', placeholder: 'any version' });
      var priority = h('input', { type: 'number', value: String(r.priority) });
      var note = h('input', { type: 'text', value: r.note || '' });
      var enabled = h('input', { type: 'checkbox', checked: r.enabled ? 'checked' : null });
      var appEdit = scopePick(scopes.applications, r.application_id || '', 'every application');
      var envEdit = scopePick(scopes.environments, r.environment_id || '', 'every environment');

      // version_range is 128 chars in the db, long || lists run out fast
      var used = h('p', { class: 'hint' }, ['']);
      function measure() {
        var n = range.value.trim().length;
        used.textContent = n + '/128 characters' + (n > 128 ? ' — too long, the save will be refused' : '');
      }
      range.addEventListener('input', measure);

      var extra = h('input', { type: 'text', placeholder: ecoHints(r.ecosystem).version });
      function addVersion() {
        var v = extra.value.trim();
        if (!v) return;
        range.value = range.value.trim() ? range.value.trim() + ' || ' + v : v;
        extra.value = '';
        measure();
      }
      extra.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); addVersion(); }
      });
      measure();

      editBox.textContent = '';
      editBox.appendChild(h('fieldset', null, [
        h('legend', null, ['Edit ' + (types.length > 1 ? typeName(r.ecosystem) + ' rule ' : '') + r.pattern]),
        h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Pattern']), pattern]),
          h('div', null, [h('label', null, ['Kind']), kind]),
          h('div', null, [h('label', null, ['Priority']), priority])
        ]),
        h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Application']), appEdit]),
          h('div', null, [h('label', null, ['Environment']), envEdit])
        ]),
        h('label', null, ['Version range']), range,
        used,
        h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Add a version to the list']), extra]),
          h('div', null, [h('button', { type: 'button', onclick: addVersion }, ['Append with ||'])])
        ]),
        h('p', { class: 'hint' }, [
          'Appending puts " || 1.2.3" on the end, which is how you widen a rule to cover another release. ' +
          'Clearing the box makes the rule cover every version of the package.'
        ]),
        h('label', null, ['Note']), note,
        h('label', null, [enabled, ' Enabled']),
        h('div', null, [
          h('button', {
            onclick: function () {
              api('PATCH', '/rules/' + r.id, {
                pattern: pattern.value.trim(),
                kind: kind.value,
                version_range: range.value.trim(),
                note: note.value.trim(),
                priority: priority.value,
                enabled: enabled.checked,
                application_id: appEdit.value,
                environment_id: envEdit.value
              }).then(route).catch(function (e) { alert(e.message); });
            }
          }, ['Save changes']),
          h('button', { onclick: function () { editBox.textContent = ''; } }, ['Cancel'])
        ])
      ]));
      editBox.scrollIntoView({ block: 'nearest' });
    }

    function refreshCount() {
      var n = Object.keys(selected).length;
      counter.textContent = n ? n + ' of ' + d.rules.length + ' on this page selected' : 'none selected';
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
      var ids = Object.keys(selected).map(Number);
      if (!ids.length) return alert('Tick a few rules first.');
      if (question && !confirm(question.replace('%n', ids.length))) return;
      api('POST', '/rules/actions', { ids: ids, action: action })
        .then(function (r) {
          if (r.skipped && r.skipped.length) {
            alert('Changed ' + r.affected + '. Skipped ' + r.skipped.length + ':\n\n' +
              r.skipped.slice(0, 10).map(function (s) { return (s.pattern || s.id) + ': ' + s.error; }).join('\n'));
          }
          route();
        })
        .catch(function (e) { alert(e.message); });
    }

    var ruleCols = [{ label: selectAll }, 'Pattern', 'Kind', 'Versions', 'Applies to', { label: 'Cached', num: true },
      { label: 'Advisories', num: true }, 'Note', { label: 'Priority', num: true }, 'Added by', 'Actions'];
    body.appendChild(table(
      ruleCols,
      d.rules.map(function (r) {
        var tick = h('input', { type: 'checkbox', value: String(r.id) });
        if (!writable) tick.setAttribute('disabled', 'disabled');
        tick.addEventListener('change', function () {
          if (tick.checked) selected[r.id] = true;
          else delete selected[r.id];
          refreshCount();
        });
        boxes.push(tick);

        var actions = h('span', { class: 'actions' }, []);
        if (can('rules:write')) {
          actions.appendChild(link('edit', function () { openEditor(r); }));
          actions.appendChild(link(r.enabled ? 'disable' : 'enable', function () {
            api('PATCH', '/rules/' + r.id, { enabled: !r.enabled }).then(route).catch(function (e) { alert(e.message); });
          }));
          actions.appendChild(link('flip to ' + (r.kind === 'allow' ? 'deny' : 'allow'), function () {
            api('PATCH', '/rules/' + r.id, { kind: r.kind === 'allow' ? 'deny' : 'allow' })
              .then(route).catch(function (e) { alert(e.message); });
          }));
          actions.appendChild(link('delete', function () {
            if (!confirm('Delete the rule for ' + r.pattern + '?')) return;
            api('DELETE', '/rules/' + r.id).then(route).catch(function (e) { alert(e.message); });
          }, 'deny'));
        }
        var cells = [
          tick,
          ecoPkg(r.ecosystem || 'npm', r.pattern),
          h('span', { class: r.kind === 'allow' ? 'allow' : 'deny' }, [r.kind + (r.enabled ? '' : ' (off)')]),
          r.version_range || 'any',
          h('span', { class: r.application_id || r.environment_id ? null : 'muted' }, [scopeLabel(r.application_name, r.environment_name, r.application_id, r.environment_id)]),
          cacheCell(r),
          vulnCell(r),
          r.note || '',
          String(r.priority),
          r.created_by || '',
          actions
        ];
        return cells;
      })
    ));

    body.appendChild(editBox);

    if (writable && d.rules.length) {
      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Do this to the ticked rules']),
        h('p', { class: 'hint' }, ['The box in the header ticks everything on this page, not the whole filtered set.']),
        counter,
        h('div', null, [
          h('button', { onclick: function () { bulk('allow', 'Make %n rule(s) allow?'); } }, ['Flip to allow']),
          h('button', { onclick: function () { bulk('deny', 'Make %n rule(s) deny?'); } }, ['Flip to deny']),
          h('button', { onclick: function () { bulk('enable'); } }, ['Enable']),
          h('button', { onclick: function () { bulk('disable'); } }, ['Disable']),
          h('button', { class: 'danger', onclick: function () { bulk('delete', 'Delete %n rule(s)? This cannot be undone.'); } }, ['Delete'])
        ])
      ]));

      // ---- pull the ticked allow rules onto disk ----
      var warmOut = h('p', { class: 'hint' }, ['']);
      var cancelBtn = h('button', {
        class: 'danger',
        onclick: function () {
          // empty object matters! api() only sends content-type with a body and /_api refuses a post without one
          api('POST', '/rules/warm/cancel', {}).then(function (r) { show(r.job); }).catch(function (e) { alert(e.message); });
        }
      }, ['Stop']);
      cancelBtn.style.display = 'none';

      function show(j) {
        if (!j) return;
        cancelBtn.style.display = j.running ? '' : 'none';
        if (j.running) {
          warmOut.textContent = 'Caching ' + (j.current || '') + ' - rule ' + j.done + ' of ' + j.total +
            '. ' + j.cached + ' downloaded, ' + j.already + ' already on disk, ' + j.failed + ' failed.';
        } else if (j.finishedAt) {
          warmOut.textContent = 'Finished. ' + j.cached + ' downloaded, ' + j.already + ' already on disk, ' +
            j.failed + ' failed.' +
            (j.notes.length ? ' ' + j.notes.slice(0, 3).join(' ') : '') +
            (j.errors.length ? ' First error: ' + j.errors[0] : '');
        }
      }

      function poll() {
        if (!warmOut.isConnected) return;             // page moved on, bail
        api('GET', '/rules/warm').then(function (r) {
          show(r.job);
          if (r.job && r.job.running) setTimeout(poll, 2000);
        }).catch(function () {});
      }

      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Cache the ticked rules']),
        h('p', { class: 'hint' }, [
          'Downloads the versions a rule pins to local disk now, so they can still be served ' +
          'with the upstream registry switched off. Allow rules with an exact name and exact ' +
          'versions only: a rule pinning 4.1.12 caches 4.1.12 and nothing else. For PyPI that means ' +
          'every file of the release (each platform wheel and the source archive), since there is no ' +
          'telling which one a machine will ask for, so big projects like numpy take a while. For an image it is ' +
          'the manifest, every platform image of it and all their layers, for each tag or digest the rule names. A rule for any ' +
          'version caches the current release (the latest tag, or the newest stable PyPI release), and a range like ^4.0.0 caches ' +
          'the newest version it allows. The rule itself stays as it is. An image rule with a tag pattern like 1.27.* is skipped, ' +
          'name the tags instead. Anything not cached is still fetched on demand while the upstream is reachable.'
        ]),
        h('div', null, [
          h('button', {
            onclick: function () {
              var ids = Object.keys(selected).map(Number);
              if (!ids.length) return alert('Tick a few rules first.');
              if (!confirm('Download the approved versions of ' + ids.length + ' rule(s) to disk?')) return;
              api('POST', '/rules/warm', { ids: ids })
                .then(function (r) {
                  if (r.skipped && r.skipped.length) {
                    alert('Started on ' + r.started + '. Skipped ' + r.skipped.length + ':\n\n' +
                      r.skipped.slice(0, 10).map(function (s) { return s.pattern + ': ' + s.error; }).join('\n'));
                  }
                  show(r.job);
                  poll();
                })
                .catch(function (e) { alert(e.message); });
            }
          }, ['Cache now']),
          cancelBtn
        ]),
        warmOut
      ]));

      poll();   //a job might already be running in another tab
    }

    body.appendChild(pager(d.page, d.total, d.limit, function (p) { rulesPage = p; route(); }));

    var sizePick = h('select', null, [50, 100, 500, 1000].map(function (n) {
      return h('option', { value: String(n), selected: rulesLimit === n }, [n + ' per page']);
    }));
    sizePick.addEventListener('change', function () {
      rulesLimit = parseInt(sizePick.value, 10);
      rulesPage = 1;
      route();
    });
    body.appendChild(h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Rows']), sizePick])]));
  });
}

// range hints written the way each ecosystem's own client writes them
var RULE_HELP = {
  npm: {
    pattern: 'lodash, @acme/*, eslint-plugin-*',
    range: 'any version. or 1.1.1, or 1.2.*',
    paste: 'one package name per line',
    lead: 'Leave the version range empty and the rule covers every version. Fill it in and the rule only ' +
      'covers the versions that match, so the rest are not even offered to npm. It takes anything npm ' +
      'itself understands:',
    facts: [
      ['1.1.1', 'that one version and nothing else'],
      ['1.2.*', 'any 1.2 patch, so 1.2.0 through 1.2.99, but not 1.3.0'],
      ['1.x', 'anything in the 1 series'],
      ['^1.2.0', '1.2.0 and up, staying on major 1'],
      ['~1.2.0', '1.2.0 and up, staying on minor 1.2'],
      ['>=4.17.21', 'that version or newer, no upper limit'],
      ['1.2.3 || 1.4.5', 'either of two exact versions']
    ],
    names: ''
  },
  pypi: {
    pattern: 'requests, django-*, zope.*',
    range: 'any version. or 2.31.0, or >=2.31,<3',
    paste: 'one project name per line',
    lead: 'Leave the version range empty and the rule covers every release. Fill it in and the rule only ' +
      'covers the releases that match, so the rest are not even offered to pip. It takes the version ' +
      'specifiers pip itself understands, with || between alternatives:',
    facts: [
      ['2.31.0', 'that one release and nothing else'],
      ['==2.31.*', 'any 2.31 release, so 2.31.0 through 2.31.99, but not 2.32'],
      ['~=2.31.0', '2.31.0 and up, staying on 2.31'],
      ['>=2.31,<3', '2.31 and up, staying below 3'],
      ['>=2.31', 'that release or newer, no upper limit'],
      ['>=2.31,!=2.32.1', 'the same, leaving out one bad release'],
      ['2.31.0 || 2.32.3', 'either of two exact releases']
    ],
    names: 'Names are matched the way pip matches them, so Flask, flask and FLASK are one rule, and so are ' +
      'zope.interface and zope-interface. The rule is saved under the normalized name.'
  },
  oci: {
    pattern: 'nginx, bitnami/redis, acme/*',
    range: 'every tag. or latest, or 1.27.*',
    paste: 'one image name per line',
    lead: 'Leave the tags empty and the rule covers every tag of the image. Fill them in and the rule only covers ' +
      'those. A tag is a label someone can move, so a rule names tags and digests exactly, with a * where you want ' +
      'part of a tag to match anything, and || between them:',
    facts: [
      ['latest', 'whatever latest points at when someone pulls it'],
      ['1.27.3', 'that one tag'],
      ['1.27.*', 'any tag that starts with 1.27.'],
      ['sha256:...', 'one exact image, by its digest, however it is tagged'],
      ['latest || 1.27.*', 'either']
    ],
    names: 'An image the rule lets through by tag also lets through its layers and platform images. On Docker Hub, ' +
      'nginx and library/nginx are the same image and a rule on either covers both.'
  }
};

function ruleHelp(id) {
  return RULE_HELP[id] || RULE_HELP.npm;
}

function ruleForm(types, scopes) {
  scopes = scopes || { applications: [], environments: [] };
  var type = ecoSelect(types);
  var appPick = scopePick(scopes.applications, '', 'every application');
  var envPick = scopePick(scopes.environments, '', 'every environment');
  var bulkApp = scopePick(scopes.applications, '', 'every application');
  var bulkEnv = scopePick(scopes.environments, '', 'every environment');
  var hasScopes = scopes.applications.length || scopes.environments.length;
  var pattern = h('input', { type: 'text' });
  var kind = h('select', null, [h('option', { value: 'allow' }, ['allow']), h('option', { value: 'deny' }, ['deny'])]);
  var range = h('input', { type: 'text' });
  var note = h('input', { type: 'text', placeholder: 'why' });
  var priority = h('input', { type: 'number', value: '0' });
  var names = h('p', { class: 'hint' }, ['']);
  var lead = h('p', { class: 'hint' }, ['']);
  var facts = h('dl', { class: 'facts' }, []);

  var bulkType = ecoSelect(types);
  var bulk = h('textarea', {});
  var bulkKind = h('select', null, [h('option', { value: 'allow' }, ['allow']), h('option', { value: 'deny' }, ['deny'])]);
  var bulkNames = h('p', { class: 'hint' }, ['']);

  function chosen(select) {
    return select ? select.value : 'npm';
  }

  function describe() {
    var help = ruleHelp(chosen(type));
    pattern.placeholder = help.pattern;
    range.placeholder = help.range;
    lead.textContent = help.lead;
    clear(facts);
    help.facts.forEach(function (f) {
      facts.appendChild(h('dt', null, [f[0]]));
      facts.appendChild(h('dd', null, [f[1]]));
    });
    names.textContent = help.names;
    names.style.display = help.names ? '' : 'none';
  }

  function describeBulk() {
    var help = ruleHelp(chosen(bulkType));
    bulk.placeholder = help.paste;
    bulkNames.textContent = help.names;
    bulkNames.style.display = help.names ? '' : 'none';
  }

  if (type) type.addEventListener('change', describe);
  if (bulkType) bulkType.addEventListener('change', describeBulk);
  describe();
  describeBulk();

  return h('div', null, [
    h('fieldset', null, [
      h('legend', null, ['Add a rule']),
      h('div', { class: 'row' }, [
        type ? h('div', null, [h('label', null, ['Type']), type]) : null,
        h('div', null, [h('label', null, ['Pattern']), pattern]),
        h('div', null, [h('label', null, ['Kind']), kind]),
        h('div', null, [h('label', null, ['Version range']), range]),
        h('div', null, [h('label', null, ['Priority']), priority])
      ]),
      hasScopes ? h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Only for application']), appPick]),
        h('div', null, [h('label', null, ['Only in environment']), envPick])
      ]) : null,
      hasScopes ? h('p', { class: 'hint' }, [
        'Leave both on every to cover everyone. Pick one to make the rule apply only to tokens for that application or environment, ' +
        'where it beats a rule for everyone. Requests with no token only ever get the rules for everyone.'
      ]) : null,
      h('label', null, ['Note']), note,
      names,
      lead,
      facts,
      h('p', { class: 'hint' }, [
        'A deny with a range only blocks those versions, the rest of the package still comes through. ' +
        'That is how you retire a bad release without banning the package.'
      ]),
      h('button', {
        onclick: function () {
          api('POST', '/rules', {
            ecosystem: chosen(type),
            pattern: pattern.value.trim(),
            kind: kind.value,
            version_range: range.value.trim(),
            note: note.value.trim(),
            priority: priority.value,
            application_id: appPick.value,
            environment_id: envPick.value
          }).then(route).catch(function (e) { alert(e.message); });
        }
      }, ['Save rule'])
    ]),
    h('fieldset', null, [
      h('legend', null, ['Paste a list']),
      bulkType ? h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Type']), bulkType])]) : null,
      h('label', null, ['Package names, one per line']), bulk,
      bulkNames,
      h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Add them as']), bulkKind]),
        hasScopes ? h('div', null, [h('label', null, ['Only for application']), bulkApp]) : null,
        hasScopes ? h('div', null, [h('label', null, ['Only in environment']), bulkEnv]) : null
      ]),
      h('button', {
        onclick: function () {
          api('POST', '/rules/bulk', { ecosystem: chosen(bulkType), patterns: bulk.value, kind: bulkKind.value, note: 'bulk added', application_id: bulkApp.value, environment_id: bulkEnv.value })
            .then(function (d) {
              if (d.skipped && d.skipped.length) {
                alert('Added ' + d.added + '. Skipped ' + d.skipped.length + ':\n\n' +
                  d.skipped.slice(0, 10).map(function (x) { return x.line + ': ' + x.error; }).join('\n'));
              }
              route();
            })
            .catch(function (e) { alert(e.message); });
        }
      }, ['Add them all'])
    ])
  ]);
}

export { scopeLabel, scopeLists, scopePick, viewRules };
