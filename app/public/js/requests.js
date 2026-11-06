// ForgeRepo portal: requests.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { can, clear, modal, notice, pager, table, untilCell, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { ecoHints, ecoName, ecoPkg, ecoSelect } from './ecosystems.js';
import { runResolve } from './review.js';
import { route } from './routing.js';
import { expiryPick } from './rules.js';

var requestsPage = 1;
var requestsStatus = 'pending';

// who to get back to: account, then token, then just the address
function askedBy(r) {
  var who = r.requested_by_user || r.requested_by ||
    (r.source === 'blocked-install' ? 'a blocked install' : r.source === 'learning' ? 'learning mode' : 'unknown');
  var kids = [h('div', null, [who])];
  var under = [];

  if (r.owner_name) under.push(h('span', null, [r.owner_name]));
  if (r.owner_email) under.push(h('a', { href: 'mailto:' + r.owner_email }, [r.owner_email]));
  if (r.token_name) under.push(h('span', null, ['token ', h('span', { class: 'mono' }, [r.token_name])]));
  if (!r.requested_by_user && !r.token_name && r.ip) under.push(h('span', { class: 'mono' }, [r.ip]));

  under.forEach(function (bit) {
    kids.push(h('div', { class: 'muted' }, [bit]));
  });
  return h('div', null, kids);
}

// Separate call since it goes out to osv, the list should show up regardless
// vulnerable gets filled with the ids that came back with findings, for Select vulnerable
function fillVulns(requests, cells, vulnerable) {
  var ids = requests.map(function (r) { return r.id; });
  if (!ids.length) return;

  function say(cell, cls, text, title) {
    if (!cell) return;
    clear(cell);
    cell.className = cls || '';
    if (title) cell.setAttribute('title', title); else cell.removeAttribute('title');
    cell.appendChild(document.createTextNode(text));
  }

  api('GET', '/requests/vulnerabilities?ids=' + ids.join(','))
    .then(function (d) {
      if (vulnerable) vulnerable.loaded = true;
      ids.forEach(function (id) {
        var cell = cells[id];
        var v = d.results[id];
        if (vulnerable && v && v.findings && v.findings.length) vulnerable.ids[id] = true;
        if (!v) return say(cell, 'muted', 'not checked');
        if (v.error) return say(cell, 'muted', 'could not check', v.error);
        if (v.note) return say(cell, 'muted', 'scanned when pulled', v.note);
        if (!v.checked) return say(cell, 'muted', 'no version matches that range');

        // how much got looked at, so a sample never pretends it covered everything
        var scope = v.matched > v.checked
          ? 'the newest ' + v.checked + ' of ' + v.matched + ' versions that match were checked'
          : (v.checked === 1 ? 'the one version that matches was checked' : 'all ' + v.checked + ' matching versions were checked');
        var notes = v.partial
          ? 'the advisory feed did not answer about all of them, so this is what was already known and not a full answer'
          : '';

        // nothing found + feed answered = clean. feed never answering is NOT that
        if (!v.findings.length) {
          if (v.partial) return say(cell, 'muted', 'could not check', notes);
          return say(cell, 'allow', 'No Known Vulnerabilities', scope);
        }

        var detail = v.findings.map(function (f) {
          return f.version + ': ' + f.severity + (f.cves ? ' ' + f.cves : '') +
            (f.fixed_in ? ', fixed in ' + f.fixed_in : ', no fix published') +
            (f.summary ? ' - ' + f.summary : '');
        }).join('\n');

        say(cell, v.worst === 'critical' || v.worst === 'high' ? 'deny' : null,
          v.findings.length + ' of ' + v.checked + ' affected, worst ' + v.worst,
          scope + '\n\n' + detail + (notes ? '\n\n' + notes : ''));
      });
    })
    .catch(function (err) {
      ids.forEach(function (id) { say(cells[id], 'muted', 'could not check', err.message); });
    });
}

function viewRequests(body) {
  var types = state.ecosystems || [];
  var typeName = ecoName;
  var query = '?page=' + requestsPage + '&limit=50' + (requestsStatus ? '&status=' + requestsStatus : '');
  return api('GET', '/requests' + query).then(function (d) {
    section(body, 'Package requests',
      d.canDecide
        ? 'Anything a developer asks for lands here, along with anything an install got blocked on.'
        : 'Ask for a package and someone with approval rights will take a look.');

    if (can('requests:create')) body.appendChild(requestForm(types));

    var tabs = h('div', { class: 'pager' }, []);
    ['pending', 'approved', 'blocked', 'rejected', 'withdrawn', ''].forEach(function (s) {
      tabs.appendChild(link(s || 'everything', function () {
        requestsStatus = s;
        requestsPage = 1;
        route();
      }, requestsStatus === s ? 'on' : null));
    });
    body.appendChild(tabs);

    var selected = {};
    var rowStatus = {};
    var boxes = [];
    var selectAll = h('input', { type: 'checkbox', title: 'select everything on this page' });
    var counters = [];
    var vulnerable = { loaded: false, ids: {} };

    function retally() {
      var n = Object.keys(selected).length;
      counters.forEach(function (c) { c.textContent = n ? n + ' selected' : 'none selected'; });
    }
    selectAll.addEventListener('change', function () {
      boxes.forEach(function (b) {
        if (b.disabled) return;
        b.checked = selectAll.checked;
        if (selectAll.checked) selected[b.value] = true; else delete selected[b.value];
      });
      retally();
    });

    // filled in when the feed answers, the list doesn't wait around
    var vulnCells = {};

    // a request from before PyPI got switched off still says it was a PyPI one
    var showType = types.length > 1 || d.requests.some(function (r) { return r.ecosystem && r.ecosystem !== 'npm'; });
    var requestCols = [{ label: selectAll }, 'Package', 'Versions', 'Vulnerabilities', 'Asked by', 'Why', 'Status', 'Expires', 'When', 'Actions'];
    body.appendChild(table(
      requestCols,
      d.requests.map(function (r) {
        var tick = h('input', { type: 'checkbox', value: String(r.id) });
        if (!d.canDecide) tick.setAttribute('disabled', 'disabled');
        rowStatus[r.id] = r.status;
        tick.addEventListener('change', function () {
          if (tick.checked) selected[r.id] = true; else delete selected[r.id];
          retally();
        });
        boxes.push(tick);

        var actions = h('span', { class: 'actions' }, []);
        if (r.status === 'pending' && d.canDecide) {
          actions.appendChild(link('approve', function () { decide(r, 'approve'); }, 'allow'));
          actions.appendChild(link('block', function () { decide(r, 'block'); }, 'deny'));
          actions.appendChild(link('clear', function () { decide(r, 'clear'); }));
        }
        if (r.status === 'pending' && r.user_id === state.me.id) {
          actions.appendChild(link('withdraw', function () {
            api('POST', '/requests/' + r.id + '/withdraw', {}).then(route).catch(function (e) { alert(e.message); });
          }));
        }
        if (can('tools:resolve')) {
          actions.appendChild(link('check deps', function () {
            window.location.hash = '#tools';
            var eco = r.ecosystem || 'npm';
            //a PyPI request pinned with == walks from that release
            var from = eco === 'pypi' ? String(r.version_range || '').replace(/^==\s*/, '') : r.version_range;
            setTimeout(function () {
              runResolve(r.package_name, eco === 'pypi' && r.version_range && !/[<>=!~,|]/.test(from)
                ? '==' + from : (r.version_range || 'latest'), undefined, undefined, eco);
            }, 60);
          }));
        }
        var cell = h('span', { class: 'muted' }, ['checking...']);
        vulnCells[r.id] = cell;

        var cells = [
          tick,
          ecoPkg(r.ecosystem || 'npm', r.package_name),
          r.version_range || 'any',
          cell,
          askedBy(r),
          r.reason || '',
          statusCell(r),
          expiresCell(r),
          when(r.created_at),
          actions
        ];
        return cells;
      })
    ));

    fillVulns(d.requests, vulnCells, vulnerable);

    var listTable = body.lastChild;

    function tickOnly(pick) {
      boxes.forEach(function (b) {
        if (b.disabled) return;
        b.checked = !!pick[b.value];
        if (b.checked) selected[b.value] = true; else delete selected[b.value];
      });
      selectAll.checked = false;
      retally();
    }

    function editSelected() {
      var ids = Object.keys(selected).map(Number);
      if (!ids.length) return alert('Tick a few requests first.');
      var notApproved = ids.filter(function (id) { return rowStatus[id] !== 'approved' && rowStatus[id] !== 'blocked'; });
      var blocked = ids.filter(function (id) { return rowStatus[id] === 'blocked'; });
      var expires = expiryPick(null);
      var also = h('input', { type: 'checkbox' });
      var note = h('input', { type: 'text', placeholder: 'why, goes on the ones approved here' });
      var out = h('div', null, []);
      var box;
      var save = h('button', {
        type: 'button',
        onclick: function () {
          clear(out);
          api('POST', '/requests/bulk-edit', { ids: ids, expires_at: expires.value(), approve_others: also.checked, note: note.value.trim() })
            .then(function (res) {
              selected = {};
              var msg = (res.edited ? res.edited + ' approved request(s) updated. ' : '') +
                (res.approved ? res.approved + ' approved now. ' : '');
              if (res.skipped && res.skipped.length) {
                alert((msg || 'Nothing changed. ') + 'Left alone ' + res.skipped.length + ':\n\n' +
                  res.skipped.slice(0, 15).map(function (x) { return (x.name || x.id) + ' ' + x.error; }).join('\n'));
              }
              box.close();
              route();
            })
            .catch(function (e) { out.appendChild(notice(e.message, 'err')); });
        }
      }, ['Save']);
      box = modal('Edit ' + ids.length + ' request(s)', h('div', null, [
        h('p', { class: 'hint' }, [
          'Sets when the allow rule each approved request wrote runs out. Leave it empty, or pick never, to make them ' +
          'permanent again. Once it passes the package is blocked and its cached copies are removed.'
        ]),
        expires.el,
        notApproved.length ? h('div', null, [
          h('label', null, [also, ' Also approve the ' + notApproved.length + ' ticked request(s) that are not approved yet, with this expiry']),
          h('label', null, ['Note']), note
        ]) : null,
        blocked.length ? h('p', { class: 'hint' }, [
          blocked.length + ' ticked request(s) are blocked by a deny rule and are left alone. Take the deny off on the Rules page first.'
        ]) : null,
        out,
        h('div', null, [save, h('button', { type: 'button', onclick: function () { box.close(); } }, ['Cancel'])])
      ]));
    }

    function approveSelected() {
      var ids = Object.keys(selected).map(Number).filter(function (id) {
        return rowStatus[id] === 'pending';
      });
      if (!ids.length) {
        return alert(Object.keys(selected).length
          ? 'None of the ticked requests are still pending. Use Edit selected to approve a rejected or withdrawn one with an expiry.'
          : 'Tick a few requests first.');
      }
      if (!confirm('Approve ' + ids.length + ' request(s)?\n\n' +
        'An allow rule is written for each package, for the versions it asked for.')) return;
      var note = prompt('Any note to go with approving these ' + ids.length + '? It goes on all of them.', '');
      if (note === null) return;
      api('POST', '/requests/bulk-approve', { ids: ids, note: note, add_rule: true })
        .then(function (res) {
          selected = {};
          if (res.skipped && res.skipped.length) {
            alert('Approved ' + res.affected + '. Left alone ' + res.skipped.length + ':\n\n' +
              res.skipped.slice(0, 10).map(function (x) {
                return (x.name || x.id) + ': ' + x.error;
              }).join('\n'));
          }
          route();
        })
        .catch(function (e) { alert(e.message); });
    }

    function clearSelected() {
      var ids = Object.keys(selected).map(Number);
      if (!ids.length) return alert('Tick a few requests first.');
      if (!confirm('Clear ' + ids.length + ' request(s)? No rules are written and nothing is decided.')) return;
      api('POST', '/requests/bulk-clear', { ids: ids })
        .then(function (res) {
          selected = {};
          if (res.cleared !== ids.length) alert('Cleared ' + res.cleared + ' of ' + ids.length + '.');
          route();
        })
        .catch(function (e) { alert(e.message); });
    }

    // the same bar above and below the list, a long page shouldn't mean scrolling to act
    function actionBar() {
      var counter = h('span', { class: 'muted' }, ['none selected']);
      counters.push(counter);
      return h('div', { class: 'row' }, [
        counter,
        h('button', { type: 'button', onclick: approveSelected }, ['Approve selected']),
        can('rules:write') ? h('button', { type: 'button', onclick: editSelected }, ['Edit selected']) : null,
        h('button', { type: 'button', onclick: clearSelected }, ['Clear selected']),
        h('button', {
          type: 'button',
          title: 'tick every request on this page with a known advisory',
          onclick: function () {
            if (!vulnerable.loaded) return alert('Still checking the advisories, give it a moment.');
            if (!Object.keys(vulnerable.ids).length) return alert('Nothing on this page has a known advisory.');
            tickOnly(vulnerable.ids);
          }
        }, ['Select vulnerable']),
        h('button', { type: 'button', onclick: function () { tickOnly({}); } }, ['Select none'])
      ]);
    }

    if (d.canDecide && d.requests.length) {
      body.insertBefore(actionBar(), listTable);
      body.appendChild(actionBar());
      body.appendChild(h('fieldset', null, [
        h('legend', null, ['The ticked requests']),
        h('p', { class: 'hint' }, [
          'Approving writes the allow rule for each one, exactly as approving them one at a time ' +
          'does, and the note goes on all of them. Only the pending ones are touched: anything ' +
          'somebody has already settled is left as it is and named back to you.'
        ]),
        h('p', { class: 'hint' }, [
          'Clearing decides nothing. It writes no rule and changes nothing about what the registry ' +
          'serves, it just takes the row off the list. For typos, packages somebody stopped needing, ' +
          'and noise from an install that has since been fixed.'
        ]),
        h('p', { class: 'hint' }, [
          'It is not a way to silence a package. If the same install is blocked again a fresh request ' +
          'appears, because there is no longer a row for it to be folded into.'
        ]),
        h('p', { class: 'hint' }, [
          'Edit sets an expiry on what approved requests allowed, for a time boxed exception. Select vulnerable ' +
          'ticks the ones with a known advisory, so you can give just those a few days. It can also approve ' +
          'a rejected or withdrawn request with an expiry, when you tick that in the box.'
        ])
      ]));
    }

    body.appendChild(pager(d.page, d.total, d.limit, function (p) { requestsPage = p; route(); }));
  });
}

// approve = allow rule, block = deny rule, clear just settles the row
// the status, and what auto approve made of it when it looked
var AUTO_WORDS = { checking: 'being scanned and checked now', waiting: 'checking, will look again', clear: 'checked', flagged: 'needs a person', approved: 'auto approved' };
var AUTO_CLASS = { clear: 'allow', flagged: 'deny', approved: 'allow' };
// approved only. what the approval's allow rule says about running out
function expiresCell(r) {
  if (r.status !== 'approved') return '';
  if (r.rule_state === 'missing') return h('span', { class: 'muted', title: 'the allow rule this approval wrote is gone' }, ['no rule']);
  if (r.rule_state === 'several') return h('span', { class: 'muted', title: 'the package has several allow rules, see the Rules page' }, ['see rules']);
  return untilCell(r.expires_ts);
}

function statusCell(r) {
  var text = r.status + (r.hits > 1 ? ' (asked ' + r.hits + ' times)' : '');
  if (!r.auto_state) return text;
  return h('span', null, [text, h('div', { class: 'hint' }, [
    h('span', { class: AUTO_CLASS[r.auto_state] || 'muted' }, [AUTO_WORDS[r.auto_state] || r.auto_state]),
    r.auto_note && r.auto_state !== 'approved' ? ': ' + r.auto_note : ''
  ])]);
}

function decide(request, action) {
  // npm writes lodash@^4.17.0; a PyPI range already brings its own operator
  var target = request.package_name + (request.version_range
    ? ((request.ecosystem || 'npm') === 'npm' ? '@' + request.version_range : ' ' + request.version_range)
    : '');
  var note;

  if (action === 'block') {
    if (!confirm('Block ' + target + '?\n\n' +
      'This writes a deny rule at priority 1000, so it beats the whitelist. ' +
      (request.version_range
        ? 'Only the versions named above are blocked.'
        : 'No version range was asked for, so the whole package is blocked.'))) return;
    note = prompt('Why is ' + target + ' being blocked? This goes in the rule note.', '');
    if (note === null) return;
    if (!note.trim()) return alert('A block needs a reason. It ends up in the rule and outlives you remembering.');
  } else if (action === 'clear') {
    if (!confirm('Clear ' + target + '?\n\n' +
      'No rule is written and nothing is decided, the row just comes off the list. ' +
      'If the same install is blocked again a fresh request appears.')) return;
    note = '';
  } else {
    return approveWithTree(request, target);
  }

  api('POST', '/requests/' + request.id + '/' + action, { note: note, add_rule: true })
    .then(route)
    .catch(function (e) { alert(e.message); });
}

function treeLines(target, d) {
  if (d.error) return 'The dependency tree could not be walked (' + d.error + '), so what it brings in is not known.';
  if (d.image) {
    var i = d.summary;
    return target + ' is ' + i.platforms + ' platform image' + (i.platforms === 1 ? '' : 's') + ' with ' + i.layers + ' layer' + (i.layers === 1 ? '' : 's') + '.\n' +
      (i.scanned ? '  ' + i.packages + ' packages found inside, ' + i.vulnerable + ' with a known advisory' : '  not scanned yet, the packages inside are not known');
  }
  var s = d.summary;
  if (!s.total) return target + ' brings in nothing else.';
  return target + ' brings in ' + s.total + ' package(s): ' + s.direct + ' direct, ' + s.transitive + ' transitive.\n' +
    '  ' + s.blocked + ' blocked right now\n' +
    '  ' + s.vulnerable + ' with a known advisory\n' +
    '  ' + s.unapproved + ' no rule approves yet\n' +
    '  ' + s.unknown + ' never seen on this registry' +
    (d.truncated ? '\nThe tree was cut short, it is a big one.' : '');
}

// approving says what comes along with it first. a walk that fails still gets said, it just can't count
function approveWithTree(request, target) {
  api('GET', '/requests/' + request.id + '/dependencies')
    .catch(function (e) { return { error: e.message }; })
    .then(function (d) {
      var note = prompt(treeLines(target, d) + '\n\nAny note to go with approving ' + target + '?', '');
      if (note === null) return;
      var withDeps = false;
      if (!d.error && d.approveClean && d.summary.approvable) {
        withDeps = confirm('Also approve the ' + d.summary.approvable + ' of them no rule approves yet and nothing is known against?\n\n' +
          'Each gets an allow rule pinned to the version the tree resolved, after the advisory feed is asked about it again. ' +
          'Blocked, vulnerable, held and killed ones are never approved this way.');
      }
      api('POST', '/requests/' + request.id + '/approve', { note: note, add_rule: true, with_dependencies: withDeps })
        .then(function (r) {
          var dep = r.dependencies;
          if (dep) {
            alert(dep.error || ('Approved ' + dep.approved + ' dependenc' + (dep.approved === 1 ? 'y' : 'ies') + ' as well.' +
              (dep.leftOut ? ' ' + dep.leftOut + ' were left for someone to look at.' : '') + (dep.note ? '\n\n' + dep.note : '')));
          }
          route();
        })
        .catch(function (e) { alert(e.message); });
    });
}

function requestForm(types) {
  var type = ecoSelect(types || []);
  var name = h('input', { type: 'text', placeholder: 'package name' });
  var range = h('input', { type: 'text', placeholder: 'optional version range' });
  var why = h('input', { type: 'text', placeholder: 'what you need it for' });
  if (type) {
    type.addEventListener('change', function () {
      var eco = ecoHints(type.value);
      name.placeholder = type.value === 'npm' ? 'package name' : type.value === 'oci' ? 'image, like ' + eco.example : 'name, like ' + eco.example;
      range.placeholder = eco.range;
    });
  }
  return h('fieldset', null, [
    h('legend', null, ['Ask for a package']),
    h('div', { class: 'row' }, [
      type ? h('div', null, [h('label', null, ['Type']), type]) : null,
      h('div', null, [h('label', null, ['Package']), name]),
      h('div', null, [h('label', null, ['Versions']), range])
    ]),
    h('label', null, ['Reason']), why,
    h('button', {
      onclick: function () {
        api('POST', '/requests', {
          ecosystem: type ? type.value : 'npm',
          package_name: name.value.trim(),
          version_range: range.value.trim(),
          reason: why.value.trim()
        }).then(function (d) {
          if (d.note) alert(d.note);
          route();
        }).catch(function (e) { alert(e.message); });
      }
    }, ['Send it'])
  ]);
}

export { viewRequests };
