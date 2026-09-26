// ForgeRepo portal: reviewing a file.
// Author: Tim Rice

import { state } from './state.js';
import { ecoPkg } from './ecosystems.js';
import { h, link } from './dom.js';
import { can, clear, notice, pager, table } from './ui.js';
import { api, downloadPost } from './api.js';
import { resolveImage } from './image-tree.js';

// last review result, for the export and list buttons. tossed on the next review
var reviewState = null;

function statusCell(f) {
  var cls = f.status === 'BLOCKED' ? 'deny' : (f.status === 'WHITELISTED' ? 'allow' : 'warn');
  var label = f.status === 'NOT_IDENTIFIED' ? 'needs review' : f.status.toLowerCase();
  if (f.whitelisted_but_vulnerable) { label = 'whitelisted, vulnerable'; cls = 'deny'; }
  else if (f.at_risk) { label = 'at risk'; cls = 'deny'; }
  else if (f.name_known_version_drift) { label = 'unapproved version'; }
  return h('span', { class: cls }, [label]);
}

function advisoryCell(f) {
  var a = f.known_advisory;
  if (!a) {
    return f.version_is_pinned
      ? h('span', { class: 'muted' }, ['none'])
      : h('span', { class: 'muted' }, ['not pinned']);
  }
  var bad = a.severity === 'CRITICAL' || a.severity === 'HIGH';
  return h('span', { class: bad ? 'deny' : 'warn', title: a.summary || '' },
    [String(a.severity).toLowerCase() + (a.cves ? ' ' + a.cves.split(', ')[0] : '') +
      (a.fixed_in ? ', fixed in ' + a.fixed_in : '')]);
}

function reviewFileSection(body) {
  var file = h('input', { type: 'file', accept: '.json,.jsonc,.csv,.tsv,.txt,.in,.lock,.yaml,.yml,.toml,.xml,.cdx,.zip,application/json,text/csv,text/plain,application/xml,text/xml,application/zip' });
  var out = h('div', null, []);
  var pin = h('input', { type: 'checkbox', checked: 'checked' });

  var box = h('fieldset', null, [
    h('legend', null, ['Review a file']),
    h('p', { class: 'hint' }, [
      'Takes a package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml; a requirements file, ' +
      'poetry.lock, uv.lock, pylock.toml or Pipfile.lock; a composer.json or composer.lock; a CycloneDX SBOM (JSON or XML) or an SPDX one; a software ' +
      'inventory another tool exported, as CSV or JSON; a plain list of names and versions; or a zip holding any number ' +
      'of them, and says ' +
      'what the rules make of every package inside. The versions it pins are then checked ' +
      'against the advisory feed before the report is drawn, so the answer is what is known ' +
      'about them now rather than what the last scan happened to cover.'
    ]),
    h('p', { class: 'hint' }, [
      'A list can be csv, tab separated, or columns lined up with spaces, with or without a ' +
      'package and version header. An ecosystem column (npm, pypi, nuget, maven, gem, cocoapods, swift, composer) or a purl ' +
      'column says which type each row is, and without one every row is taken as npm. A package listed once per ' +
      'repository is read once. Anything on a line that is not a name and a version is ' +
      'counted and reported rather than quietly skipped.'
    ]),
    h('p', { class: 'hint' }, [
      'A bill of materials usually describes a whole estate, so the parts of it that are not ' +
      'dependencies, like the repositories it searched, and packages of a type this registry has no rules for, ' +
      'are counted and left out. Each package is judged by its own type\'s rules: npm by the npm rules, NuGet ' +
      'by the NuGet rules and so on, never the other way round, and every row says its type next to the name. ' +
      'A type that is switched off on this box is left out, and the notes say so.'
    ]),
    h('p', { class: 'hint' }, [
      'The file is read in memory and nothing is unpacked to disk, so there is nothing left ' +
      'behind on this box afterward. The report lives in this page until you review another ' +
      'file or navigate away.'
    ]),
    file,
    h('div', null, [
      h('button', {
        type: 'button',
        onclick: function () { runReview(file, out, pin); }
      }, ['Review it'])
    ])
  ]);
  body.appendChild(box);
  body.appendChild(out);
}

function runReview(file, out, pin) {
  var f = file.files && file.files[0];
  if (!f) return alert('Pick a file first.');
  var maxMB = state.maxImportMB || 64;
  if (f.size > maxMB * 1024 * 1024) {
    return alert('That file is ' + (f.size / 1048576).toFixed(1) + 'MB and the limit is ' + maxMB + 'MB.');
  }

  clear(out);
  out.appendChild(h('p', { class: 'muted' }, [
    'Reading ' + f.name + ' and checking it against the rules and the advisory feed. ' +
    'A big lockfile takes a moment.'
  ]));

  var reader = new FileReader();
  reader.onerror = function () {
    clear(out);
    out.appendChild(notice('That file could not be read.', 'err'));
  };
  reader.onload = function () {
    // a zip is bytes so it goes up as base64; a manifest is text and goes as is
    var bytes = new Uint8Array(reader.result);
    var isZip = bytes.length > 1 && bytes[0] === 0x50 && bytes[1] === 0x4b;
    var payload = { filename: f.name };

    if (isZip) {
      var chunk = 0x2000;
      var parts = [];
      for (var i = 0; i < bytes.length; i += chunk) {
        parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + chunk)));
      }
      payload.encoding = 'base64';
      payload.data = btoa(parts.join(''));
    } else {
      payload.encoding = 'text';
      payload.data = new TextDecoder('utf-8').decode(bytes);
    }

    api('POST', '/tools/review', payload)
      .then(function (report) {
        reviewState = {
          payload: payload,
          report: report,
          pin: pin,
          // a new file starts at the top, re-running the same one keeps your filters
          view: { filter: 'all', size: 100, page: 1 }
        };
        renderReview(out, report, payload, pin, reviewState.view);
      })
      .catch(function (e) {
        clear(out);
        out.appendChild(notice(e.message, 'err'));
      });
  };
  reader.readAsArrayBuffer(f);
}

function renderReview(out, report, payload, pin, view) {
  var s = report.summary;
  view = view || { filter: 'all', size: 100, page: 1 };
  clear(out);

  out.appendChild(h('h3', null, ['Review of ' + report.input.name]));
  out.appendChild(notice(
    s.total_packages + ' package entr' + (s.total_packages === 1 ? 'y' : 'ies') + ' across ' +
    s.files_scanned + ' file' + (s.files_scanned === 1 ? '' : 's') + '. ' +
    s.blocked + ' blocked, ' + s.whitelisted + ' whitelisted, ' + s.not_identified + ' need a decision.',
    s.blocked || s.whitelisted_but_vulnerable || s.known_advisories ? 'err' : 'ok'
  ));

  var lines = [];
  if (s.known_advisories) {
    lines.push(s.known_advisories + ' pinned version(s) have a known advisory against them, ' +
      s.advisories_critical_or_high + ' of those critical or high. That is the advisory feed, not the rules: ' +
      'a package can be whitelisted here and still be one of these.');
  } else if (s.versions_checked_against_the_feed) {
    lines.push('None of the ' + s.versions_checked_against_the_feed +
      ' pinned version(s) has a known advisory against it.');
  }
  if (s.whitelisted_but_vulnerable) {
    lines.push(s.whitelisted_but_vulnerable + ' package(s) match a deny rule but are let through by an ' +
      'allow rule that wins on priority. Worth confirming that is on purpose.');
  }
  if (s.at_risk) {
    lines.push(s.at_risk + ' package(s) are at risk: the rules block other releases of them, and the ' +
      'version here has never been vetted either way' +
      (s.at_risk_no_approved_version ? ', and ' + s.at_risk_no_approved_version +
        ' of those have no approved version to move to at all' : '') + '.');
  }
  if (s.not_identified_name_known) {
    lines.push(s.not_identified_name_known + ' are an unapproved version of a package the rules know, ' +
      'and ' + s.not_identified_name_unknown + ' are packages no rule mentions.');
  }
  if (s.vulnerable_range_overlap) {
    lines.push(s.vulnerable_range_overlap + ' finding(s) come from a declared range that can resolve to a ' +
      'blocked version rather than a pinned one. npm may or may not install an affected release, so ' +
      'treat them as exposed until the version is pinned or raised.');
  }
  lines.forEach(function (line) { out.appendChild(h('p', { class: 'hint' }, [line])); });

  (report.notes || []).forEach(function (n) {
    out.appendChild(h('p', { class: 'hint warn' }, [n]));
  });
  (report.files_skipped || []).slice(0, 5).forEach(function (x) {
    out.appendChild(h('p', { class: 'hint muted' }, [x.file + ' - ' + x.reason]));
  });
  (report.files_unreadable || []).slice(0, 5).forEach(function (x) {
    out.appendChild(h('p', { class: 'hint warn' }, [x.file + ' - ' + x.reason]));
  });

  // ---- the list, with tick boxes for whoever can actually do something ----
  // approvers write rules, developers ask for packages, viewers read. Lockfiles review
  // into thousands of rows so it's paged here, ticks survive paging and export asks for the filter showing.
  var writable = can('rules:write');
  var canAsk = can('requests:create');
  var selectable = writable || canAsk;

  var VIEWS = [
    { key: 'all', label: 'Everything', match: function () { return true; } },
    { key: 'unapproved', label: 'Not whitelisted', match: function (f) { return f.status !== 'WHITELISTED'; } },
    { key: 'undecided', label: 'Needs a decision', match: function (f) { return f.status === 'NOT_IDENTIFIED'; } },
    { key: 'at_risk', label: 'At risk', match: function (f) { return f.at_risk; } },
    { key: 'drift', label: 'Unapproved version of a known package', match: function (f) { return f.name_known_version_drift; } },
    { key: 'vulnerable', label: 'Whitelisted but vulnerable', match: function (f) { return f.whitelisted_but_vulnerable; } },
    { key: 'advisory', label: 'Has an advisory', match: function (f) { return !!f.known_advisory; } },
    { key: 'blocked', label: 'Blacklisted', match: function (f) { return f.status === 'BLOCKED'; } }
  ];
  var SIZES = [100, 500, 1000];

  function viewFor(key) {
    for (var i = 0; i < VIEWS.length; i += 1) if (VIEWS[i].key === key) return VIEWS[i];
    return VIEWS[0];
  }

  // finding index -> finding, so ticks survive redraws and paging
  var selected = {};
  var counter = h('span', { class: 'muted' }, ['none selected']);
  var bulkCount = h('span', { class: 'muted' }, []);
  var listBox = h('div', null, []);
  var pagerBox = h('div', null, []);
  var bulkBox = h('p', { class: 'hint' }, []);
  var exportNote = h('p', { class: 'hint' }, []);

  function selectedItems() {
    return Object.keys(selected).map(function (k) { return selected[k]; });
  }

  function refreshCount() {
    var n = Object.keys(selected).length;
    var text = n ? n + ' selected' : 'none selected';
    counter.textContent = text;
    bulkCount.textContent = text + ', across the whole review.';
  }

  var filterSel = h('select', null, VIEWS.map(function (v) {
    var n = report.findings.filter(v.match).length;
    return h('option', { value: v.key }, [v.label + ' (' + n + ')']);
  }));
  filterSel.value = view.filter;
  filterSel.addEventListener('change', function () {
    view.filter = filterSel.value;
    view.page = 1;
    drawList();
  });

  var sizeSel = h('select', null, SIZES.map(function (n) {
    return h('option', { value: String(n) }, [n + ' at a time']);
  }));
  sizeSel.value = String(view.size);
  sizeSel.addEventListener('change', function () {
    view.size = Number(sizeSel.value);
    view.page = 1;
    drawList();
  });

  out.appendChild(h('div', { class: 'row' }, [
    h('div', null, [h('label', null, ['Show']), filterSel]),
    h('div', null, [h('label', null, ['Rows']), sizeSel])
  ]));
  out.appendChild(listBox);
  out.appendChild(pagerBox);
  out.appendChild(bulkBox);

  function drawList() {
    var match = viewFor(view.filter).match;
    var rows = [];
    for (var i = 0; i < report.findings.length; i += 1) {
      if (match(report.findings[i])) rows.push(i);
    }
    var tickableAll = rows.filter(function (idx) { return report.findings[idx].status !== 'BLOCKED'; });

    var pages = Math.max(1, Math.ceil(rows.length / view.size));
    if (view.page > pages) view.page = pages;
    if (view.page < 1) view.page = 1;
    var pageRows = rows.slice((view.page - 1) * view.size, view.page * view.size);

    var boxes = [];
    var selectAll = h('input', { type: 'checkbox', title: 'tick everything on this page' });
    selectAll.addEventListener('change', function () {
      boxes.forEach(function (b) {
        b.checked = selectAll.checked;
        if (selectAll.checked) selected[b.value] = report.findings[Number(b.value)];
        else delete selected[b.value];
      });
      refreshCount();
    });

    clear(listBox);
    listBox.appendChild(table(
      [{ label: selectable ? selectAll : '' }, 'Status', 'Package', 'Version', 'What that version means',
        'Advisory', 'Where', 'Why'],
      pageRows.map(function (idx) {
        var f = report.findings[idx];
        var tick = h('input', { type: 'checkbox', value: String(idx) });
        // no tick box for blocked, the server refuses to whitelist them anyway
        if (!selectable || f.status === 'BLOCKED') {
          tick.setAttribute('disabled', 'disabled');
          if (f.status === 'BLOCKED') {
            tick.setAttribute('title', 'blacklisted, and a blocked version is never whitelisted from here');
          }
        } else {
          tick.checked = !!selected[idx];
          boxes.push(tick);
        }
        tick.addEventListener('change', function () {
          if (tick.checked) selected[idx] = f;
          else delete selected[idx];
          refreshCount();
        });
        return [
          tick,
          statusCell(f),
          ecoPkg(f.ecosystem || 'npm', f.package),
          h('span', { class: 'mono' }, [f.declared_version]),
          f.declared_version_human,
          advisoryCell(f),
          f.source_file + ' (' + f.section + ')',
          f.detail
        ];
      })
    ));
    if (!boxes.length) selectAll.setAttribute('disabled', 'disabled');
    selectAll.checked = boxes.length > 0 && boxes.every(function (b) { return b.checked; });

    clear(pagerBox);
    pagerBox.appendChild(pager(view.page, rows.length, view.size, function (p) {
      view.page = p;
      drawList();
    }));

    clear(bulkBox);
    if (selectable && tickableAll.length) {
      bulkBox.appendChild(link('Tick all ' + tickableAll.length + ' on this list', function () {
        tickableAll.forEach(function (idx) { selected[idx] = report.findings[idx]; });
        drawList();
      }));
      bulkBox.appendChild(document.createTextNode(' · '));
      bulkBox.appendChild(link('Clear the ticks', function () {
        selected = {};
        drawList();
      }));
      bulkBox.appendChild(document.createTextNode(
        ' Ticks stay put when you turn the page or change the filter. '
      ));
      bulkBox.appendChild(bulkCount);
    }
    var blockedInView = rows.length - tickableAll.length;
    if (selectable && blockedInView) {
      bulkBox.appendChild(h('span', null, [
        ' The ' + blockedInView + ' blacklisted row(s) on this list cannot be ticked. A blocked ' +
        'version is never whitelisted from here: the deny rule and the note saying why somebody ' +
        'wrote it are on the ',
        link('Rules page', function () { window.location.hash = '#rules'; }),
        ', and that is where taking one off the blacklist belongs. They are still in the export.'
      ]));
    }

    exportNote.textContent = view.filter === 'all'
      ? 'Every one of the ' + report.findings.length + ' rows, whichever page you are on.'
      : 'The ' + rows.length + ' row(s) the filter is showing, not just this page. Set the filter ' +
        'back to everything for the whole review.';

    refreshCount();
  }

  if (can('rules:export')) {
    out.appendChild(h('fieldset', null, [
      h('legend', null, ['Export the results']),
      h('p', { class: 'hint' }, [
        'What is on the list above and what was decided about it. The file goes back up to be ' +
        'formatted and comes straight back down; nothing is kept on the box.'
      ]),
      exportNote,
      h('div', null, [
        h('button', {
          type: 'button',
          onclick: function () {
            downloadPost('/tools/review?format=csv&only=' + view.filter, payload,
              'package-review' + (view.filter === 'all' ? '' : '-' + view.filter) + '.csv');
          }
        }, ['Export CSV']),
        h('button', {
          type: 'button',
          onclick: function () {
            downloadPost('/tools/review?format=file&only=' + view.filter, payload,
              'package-review' + (view.filter === 'all' ? '' : '-' + view.filter) + '.json');
          }
        }, ['Export JSON'])
      ])
    ]));
  }

  drawList();

  // ---- developers can't write rules, but they can ask for what's missing ----
  if (canAsk) {
    var reason = h('input', { type: 'text', placeholder: 'why this project needs them' });
    out.appendChild(h('fieldset', null, [
      h('legend', null, ['Ask for the ticked packages to be approved']),
      h('p', { class: 'hint' }, [
        'Raises a request for every ticked package this registry will not serve today, so an ' +
        'approver sees them on the Requests page. Anything already approved is left out rather ' +
        'than asked for again, and anything you have already asked about is bumped instead of ' +
        'raised twice.'
      ]),
      h('label', null, ['Reason']), reason,
      h('div', null, [
        h('button', {
          type: 'button',
          onclick: function () {
            var items = selectedItems()
              .filter(function (f) { return f.status !== 'WHITELISTED'; })
              .map(function (f) {
                return {
                  ecosystem: f.ecosystem || 'npm',
                  name: f.resolved_package || f.package,
                  version_range: f.version_is_pinned ? (f.ecosystem === 'pypi' ? '==' + f.pinned_version : (f.pinned_version || f.declared_version)) : ''
                };
              });
            if (!items.length) {
              return alert('Tick some packages that are not whitelisted yet. The ones already ' +
                'approved do not need asking for.');
            }
            // server takes 200 at a time, say which 200 instead of letting it bounce
            if (items.length > 200) {
              return alert('That is ' + items.length + ' packages and an ask goes up 200 at a time. ' +
                'Narrow the filter, or set the page size to 100 and work through it a page at a time.');
            }
            if (!reason.value.trim()) return alert('Say why you need them, the approver has to go on something.');
            var asks = {};
            items.forEach(function (it) {
              (asks[it.ecosystem] = asks[it.ecosystem] || []).push({ name: it.name, version_range: it.version_range });
            });
            Object.keys(asks).reduce(function (chain, eco) {
              return chain.then(function (acc) {
                return api('POST', '/requests/bulk', { ecosystem: eco, items: asks[eco], reason: reason.value.trim() })
                  .then(function (r) {
                    return { created: acc.created + r.created, bumped: acc.bumped + (r.bumped || 0), skipped: acc.skipped.concat(r.skipped) };
                  });
              });
            }, Promise.resolve({ created: 0, bumped: 0, skipped: [] }))
              .then(function (r) {
                var msg = 'Asked for ' + r.created + ' package(s)' +
                  (r.bumped ? ', bumped ' + r.bumped + ' you had already asked about' : '') + '.';
                if (r.skipped.length) {
                  msg += '\n\nLeft out ' + r.skipped.length + ':\n' +
                    r.skipped.slice(0, 10).map(function (x) { return x.name + ': ' + x.error; }).join('\n');
                }
                alert(msg);
              })
              .catch(function (e) { alert(e.message); });
          }
        }, ['Request approval for ticked'])
      ])
    ]));
  }

  if (!writable) {
    out.appendChild(h('p', { class: 'hint muted' }, [
      'Writing the allow and deny rules is an approver or admin job. The export is yours either way.'
    ]));
    return;
  }

  function decide(kind) {
    var items = selectedItems().map(function (f) {
      return {
        ecosystem: f.ecosystem || 'npm',
        name: f.resolved_package || f.package,
        version: f.version_is_pinned ? (f.pinned_version || f.declared_version) : null
      };
    });
    if (!items.length) return alert('Tick a few packages first.');
    if (items.length > 2000) {
      return alert('That is ' + items.length + ' packages and rules go in 2000 at a time. ' +
        'Narrow the filter and do it in batches.');
    }
    var what = kind === 'allow' ? 'Whitelist' : 'Blacklist';
    if (!confirm(what + ' ' + items.length + ' package(s)?' +
      (pin.checked ? ' The rule is pinned to the version reviewed.' : ' The rule covers every version.'))) return;

    var groups = {};
    items.forEach(function (it) {
      (groups[it.ecosystem] = groups[it.ecosystem] || []).push({ name: it.name, version: it.version });
    });
    Object.keys(groups).reduce(function (chain, eco) {
      return chain.then(function (acc) {
        return api('POST', '/tools/decide', { ecosystem: eco, kind: kind, items: groups[eco], pin: pin.checked })
          .then(function (r) { return { written: acc.written + r.written, skipped: acc.skipped.concat(r.skipped) }; });
      });
    }, Promise.resolve({ written: 0, skipped: [] }))
      .then(function (r) {
        var msg = 'Wrote ' + r.written + ' ' + kind + ' rule(s).';
        if (r.skipped.length) {
          msg += '\n\nSkipped ' + r.skipped.length + ':\n' +
            r.skipped.slice(0, 10).map(function (x) { return x.name + ': ' + x.error; }).join('\n');
        }
        alert(msg);
        // verdicts changed, so the review on screen is stale now
        runReviewAgain(out);
      })
      .catch(function (e) { alert(e.message); });
  }

  out.appendChild(h('fieldset', null, [
    h('legend', null, ['Decide on the ticked packages']),
    h('p', { class: 'hint' }, [
      'Whitelisting writes an allow rule, blacklisting writes a deny rule. A package that is ' +
      'already blacklisted cannot be whitelisted from here: the deny rule and the reason it was ' +
      'written are on the Rules page, and taking something off the blacklist is a decision to ' +
      'make there, with both in front of you.'
    ]),
    h('label', null, [pin, ' Pin the rule to the version reviewed, rather than covering every version']),
    counter,
    h('div', null, [
      h('button', { type: 'button', onclick: function () { decide('allow'); } }, ['Whitelist ticked']),
      h('button', { type: 'button', class: 'danger', onclick: function () { decide('deny'); } }, ['Blacklist ticked'])
    ])
  ]));
}

// re-run the last review against the rules as they are now
function runReviewAgain(out) {
  if (!reviewState) return;
  var payload = reviewState.payload;
  var pin = reviewState.pin;
  clear(out);
  out.appendChild(h('p', { class: 'muted' }, ['Checking it again against the rules as they are now...']));
  api('POST', '/tools/review', payload)
    .then(function (report) {
      reviewState.report = report;
      renderReview(out, report, payload, pin, reviewState.view);
    })
    .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
}

// most serious first, the reasons in the tooltip and after the label
var NODE_LABELS = {
  blocked: 'blocked', vulnerable: 'known advisory', unapproved: 'allowed, no rule approves it', unknown: 'allowed, never seen on this registry', clean: 'allowed'
};

function nodeStatus(p) {
  if (!p.status) return h('span', { class: p.allowed ? 'allow' : 'deny' }, [p.allowed ? 'allowed' : p.reason]);
  var why = (p.why || []).join('; ');
  var cls = p.status === 'clean' ? 'allow' : (p.status === 'blocked' || p.status === 'vulnerable' ? 'deny' : 'muted');
  return h('span', { class: cls, title: why }, [NODE_LABELS[p.status] + (why && (p.status === 'blocked' || p.status === 'vulnerable') ? ': ' + why : '')]);
}

function treeSummary(s) {
  return s.total + ' dependenc' + (s.total === 1 ? 'y' : 'ies') + ': ' + s.direct + ' direct, ' + s.transitive + ' transitive. ' +
    s.blocked + ' blocked, ' + s.vulnerable + ' with a known advisory, ' + s.unapproved + ' no rule approves yet, ' +
    s.unknown + ' never seen on this registry.';
}

function runResolve(name, range, depth, out, ecosystem) {
  // a walk started elsewhere (Requests page) has no type, those are all npm
  var eco = ecosystem || 'npm';
  var target = window.__resolveTarget;
  if (!out && target) {
    out = target.out;
    target.name.value = name;
    target.range.value = range || 'latest';
    if (target.type) target.type.value = eco;
  }
  if (!out) return;
  if (eco === 'oci') return resolveImage(name, range, out);

  clear(out);
  out.appendChild(h('p', { class: 'muted' }, ['Walking the tree, this can take a moment...']));

  api('POST', '/tools/resolve', { ecosystem: eco, name: name, version_range: range || 'latest', depth: depth || 12 })
    .then(function (d) {
      clear(out);
      // total has the package itself in it, the summary does not
      var pulled = d.summary ? d.summary.total : Math.max(0, d.total - 1);
      out.appendChild(notice(
        d.root + ' pulls in ' + pulled + ' package' + (pulled === 1 ? '' : 's') + '. ' +
        (d.blocked ? d.blocked + ' of them would be blocked right now.' : 'All of them are allowed.') +
        (d.truncated ? ' The tree was cut short, it is a big one.' : ''),
        d.blocked ? 'err' : 'ok'
      ));
      if (d.summary) out.appendChild(h('p', { class: 'hint tree-summary' }, [treeSummary(d.summary)]));

      var blocked = d.packages.filter(function (p) { return !p.allowed; });
      var writable = can('rules:write');
      var canAsk = can('requests:create');
      var selectable = writable || canAsk;

      // blocked covers both kinds, only ones no deny rule names can be allowed in one go
      var allowable = blocked.filter(function (p) { return !p.denied; });
      var blacklisted = blocked.length - allowable.length;

      if (allowable.length && writable) {
        out.appendChild(h('button', {
          onclick: function () {
            if (!confirm('Add an allow rule for all ' + allowable.length + ' of these?')) return;
            api('POST', '/tools/allow-tree', {
              ecosystem: eco,
              names: allowable.map(function (p) { return p.name; }),
              note: 'approved with ' + name
            }).then(function (r) {
              alert('Added ' + r.added + ' rules.' +
                (r.skipped && r.skipped.length ? '\n\nLeft blocked: ' + r.skipped.length + '.' : ''));
              runResolve(name, range, depth, out, eco);
            }).catch(function (e) { alert(e.message); });
          }
        }, ['Allow all ' + allowable.length + ' packages that are not approved yet']));
      }

      if (blacklisted) {
        out.appendChild(h('p', { class: 'hint' }, [
          blacklisted + ' of these are blacklisted by a deny rule. They cannot be ticked and are ' +
          'left out of allowing the rest: a blocked version is never whitelisted from here. The ',
          link('Rules page', function () { window.location.hash = '#rules'; }),
          ' has the rule and the reason it was written.'
        ]));
      }

      // ---- tick a few and decide on those, instead of all or nothing ----
      var picked = {};
      var boxes = [];
      var selectAll = h('input', { type: 'checkbox', title: 'select every package in the tree' });
      var counter = h('span', { class: 'muted' }, ['none selected']);
      var pin = h('input', { type: 'checkbox', checked: 'checked' });

      var tickable = d.packages.filter(function (p) { return !p.denied; }).length;

      function refreshCount() {
        var n = Object.keys(picked).length;
        counter.textContent = n ? n + ' of ' + tickable + ' selected' : 'none selected';
      }

      selectAll.addEventListener('change', function () {
        boxes.forEach(function (b) {
          b.checked = selectAll.checked;
          if (selectAll.checked) picked[b.value] = true;
          else delete picked[b.value];
        });
        refreshCount();
      });

      out.appendChild(table(
        [{ label: selectable ? selectAll : '' }, 'Package', 'Version', { label: 'Depth', num: true },
          'Pulled in by', 'Status'],
        d.packages.map(function (p, i) {
          var tick = h('input', { type: 'checkbox', value: String(i) });
          // blocked by a deny rule, as opposed to just not approved yet
          if (!selectable || p.denied) {
            tick.setAttribute('disabled', 'disabled');
            if (p.denied) {
              tick.setAttribute('title', 'blacklisted, and a blocked version is never whitelisted from here');
            }
          }
          tick.addEventListener('change', function () {
            if (tick.checked) picked[i] = true;
            else delete picked[i];
            refreshCount();
          });
          if (!p.denied) boxes.push(tick);
          return [
            tick,
            h('span', { class: 'mono' }, [p.name]),
            p.version,
            String(p.depth),
            (p.via || 'you asked for it') + (p.when ? ', when ' + p.when : ''),
            nodeStatus(p)
          ];
        })
      ));

      if (canAsk && blocked.length) {
        var treeReason = h('input', { type: 'text', placeholder: 'why this project needs them' });
        out.appendChild(h('fieldset', null, [
          h('legend', null, ['Ask for the ticked packages to be approved']),
          h('p', { class: 'hint' }, [
            'Raises a request for every ticked package the rules will not serve, so an approver ' +
            'sees them on the Requests page. The ones already allowed are left out.'
          ]),
          h('label', null, ['Reason']), treeReason,
          h('div', null, [
            h('button', {
              type: 'button',
              onclick: function () {
                var items = Object.keys(picked).map(function (i) { return d.packages[Number(i)]; })
                  .filter(function (p) { return !p.allowed; })
                  .map(function (p) { return { name: p.name, version_range: p.version || '' }; });
                if (!items.length) return alert('Tick some packages that are not allowed yet.');
                if (!treeReason.value.trim()) return alert('Say why you need them.');
                api('POST', '/requests/bulk', { ecosystem: eco, items: items, reason: treeReason.value.trim() })
                  .then(function (r) {
                    var msg = 'Asked for ' + r.created + ' package(s)' +
                      (r.bumped ? ', bumped ' + r.bumped + ' you had already asked about' : '') + '.';
                    if (r.skipped.length) {
                      msg += '\n\nLeft out ' + r.skipped.length + ':\n' +
                        r.skipped.slice(0, 10).map(function (x) { return x.name + ': ' + x.error; }).join('\n');
                    }
                    alert(msg);
                  })
                  .catch(function (e) { alert(e.message); });
              }
            }, ['Request approval for ticked'])
          ])
        ]));
      }

      if (writable && d.packages.length) {
        var decideTree = function (kind) {
          var items = Object.keys(picked).map(function (i) {
            var p = d.packages[Number(i)];
            return { name: p.name, version: p.version || null };
          });
          if (!items.length) return alert('Tick a few packages first.');
          var what = kind === 'allow' ? 'Whitelist' : 'Blacklist';
          if (!confirm(what + ' ' + items.length + ' package(s) from this tree?' +
            (pin.checked ? ' The rule is pinned to the version the tree resolved.'
                         : ' The rule covers every version.'))) return;

          api('POST', '/tools/decide', {
            ecosystem: eco,
            kind: kind,
            items: items,
            pin: pin.checked,
            note: (kind === 'allow' ? 'approved' : 'blocked') + ' from the tree walk of ' + name
          }).then(function (r) {
            var msg = 'Wrote ' + r.written + ' ' + kind + ' rule(s).';
            if (r.skipped.length) {
              msg += '\n\nSkipped ' + r.skipped.length + ':\n' +
                r.skipped.slice(0, 10).map(function (x) { return x.name + ': ' + x.error; }).join('\n');
            }
            alert(msg);
            runResolve(name, range, depth, out, eco);
          }).catch(function (e) { alert(e.message); });
        };

        out.appendChild(h('fieldset', null, [
          h('legend', null, ['Decide on the ticked packages']),
          h('p', { class: 'hint' }, [
            'Whitelisting writes an allow rule, blacklisting writes a deny rule. Anything already ' +
            'blacklisted is refused rather than whitelisted from here, and says which rule stopped it.'
          ]),
          h('label', null, [pin, ' Pin the rule to the version the tree resolved, rather than covering every version']),
          counter,
          h('div', null, [
            h('button', { type: 'button', onclick: function () { decideTree('allow'); } }, ['Whitelist ticked']),
            h('button', { type: 'button', class: 'danger', onclick: function () { decideTree('deny'); } }, ['Blacklist ticked'])
          ])
        ]));
      }

      if (d.problems.length) {
        out.appendChild(h('h3', null, ['Could not resolve these']));
        out.appendChild(table(['Package', 'Problem'], d.problems.map(function (p) { return [p.name, p.error]; })));
      }
    })
    .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
}

export { reviewFileSection, runResolve };
