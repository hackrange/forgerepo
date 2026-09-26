// ForgeRepo portal: vulnerabilities.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { can, clear, notice, pager, table, when } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';
import { unassigned } from './labels.js';
import { ecoPkg, ecoSpec } from './ecosystems.js';
import { route } from './routing.js';

var cvePage = 1;
var cveFilter = { ecosystem: '', severity: '', q: '', only_new: false, kev: false };
// a scan this page watched finish, kept across the redraw
var cveLastScan = null;

// just the filters, so list and export match
function cveQuery() {
  return (cveFilter.ecosystem ? '&ecosystem=' + cveFilter.ecosystem : '') +
    (cveFilter.severity ? '&severity=' + cveFilter.severity : '') +
    (cveFilter.q ? '&q=' + encodeURIComponent(cveFilter.q) : '') +
    (cveFilter.only_new ? '&only_new=1' : '') +
    (cveFilter.kev ? '&kev=1' : '');
}

// on CISA's known exploited list, with the federal fix-by date and ransomware use in the tooltip
function exploitedCell(f) {
  if (!f.kev) return h('span', { class: 'muted' }, ['no']);
  var title = 'On the CISA Known Exploited Vulnerabilities list' + (f.kevDue ? ', fix by ' + String(f.kevDue).slice(0, 10) : '') +
    (f.ransomware ? ', used in ransomware campaigns' : '');
  return h('span', { class: 'deny', title: title }, ['KEV' + (f.ransomware ? ', ransomware' : '')]);
}

function epssCell(f) {
  if (f.epss === null || f.epss === undefined) return '';
  return h('span', { class: f.percentile >= 0.95 ? 'deny' : null, title: 'Chance of exploitation in the next 30 days. Higher than ' + Math.round(f.percentile * 100) + '% of all CVEs' },
    [(f.epss * 100).toFixed(1) + '%']);
}

function spellVersion(ecosystem, name, version) {
  return ecosystem === 'oci' ? name + '@' + version : ecoSpec(ecosystem, name, version);
}

// ---- container images ----
// where the detail of one image opens, under the images list
var imageBox = null;

function shortDigest(d) {
  return String(d || '').slice(0, 19) + '...';
}

function sevCell(s) {
  if (!s) return h('span', { class: 'muted' }, ['none known']);
  return h('span', { class: s === 'CRITICAL' || s === 'HIGH' ? 'deny' : null }, [s.toLowerCase()]);
}

function imageDetail(repository, digest, all) {
  if (!imageBox) return;
  var box = imageBox;
  clear(box);
  box.appendChild(h('p', { class: 'hint' }, ['Opening ' + repository + '...']));
  api('GET', '/cve/images/detail?repository=' + encodeURIComponent(repository) + '&digest=' + encodeURIComponent(digest) + (all ? '&all=1' : ''))
    .then(function (d) {
      clear(box);
      var img = d.image;
      var rows = all ? d.components : d.vulnerable;
      var said = (img.os || 'An operating system that could not be read') +
        (img.feed ? ', matched against the ' + img.feed + ' advisories. ' : '. ') +
        img.components + ' packages, ' + img.vulnerable + ' with a known advisory. Last checked ' + when(img.checked_at || img.scanned_at) + '.';
      box.appendChild(h('fieldset', null, [
        h('legend', null, ['Inside ' + repository]),
        h('p', { class: 'hint mono digest' }, [img.digest]),
        h('p', { class: 'hint' }, [said]),
        img.notes && img.notes.length ? h('ul', { class: 'hint' }, img.notes.map(function (n) { return h('li', null, [n]); })) : null,
        h('div', null, [
          h('button', { type: 'button', onclick: function () { imageDetail(repository, digest, !all); } },
            [all ? 'Only the vulnerable packages' : 'Every package in it']),
          h('button', { type: 'button', onclick: function () { clear(box); } }, ['Close'])
        ]),
        rows.length
          ? table(['Package', 'Kind', 'Installed', 'Severity', 'Fixed in', 'CVE', 'What it is'], rows.map(function (c) {
            return [
              h('span', { class: 'mono', title: (c.binaries || []).length ? 'installed as ' + c.binaries.join(', ') : null }, [c.name]),
              c.type,
              h('span', { class: 'mono' }, [c.version]),
              c.advisories ? sevCell(c.severity) : h('span', { class: 'muted' }, ['none known']),
              c.fixed_in ? h('span', { class: 'mono' }, [c.fixed_in]) : (c.advisories ? h('span', { class: 'muted' }, ['no fix yet']) : ''),
              c.cves || '',
              c.summary || ''
            ];
          }))
          : h('p', { class: 'hint' }, [all ? 'No packages were found in this image.' : 'No package in this image has a known advisory against it.'])
      ]));
      box.scrollIntoView({ block: 'start', behavior: 'smooth' });
    })
    .catch(function (e) {
      clear(box);
      box.appendChild(notice(e.message, 'err'));
    });
}

function statusCell(img) {
  if (img.status === 'failed') return h('span', { class: 'deny', title: img.error || null }, ['could not scan']);
  if (img.status === 'skipped') return h('span', { class: 'muted', title: (img.notes || [])[0] || null }, ['not an image to scan']);
  if (img.status === 'queued' || img.status === 'scanning') return h('span', { class: 'muted' }, [img.status + '...']);
  return 'scanned';
}

function viewImages(box) {
  api('GET', '/cve/images?page=1&limit=25').then(function (d) {
    clear(box);
    var fs = h('fieldset', null, [
      h('legend', null, ['Container images']),
      h('p', { class: 'hint' }, [
        'Every image pulled through here is opened once per digest, and the packages inside it, from the operating system and from npm and Python, ' +
        'are checked against the advisory feeds. Only package names and versions leave the box. The scheduled scan checks them again as new advisories come out.'
      ])
    ]);
    var st = d.settings || {};
    [
      ['oci_scan', 'Scan the images people pull', null],
      ['oci_scan_before_serve', 'Scan before serving', 'An image nobody has looked inside yet is refused with try again in a minute until its scan is done. Off, the first pull goes out and the scan follows.'],
      ['oci_scan_ignore_unfixed', 'Only count what has a fix', 'With Safe Version Resolution on, an image is refused when a package inside it has an advisory at or above ' +
        String(st.safe_resolution_severity || 'HIGH').toLowerCase() + '. Ticked, only advisories an upgrade already fixes count, since nearly every base image carries something nobody can fix yet.']
    ].forEach(function (item) {
      if (!can('settings:write')) return;
      var tick = h('input', {
        type: 'checkbox',
        checked: st[item[0]] ? 'checked' : null,
        onchange: function () {
          var payload = {};
          payload[item[0]] = tick.checked ? '1' : '0';
          api('PUT', '/settings', payload).catch(function (e) {
            tick.checked = !tick.checked;
            alert(e.message);
          });
        }
      });
      fs.appendChild(h('label', null, [tick, item[1]]));
      if (item[2]) fs.appendChild(h('p', { class: 'hint' }, [item[2]]));
    });
    if (!can('settings:write') && !st.oci_scan) {
      fs.appendChild(h('p', { class: 'hint muted' }, ['Image scanning is switched off. Only an admin can switch it on.']));
    }
    fs.appendChild(h('p', { class: 'hint' }, [st.safe_resolution
      ? 'Safe Version Resolution is on, so an image too vulnerable by that measure is refused, unless a waiver covers it.'
      : 'Safe Version Resolution is off, so image findings are listed here and nothing is refused for them.']));
    var tally = (d.counts || []).map(function (c) { return c.n + ' ' + c.status; }).join(', ');
    fs.appendChild(h('p', { class: 'hint' }, [
      d.total ? d.total + ' image(s) seen: ' + tally + (d.waiting ? ', ' + d.waiting + ' waiting to be read' : '') + '.' : 'No image has been pulled through here yet.'
    ]));
    if (d.images.length) {
      fs.appendChild(table(['Image', 'Digest', 'Status', 'OS', { label: 'Packages', num: true }, { label: 'Vulnerable', num: true }, 'Worst', 'Scanned', 'Actions'],
        d.images.map(function (img) {
          var actions = h('span', { class: 'actions' }, []);
          if (img.status === 'done') actions.appendChild(link('packages', function () { imageDetail(img.repository, img.digest, false); }));
          if (can('rules:write') && img.status !== 'queued' && img.status !== 'scanning') {
            actions.appendChild(link('scan again', function () {
              api('POST', '/cve/images/scan', { repository: img.repository, digest: img.digest })
                .then(function () { setTimeout(function () { viewImages(box); }, 1500); })
                .catch(function (e) { alert(e.message); });
            }));
          }
          return [
            ecoPkg('oci', img.repository),
            h('span', { class: 'mono', title: img.digest }, [shortDigest(img.digest)]),
            statusCell(img),
            img.os || '',
            img.status === 'done' ? String(img.components) : '',
            img.status === 'done' ? String(img.vulnerable) : '',
            img.status === 'done' ? sevCell(img.severity) : '',
            when(img.scanned_at),
            actions
          ];
        })));
    }
    imageBox = h('div', null, []);
    box.appendChild(fs);
    box.appendChild(imageBox);
  }).catch(function (e) {
    clear(box);
    box.appendChild(notice(e.message, 'err'));
  });
}

function viewCve(body) {
  section(body, 'Vulnerabilities', 'Versions the rules allow today that have a known advisory against them.');
  // same Type picker as the Rules page, same reason
  var types = state.ecosystems || [];
  var typeName = function (id) {
    var t = types.filter(function (x) { return x.id === id; })[0];
    return t ? t.name : (id || 'npm');
  };
  if (cveFilter.ecosystem && (types.length < 2 || !types.some(function (t) { return t.id === cveFilter.ecosystem; }))) {
    cveFilter.ecosystem = '';
  }

  return api('GET', '/cve/scan').then(function (scan) {
    var last = (scan.history || [])[0];

    // ---- the scan itself ----
    var out = h('div', null, []);
    var justFinished = cveLastScan;
    cveLastScan = null;
    var cancelBtn = h('button', {
      class: 'danger',
      onclick: function () {
        api('POST', '/cve/scan/cancel', {}).then(function (r) { render(r.job); }).catch(function (e) { alert(e.message); });
      }
    }, ['Stop']);
    cancelBtn.style.display = 'none';
    var scanBtn = null;

    // progress right by the button so nobody mashes it
    function render(j, announce) {
      if (!j) return;
      cancelBtn.style.display = j.running ? '' : 'none';
      if (scanBtn) {
        scanBtn.disabled = !!j.running;
        scanBtn.textContent = j.running ? 'Scanning...' : 'Scan now';
      }
      clear(out);
      if (j.running) {
        out.appendChild(notice(!j.total && j.phase === 'preparing'
          ? 'Scanning. Working out which allowed versions to check.'
          : 'Scanning. Checked ' + j.done + ' of ' + j.total + ' allowed versions.', 'info'));
        // no total yet means the bar has no value, which draws it as busy
        var bar = h('progress', { max: String(j.total || 1), 'aria-label': 'scan progress' }, []);
        if (j.total) bar.value = j.done;
        out.appendChild(bar);
      } else if (j.finishedAt) {
        var troubled = j.failed || (j.errors && j.errors.length);
        var summary = 'Finished. ' + j.done + ' of ' + j.total + ' checked, ' + j.vulnerable + ' vulnerable, ' +
          j.fresh + ' new, ' + j.resolved + ' no longer apply' +
          (j.failed ? ', ' + j.failed + ' could not be checked' : '') + '.' +
          (j.errors && j.errors.length ? ' ' + j.errors[0] : '');
        out.appendChild(announce ? notice(summary, troubled ? 'err' : 'ok') : h('p', { class: 'hint' }, [summary]));
      }
    }

    // server keeps the last job around, only announce one we actually watched
    var watching = false;

    function poll() {
      if (!out.isConnected) return;
      api('GET', '/cve/scan').then(function (r) {
        render(r.job, watching && r.job && !r.job.running);
        if (r.job && r.job.running) setTimeout(poll, 1500);
        else if (watching) {
          watching = false;
          cveLastScan = r.job;
          setTimeout(route, 1500);
        }
      }).catch(function () { setTimeout(poll, 3000); });
    }

    scanBtn = h('button', {
      class: 'primary',
      onclick: function () {
        scanBtn.disabled = true;
        scanBtn.textContent = 'Starting...';
        api('POST', '/cve/scan', {}).then(function (r) {
          watching = true;
          render(r.job);
          poll();
        }).catch(function (e) {
          // someone else's scan (or the scheduled one) is already going, so just watch that
          if (/already running/.test(e.message)) {
            watching = true;
            poll();
            return;
          }
          scanBtn.disabled = false;
          scanBtn.textContent = 'Scan now';
          clear(out);
          out.appendChild(notice(e.message, 'err'));
        });
      }
    }, ['Scan now']);

    body.appendChild(h('fieldset', null, [
      h('legend', null, ['Scan']),
      h('p', { class: 'hint' }, [
        last
          ? 'Last checked ' + last.started_at + ' by ' + last.started_by + ': ' + last.checked +
            ' versions, ' + last.vulnerable + ' vulnerable, ' + last.fresh + ' new at the time.'
          : 'This list has never been checked.',
        scan.everyHours
          ? ' Runs on its own every ' + scan.everyHours + ' hour(s).'
          : ' The scheduled run is switched off in Settings.'
      ]),
      h('p', { class: 'hint' }, [
        'Nothing here is blocked automatically. Blocking a version breaks whoever depends on it, ' +
        'so that stays a decision somebody makes on purpose.'
      ]),
      can('rules:write') ? h('div', null, [scanBtn, cancelBtn]) : null,
      out
    ]));

    // ---- what developers get told ----
    // none of these can fail a build, hence on by default. say so before someone panics and flips them off
    var TELLING = [
      ['audit_answer', 'Answer npm audit',
        'npm asks this registry about the tree it just installed and prints the summary. The answer comes from the findings below, so nothing about your project leaves the box. npm only fails on it when somebody runs npm audit --audit-level themselves.'],
      ['audit_warn_install', 'Warn during the install',
        'Marks affected versions in the metadata and sets a notice header on the download, so npm prints the package, the version and the severity as it installs. It is a warning, the install carries on.'],
      ['audit_log_downloads', 'Record who downloaded what',
        'Writes a row every time a version with a known advisory is pulled, with the client address and the token behind it. Nothing is shown to the developer for this one, it is for you.']
    ];

    var telling = h('fieldset', null, [
      h('legend', null, ['Telling developers']),
      h('p', { class: 'hint' }, [
        'What this registry says about a bad version when somebody installs one. ' +
        'None of it blocks an install or fails a pipeline.'
      ])
    ]);

    TELLING.forEach(function (item) {
      var key = item[0];
      var tick = h('input', {
        type: 'checkbox',
        checked: scan.reporting && scan.reporting[key] ? 'checked' : null,
        disabled: can('settings:write') ? null : 'disabled',
        onchange: function () {
          var payload = {};
          payload[key] = tick.checked ? '1' : '0';
          api('PUT', '/settings', payload).catch(function (e) {
            tick.checked = !tick.checked;
            alert(e.message);
          });
        }
      });
      telling.appendChild(h('label', null, [tick, item[1]]));
      telling.appendChild(h('p', { class: 'hint' }, [item[2]]));
    });
    if (!can('settings:write')) {
      telling.appendChild(h('p', { class: 'hint muted' }, ['Only an admin can change these.']));
    }
    body.appendChild(telling);

    // only chase a live job. one we just watched finish gets announced again with its findings
    if (scan.job && scan.job.running) render(scan.job);
    else render(justFinished || scan.job, !!justFinished);
    if (scan.job && scan.job.running) {
      watching = true;
      poll();
    }

    // ---- filters ----
    var sev = h('select', null, [
      h('option', { value: '' }, ['any severity']),
      h('option', { value: 'CRITICAL', selected: cveFilter.severity === 'CRITICAL' }, ['critical']),
      h('option', { value: 'HIGH', selected: cveFilter.severity === 'HIGH' }, ['high']),
      h('option', { value: 'MODERATE', selected: cveFilter.severity === 'MODERATE' }, ['moderate']),
      h('option', { value: 'LOW', selected: cveFilter.severity === 'LOW' }, ['low'])
    ]);
    var cveType = types.length > 1
      ? h('select', null, [h('option', { value: '' }, ['All'])].concat(types.map(function (t) {
        return h('option', { value: t.id, selected: cveFilter.ecosystem === t.id }, [t.name]);
      })))
      : null;
    var q = h('input', { type: 'text', value: cveFilter.q, placeholder: 'package or CVE' });
    var onlyNew = h('input', { type: 'checkbox', checked: cveFilter.only_new ? 'checked' : null });
    var kevOnly = h('input', { type: 'checkbox', checked: cveFilter.kev ? 'checked' : null });

    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        cveFilter.ecosystem = cveType ? cveType.value : '';
        cveFilter.severity = sev.value;
        cveFilter.q = q.value.trim();
        cveFilter.only_new = onlyNew.checked;
        cveFilter.kev = kevOnly.checked;
        cvePage = 1;
        route();
      }
    }, [
      cveType ? h('div', null, [h('label', null, ['Type']), cveType]) : null,
      h('div', null, [h('label', null, ['Search']), q]),
      h('div', null, [h('label', null, ['Severity']), sev]),
      h('div', null, [h('label', null, ['New in 24h']), onlyNew]),
      h('div', null, [h('label', null, ['Known exploited']), kevOnly]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    if (can('rules:export')) {
      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Export the findings']),
        h('p', { class: 'hint' }, [
          'Every finding the filter above matches, not just the page on screen, with the package, ' +
          'the version, the severity, the CVE, the patched release and when it was first seen. ' +
          'Leave the filter empty and it is every vulnerability this box knows about.'
        ]),
        h('div', null, [
          h('button', {
            type: 'button',
            onclick: function () {
              download('/cve/findings/export?format=csv' + cveQuery(), 'forgerepo-vulnerabilities.csv');
            }
          }, ['Export CSV']),
          h('button', {
            type: 'button',
            onclick: function () {
              download('/cve/findings/export?format=json' + cveQuery(), 'forgerepo-vulnerabilities.json');
            }
          }, ['Export JSON'])
        ])
      ]));
    }

    var query = '?page=' + cvePage + '&limit=100' + cveQuery();

    return api('GET', '/cve/findings' + query).then(function (d) {
      var tally = (d.counts || []).map(function (c) { return c.n + ' ' + c.severity.toLowerCase(); }).join(', ');
      body.appendChild(h('p', { class: 'hint' }, [
        d.total ? 'Showing ' + d.findings.length + ' of ' + d.total + '. Across everything: ' + tally + '.'
                : 'Nothing on the allow list has a known advisory against it.'
      ]));

      if (d.findings.length) {
        var findingCols = ['Package', 'Version', 'Severity', 'Exploited', { label: 'EPSS', num: true }, 'What it is', 'CVE', 'Patched in', 'First seen', 'Actions'];
        body.appendChild(table(
          findingCols,
          d.findings.map(function (f) {
            var actions = h('span', { class: 'actions' }, []);
            if (can('rules:write')) {
              actions.appendChild(link('block', function () {
                if (!confirm('Write a deny rule for ' + spellVersion(f.ecosystem, f.package_name, f.version) + '?\n\n' +
                  'Anything pinned to that version stops resolving.')) return;
                api('POST', '/cve/findings/' + f.id + '/block', {})
                  .then(route).catch(function (e) { alert(e.message); });
              }));
              actions.appendChild(link(f.acknowledged ? 'un-ack' : 'ack', function () {
                api('POST', '/cve/findings/' + f.id + '/ack', { acknowledged: !f.acknowledged })
                  .then(route).catch(function (e) { alert(e.message); });
              }));
            }
            if (f.ecosystem === 'oci') {
              actions.appendChild(link('packages', function () { imageDetail(f.package_name, f.version, false); }));
            }
            var cells = [
              ecoPkg(f.ecosystem, f.package_name),
              f.ecosystem === 'oci' ? h('span', { class: 'mono', title: f.version }, [shortDigest(f.version)]) : h('span', { class: 'mono' }, [f.version]),
              h('span', { class: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'deny' : null },
                [f.severity.toLowerCase() + (f.acknowledged ? ' (ack)' : '')]),
              exploitedCell(f),
              epssCell(f),
              f.summary || f.advisories,
              f.cves || h('span', { class: 'muted' }, ['none']),
              f.fixed_in || h('span', { class: 'muted' }, ['no fix listed']),
              String(f.first_seen).slice(0, 10),
              actions
            ];
            return cells;
          })
        ));
      }

      body.appendChild(pager(d.page, d.total, d.limit, function (p) { cvePage = p; route(); }));

      // images get their own list, filled in as it loads
      imageBox = null;
      if (types.some(function (t) { return t.id === 'oci'; })) {
        var imagesHere = h('div', null, []);
        body.appendChild(imagesHere);
        viewImages(imagesHere);
      }

      // ---- and what somebody actually pulled ----
      // who pulled it is traffic, admin only
      if (!can('logs:read')) return null;
      return api('GET', '/cve/downloads?page=1&limit=25').then(function (dl) {
        body.appendChild(h('h3', null, ['Pulled with a known advisory']));
        body.appendChild(h('p', { class: 'hint' }, [
          dl.total
            ? dl.total + ' download(s) of a version we already knew about. This is the list to work ' +
              'through: the application and environment say what is running it, and the address says ' +
              'which build agent or laptop it landed on. A row that reads unassigned came from a token ' +
              'with no application set, which is worth fixing on the Tokens page.'
            : 'Nothing with a known advisory against it has been pulled through here.'
        ]));
        if (dl.downloads.length) {
          var downloadCols = ['When', 'Package', 'Version', 'Severity', 'CVE', 'Application', 'Environment', 'From', 'Token', 'Cached'];
          body.appendChild(table(
            downloadCols,
            dl.downloads.map(function (r) {
              var cells = [
                when(r.ts),
                ecoPkg(r.ecosystem, r.package_name),
                h('span', { class: 'mono' }, [r.version]),
                h('span', { class: r.severity === 'CRITICAL' || r.severity === 'HIGH' ? 'deny' : null },
                  [String(r.severity).toLowerCase()]),
                r.cves || h('span', { class: 'muted' }, ['none']),
                r.application || unassigned(),
                r.environment || unassigned(),
                h('span', { class: 'mono' }, [r.ip || '']),
                r.username || r.token_name || h('span', { class: 'muted' }, ['no token']),
                r.cache_hit ? 'from cache' : 'from upstream'
              ];
              return cells;
            })
          ));
        }
      });
    });
  });
}

export { viewCve };
