// ForgeRepo portal: dashboard.
// Author: Tim Rice

import { h, link } from './dom.js';
import { bytes, can, clear, notice, svgIcon, table, when } from './ui.js';
import { api } from './api.js';
import { renderFrame, section } from './frame.js';
import { ecoHints, ecoIcon, ecoName } from './ecosystems.js';
import { boot, route } from './routing.js';

//numbers come off a timer, not per visit. not worth the wait
function dashAge(d) {
  if (!d.cacheMinutes) return h('p', { class: 'hint' }, ['Worked out just now.']);
  var age = Number(d.ageSeconds) || 0;
  var how = age < 60 ? 'just now' : Math.round(age / 60) + ' minutes ago';
  return h('p', { class: 'hint' }, [
    'Counted ' + how + ', kept for ' + d.cacheMinutes + ' minutes at a time. ',
    link('Work them out again', function () { viewDashRefresh(); })
  ]);
}

function viewDashRefresh() {
  var body = renderFrame('dash');
  body.appendChild(h('p', { class: 'muted' }, ['Counting...']));
  return viewDash(body, true).catch(function (err) {
    clear(body);
    body.appendChild(notice(err.message, 'err'));
  });
}

var MODE_TEXT = {
  normal: 'Packages are fetched from upstream as usual.',
  degraded: 'Nothing new is fetched from upstream by name. Packages this registry already holds still refresh and install.',
  lockdown: 'Nothing is fetched from upstream at all. Metadata only offers what is cached, and any file with a quarantine hold is refused.'
};
var MODE_ORDER = ['normal', 'degraded', 'lockdown'];

// the incident switch. approvers can raise it, only admins bring it back down
function modePanel(m) {
  if (!m) return null;
  var buttons = MODE_ORDER.filter(function (x) {
    if (x === m.mode) return false;
    return MODE_ORDER.indexOf(x) > MODE_ORDER.indexOf(m.mode) ? m.canRaise : m.canLower;
  }).map(function (x) {
    return h('button', {
      type: 'button',
      class: x === 'lockdown' ? 'danger' : null,
      onclick: function () {
        var why = prompt('Switch the registry to ' + x + '?\n\n' + MODE_TEXT[x] + '\n\nWhy? It goes to the admins and into the audit trail.', '');
        if (why === null) return;
        if (!why.trim()) return alert('Say why.');
        api('PUT', '/mode', { mode: x, reason: why.trim() })
          .then(function () { return boot(true); })
          .then(function () { route(); })
          .catch(function (e) { alert(e.message); });
      }
    }, [x === 'normal' ? 'Back to normal' : 'Switch to ' + x]);
  });
  return h('fieldset', { class: 'mode-panel' + (m.mode === 'normal' ? '' : ' mode-' + m.mode) }, [
    h('legend', null, ['Registry mode']),
    h('p', null, [h('strong', { class: m.mode === 'normal' ? 'allow' : 'deny' }, [m.mode]), ' ', MODE_TEXT[m.mode]]),
    m.mode !== 'normal' && m.by ? h('p', { class: 'hint' }, ['Since ' + when(m.at) + ', by ' + m.by + ': ' + m.reason]) : null,
    buttons.length ? h('div', null, buttons) : null
  ]);
}

// a person out of the loop for clean requests. admins switch it, everyone who reads the dashboard sees it
function autoPanel(a) {
  if (!a) return null;
  var toggle = a.canChange ? h('button', {
    type: 'button',
    class: a.on ? null : 'danger',
    onclick: function () {
      var question = a.on
        ? 'Turn auto approve off?\n\nEvery request waits for a person again.'
        : 'Turn auto approve on?\n\nA pending request is approved by itself when a malware scan of every file comes back clean and nothing High or Critical is known. It is pinned to the exact versions checked. Anything else waits in Requests.';
      var why = prompt(question + '\n\nWhy? It goes to the admins and into the audit trail.', '');
      if (why === null) return;
      if (!why.trim()) return alert('Say why.');
      api('PUT', '/auto-approve', { on: !a.on, reason: why.trim() })
        .then(function () { route(); })
        .catch(function (e) { alert(e.message); });
    }
  }, [a.on ? 'Turn auto approve off' : 'Turn auto approve on']) : null;
  return h('fieldset', { class: 'mode-panel' }, [
    h('legend', null, ['Auto approve']),
    h('p', null, [
      h('strong', { class: a.on ? 'warn' : 'allow' }, [a.on ? 'on' : 'off']), ' ',
      a.on
        ? 'Requests are approved by themselves when every file scans clean for malware and the worst advisory is below High. High or Critical, or anything the scanners could not answer, waits in Requests.'
        : 'Every request waits for a person in Requests.'
    ]),
    a.by ? h('p', { class: 'hint' }, ['Switched ' + (a.on ? 'on' : 'off') + ' ' + when(a.at) + ', by ' + a.by + ': ' + a.reason]) : null,
    toggle ? h('div', null, [toggle]) : null
  ]);
}

function viewDash(body, refresh) {
  return api('GET', '/stats' + (refresh ? '?refresh=1' : '')).then(function (d) {
    section(body, 'Dashboard', 'Where this registry stands right now.');
    body.appendChild(dashAge(d));
    if (d.registryMode) body.appendChild(modePanel(d.registryMode));
    if (d.autoApprove) body.appendChild(autoPanel(d.autoApprove));
    var panel = h('div', { class: 'dash-list', id: 'dash-list', 'aria-live': 'polite' }, []);
    body.appendChild(dashCards(d.cards, panel));
    body.appendChild(panel);

    body.appendChild(h('dl', { class: 'facts' }, [
      h('dt', null, ['Policy']), h('dd', null, [d.policyMode + (d.auditMode ? ' (audit only, nothing is actually blocked)' : '')]),
      h('dt', null, ['Upstream']), h('dd', null, [
        d.upstream + (d.upstreamCount > 1 ? ' and ' + (d.upstreamCount - 1) + ' more' : '')
      ]),
      h('dt', null, ['Rules']), h('dd', null, [d.allowRules + ' allow, ' + d.denyRules + ' deny']),
      h('dt', null, ['Packages seen']), h('dd', null, [String(d.packages)]),
      h('dt', null, ['Cache']), h('dd', null, [d.cache.tarballs + ' tarballs, ' + bytes(d.cache.tarballBytes) + ', plus ' + d.cache.packuments + ' metadata docs']),
      // traffic numbers only come back for roles that can read traffic
      d.allows24h === undefined ? null : h('dt', null, ['Last 24 hours']),
      d.allows24h === undefined ? null : h('dd', null, [d.allows24h + ' served, ' + d.denies24h + ' blocked']),
      h('dt', null, ['Pending requests']), h('dd', null, [
        d.pendingRequests ? h('a', { href: '#requests' }, [d.pendingRequests + ' waiting']) : 'none'
      ]),
      h('dt', null, ['Integrity alerts']), h('dd', null, [
        d.integrityOpen ? h('a', { href: '#integrity', class: 'deny' }, [d.integrityOpen + ' open']) : 'none'
      ]),
      h('dt', null, ['Malware']), h('dd', null, [
        !d.malwareEnabled ? 'scanning off'
          : d.malwareFlagged ? h('a', { href: '#quarantine', class: 'deny' }, [d.malwareFlagged + ' flagged file(s)']) : 'nothing flagged'
      ]),
      h('dt', null, ['Quarantine']), h('dd', null, [
        d.quarantineOpen ? h('a', { href: '#quarantine', class: 'deny' }, [d.quarantineOpen + ' held']) : 'nothing held',
        ' (' + d.quarantineMode + ')'
      ]),
      h('dt', null, ['Client auth']), h('dd', null, [d.requireAuth ? 'tokens required' : 'open to anyone who can reach it']),
      h('dt', null, ['Portal ip filter']), h('dd', null, [d.aclEnabled ? 'on' : 'off'])
    ]));

    if (d.topApplications && d.topApplications.length) {
      body.appendChild(h('h3', null, ['Busiest applications this week']));
      body.appendChild(h('p', { class: 'hint' }, ['From the traffic log, by the application and environment on the token each request used.']));
      body.appendChild(table(
        ['Application', 'Environment', { label: 'Requests', num: true }, { label: 'Packages', num: true }, { label: 'Blocked', num: true }],
        d.topApplications.map(function (a) {
          return [a.application, a.environment || '', String(a.requests), String(a.packages), h('span', { class: Number(a.blocked) ? 'deny' : null }, [String(a.blocked)])];
        })
      ));
    }

    body.appendChild(h('h3', null, [
      'Most blocked in the last week',
      can('packages:purge') ? h('small', null, [
        link('clear the list', function () { clearOverview('blocked'); })
      ]) : ''
    ]));
    body.appendChild(table(
      ['Package', { label: 'Blocked', num: true }, ''],
      d.topBlocked.map(function (r) {
        return [
          r.package_name,
          String(r.n),
          can('rules:write') ? link('allow it', function () { quickAllow(r.package_name); }) : ''
        ];
      })
    ));

    body.appendChild(h('h3', null, [
      'Busiest packages',
      can('packages:purge') ? h('small', null, [
        link('clear the counts', function () { clearOverview('busiest'); })
      ]) : ''
    ]));
    body.appendChild(h('p', { class: 'hint' }, [
      'Counted from tarballs served, so metadata a scanner asked for does not show up here.'
    ]));
    body.appendChild(table(
      ['Package', { label: 'Hits', num: true }, { label: 'Blocked', num: true }, 'Last used'],
      d.topPackages.map(function (r) {
        return [r.name, String(r.hits), String(r.blocked_hits), when(r.last_access)];
      })
    ));
  });
}

// ---- the cards. a number only gets a color when there is something to look at

var CARD_LISTS = {
  vulnerable: { perm: 'rules:read', title: 'Packages with known vulnerabilities', page: '#cve', pageLabel: 'Vulnerabilities', extra: 'Fix' },
  malicious: { perm: 'packages:read', title: 'Malicious packages', page: '#quarantine', pageLabel: 'Quarantine', extra: 'Refused' },
  license: { perm: 'packages:read', title: 'License violations', page: '#artifacts', pageLabel: 'Artifacts', extra: 'Note' },
  risky: { perm: 'rules:read', title: 'Vulnerable versions pulled in the last 30 days, worst first', page: '#cve', pageLabel: 'Vulnerabilities', extra: 'Pulled' },
  integrity: { perm: 'packages:read', title: 'Open integrity alerts', page: '#integrity', pageLabel: 'Integrity alerts', extra: 'Seen' },
  waivers: { perm: 'packages:read', title: 'Waivers ending this week, or just ended', page: '#waivers', pageLabel: 'Waivers', extra: 'Ticket' }
};

function plural(n, one, many) {
  return n + ' ' + (n === 1 ? one : many);
}

function dashCards(c, panel) {
  var v = c.vulnerable, m = c.malicious, l = c.license, r = c.risky, i = c.integrity, w = c.waivers;
  return h('div', { class: 'dash-cards' }, [
    dashCard('vulnerable', panel, v.packages, 'Vulnerable packages',
      plural(v.versions, 'version', 'versions') + ', ' + v.serious + ' critical or high' + (v.kev ? ', ' + v.kev + ' known to be exploited (CISA KEV)' : ''),
      v.serious || v.kev ? 'bad' : v.packages ? 'warn' : ''),
    dashCard('malicious', panel, m.packages, 'Malicious packages',
      plural(m.attempts24h, 'install', 'installs') + ' refused in the last 24 hours. ' + m.flaggedPackages + ' flagged by malware scans, ' +
        plural(m.lookalikes, 'lookalike', 'lookalikes') + ', ' + plural(m.killSwitches, 'kill switch', 'kill switches') + '.',
      m.attempts24h ? 'bad' : m.packages ? 'warn' : ''),
    dashCard('license', panel, l.blockedPackages, 'License violations',
      l.reviewPackages + ' more need a license review',
      l.blockedPackages ? 'bad' : l.reviewPackages ? 'warn' : ''),
    dashCard('risky', panel, r.versions, 'Risky packages in use',
      r.versions
        ? (r.applications === undefined ? plural(r.versions, 'vulnerable version was', 'vulnerable versions were') + ' pulled in 30 days'
          : plural(r.applications, 'application', 'applications') + ' pulled a vulnerable version in 30 days') + (r.kev ? ', ' + r.kev + ' of them on CISA KEV' : '')
        : 'no vulnerable version has been pulled in 30 days',
      r.kev ? 'bad' : r.versions ? 'warn' : ''),
    dashCard('integrity', panel, i.open, 'Integrity alerts',
      i.open ? plural(i.packages, 'package', 'packages') + ' changed after they were first seen' : 'every cached file still matches what was first seen',
      i.open ? 'bad' : ''),
    dashCard('waivers', panel, w.ending, 'Waivers ending soon',
      (w.ending ? 'within the next 7 days' : 'none end in the next 7 days') + (w.expired ? ', ' + w.expired + ' ran out in the last 7' : ''),
      w.ending || w.expired ? 'warn' : ''),
    c.bandwidth ? bandwidthCard(c.bandwidth) : null
  ]);
}

// a card opens its list only for a role that can see the page behind it
function dashCard(kind, panel, n, label, sub, tone) {
  var kids = [
    h('span', { class: 'dash-label' }, [label]),
    h('span', { class: 'dash-num' }, [String(n)]),
    h('span', { class: 'dash-sub' }, [sub])
  ];
  var cls = 'dash-card' + (tone ? ' ' + tone : '');
  if (!can(CARD_LISTS[kind].perm)) return h('div', { class: cls }, kids);
  var card = h('button', { type: 'button', class: cls, 'aria-expanded': 'false', 'aria-controls': 'dash-list' }, kids);
  card.addEventListener('click', function () { showCardList(kind, panel, card); });
  return card;
}

function bandwidthCard(b) {
  var perDay = function (n) { return b.averageDays && n !== null ? bytes(n) + ' a day' : ''; };
  var rows = [
    ['Pulled by clients', bytes(b.pulled24h), perDay(b.pulledDailyAverage)],
    ['Fetched from upstream', bytes(b.fetched24h), perDay(b.fetchedDailyAverage)],
    ['Pushed by clients', b.publishing ? bytes(b.pushed24h) : 'publishing is off', b.publishing ? perDay(b.pushedDailyAverage) : '']
  ];
  return h('div', { class: 'dash-card' }, [
    h('span', { class: 'dash-label' }, ['Bandwidth, last 24 hours']),
    h('dl', { class: 'dash-band' }, rows.reduce(function (out, r) {
      return out.concat([h('dt', null, [r[0]]), h('dd', null, [r[1], r[2] ? h('small', null, [r[2]]) : null])]);
    }, [])),
    h('span', { class: 'dash-sub' }, [b.averageDays
      ? 'Daily averages over the last ' + plural(b.averageDays, 'whole day', 'whole days') + '.'
      : 'Daily averages start once there is a whole day of traffic.'])
  ]);
}

function ecoBadge(eco) {
  if (!eco) return h('span', { class: 'eco muted' }, ['any type']);
  return h('span', { class: 'eco' }, [ecoIcon(eco), ecoName(eco)]);
}

function showCardList(kind, panel, card) {
  var spec = CARD_LISTS[kind];
  var again = panel.getAttribute('data-kind') === kind;
  Array.prototype.forEach.call(document.querySelectorAll('.dash-card[aria-expanded]'), function (b) {
    b.setAttribute('aria-expanded', 'false');
  });
  clear(panel);
  panel.removeAttribute('data-kind');
  if (again) return;
  panel.setAttribute('data-kind', kind);
  card.setAttribute('aria-expanded', 'true');
  panel.appendChild(h('p', { class: 'muted' }, ['Loading...']));
  api('GET', '/stats/list/' + kind).then(function (r) {
    // someone clicked another card while this one was loading
    if (panel.getAttribute('data-kind') !== kind) return;
    clear(panel);
    panel.appendChild(h('h3', null, [spec.title, h('small', null, [h('a', { href: spec.page }, ['open ' + spec.pageLabel])])]));
    panel.appendChild(table(
      ['Registry', 'Package', 'Version', 'Why', spec.extra, 'Seen'],
      r.rows.map(function (row) {
        return [ecoBadge(row.ecosystem), row.package, row.version || '', row.why, row.extra || '', when(row.seen)];
      })
    ));
    if (r.rows.length >= r.limit) {
      panel.appendChild(h('p', { class: 'hint' }, ['Showing the first ' + r.limit + '. The ' + spec.pageLabel + ' page has the rest.']));
    }
  }).catch(function (err) {
    if (panel.getAttribute('data-kind') !== kind) return;
    clear(panel);
    panel.appendChild(notice(err.message, 'err'));
  });
}

var CLEAR_OVERVIEW = {
  blocked: {
    path: '/stats/clear-blocked',
    ask: 'Empty the most blocked list?\n\nThe traffic log keeps every line, this only stops the overview counting what was blocked up to now. Anything blocked after this is back on the list.'
  },
  busiest: {
    path: '/stats/clear-busiest',
    ask: 'Reset the package hit counts?\n\nNothing is deleted from the cache and no rule changes. The counts start again from zero, and so does the packages seen figure.'
  }
};

function clearOverview(which) {
  var what = CLEAR_OVERVIEW[which];
  if (!confirm(what.ask)) return;
  api('POST', what.path, {})
    .then(function () { viewDashRefresh(); })
    .catch(function (err) { alert(err.message); });
}

function quickAllow(name) {
  if (!confirm('Add an allow rule for ' + name + '?')) return;
  api('POST', '/rules', { pattern: name, kind: 'allow', note: 'added from the overview' })
    .then(function () { route(); })
    .catch(function (err) { alert(err.message); });
}

export { quickAllow, viewDash };
