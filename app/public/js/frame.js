// ForgeRepo portal: frame.
// Author: Tim Rice

import { root, state } from './state.js';
import { h, link } from './dom.js';
import { brandMark, can, clear, notice, svgIcon } from './ui.js';
import { api } from './api.js';
import { boot } from './routing.js';

// Sidebar. folds remembered per browser, links only for roles that can use them (tidiness, not security)
var NAV_GROUPS = [
  { id: 'help', label: 'Help', icon: 'info', items: [
    { id: 'docs', label: 'Documentation', perm: 'requests:read:own', icon: 'info' }
  ] },
  { id: 'security', label: 'Security', icon: 'shield', items: [
    { id: 'dash', label: 'Dashboard', perm: 'rules:read', icon: 'grid' },
    { id: 'killswitch', label: 'Kill switch', perm: 'packages:read', icon: 'alert' },
    { id: 'cve', label: 'Vulnerabilities', perm: 'rules:read', icon: 'alert' },
    { id: 'integrity', label: 'Integrity alerts', perm: 'packages:read', icon: 'shield' },
    { id: 'quarantine', label: 'Quarantine', perm: 'packages:read', icon: 'lines' },
    { id: 'typosquats', label: 'Lookalike packages', perm: 'packages:read', icon: 'alert' },
    { id: 'waivers', label: 'Waivers', perm: 'packages:read', icon: 'ticket' }
  ] },
  { id: 'packages', label: 'Packages', icon: 'cube', items: [
    { id: 'packages', label: 'Packages', perm: 'packages:read', icon: 'box' },
    { id: 'artifacts', label: 'Artifacts', perm: 'packages:read', icon: 'cube' },
    { id: 'requests', label: 'Requests', perm: 'requests:read:own', icon: 'ticket' },
    { id: 'rules', label: 'Rules', perm: 'rules:read', icon: 'funnel' },
    { id: 'dryrun', label: 'Dry run', perm: 'logs:read', icon: 'funnel' },
    { id: 'tools', label: 'Check a package', perm: 'rules:read', icon: 'search' }
  ] },
  { id: 'activity', label: 'Activity', icon: 'clock', items: [
    { id: 'logs', label: 'Traffic', perm: 'logs:read', icon: 'bars' },
    { id: 'consumers', label: 'Consumers', perm: 'logs:read', icon: 'user' },
    { id: 'resolutions', label: 'Resolutions', perm: 'logs:read', icon: 'funnel' },
    { id: 'utilization', label: 'Utilization', perm: 'settings:read', icon: 'grid' },
    { id: 'audit', label: 'Audit trail', perm: 'audit:read', icon: 'lines' }
  ] },
  { id: 'access', label: 'Access', icon: 'key', items: [
    { id: 'tokens', label: 'Tokens', perm: 'tokens:read:own', icon: 'key' },
    { id: 'users', label: 'Users', perm: 'users:read', icon: 'user' },
    { id: 'acl', label: 'Whitelists', perm: 'settings:read', icon: 'globe' }
  ] },
  { id: 'config', label: 'Configuration', icon: 'gear', items: [
    { id: 'integrations', label: 'Integrations', perm: 'settings:read', icon: 'link' },
    { id: 'transfer', label: 'Import and export', perm: 'rules:export', icon: 'swap' },
    { id: 'settings', label: 'Settings', perm: 'settings:read', icon: 'gear' }
  ] }
];

var NAV = [];
NAV_GROUPS.forEach(function (group) { NAV = NAV.concat(group.items); });

// built once, changing page just swaps the content so scroll and folds stay put
var shell = null;
var impersonationTimer = null;

// signing out throws the frame away, it gets built again next time
function forgetShell() {
  shell = null;
}

function stopImpersonationTimer() {
  if (impersonationTimer) {
    clearInterval(impersonationTimer);
    impersonationTimer = null;
  }
}

function shellKey() {
  return [state.me.username, state.me.role, state.perms.join(','), state.registryName,
    state.policyMode, state.auditMode, state.registryMode, state.version,
    state.impersonation ? state.impersonation.by + ' ' + state.impersonation.endsAt : ''].join('\u0000');
}

// acting as someone: a bar that never scrolls away, with the time left and a way out
function impersonationBar(app) {
  if (impersonationTimer) {
    clearInterval(impersonationTimer);
    impersonationTimer = null;
  }
  if (!state.impersonation) return;
  var ends = new Date(state.impersonation.endsAt).getTime();
  var left = h('span', { class: 'left' }, ['']);
  var tick = function () {
    var mins = Math.ceil((ends - Date.now()) / 60000);
    if (mins <= 0) {
      clearInterval(impersonationTimer);
      impersonationTimer = null;
      boot();
      return;
    }
    left.textContent = mins + (mins === 1 ? ' minute' : ' minutes') + ' left.';
  };
  app.classList.add('impersonated');
  app.appendChild(h('div', { class: 'impersonating', role: 'status' }, [
    h('strong', null, ['Acting as ' + state.me.username + ' (' + state.me.role + ')']),
    h('span', null, ['Everything you do is recorded as ' + state.impersonation.by + ' acting as ' + state.me.username + '.']),
    left,
    h('button', {
      type: 'button',
      onclick: function () {
        api('POST', '/impersonate/stop', {}).then(function (r) {
          window.location.hash = r.restored ? '#users' : '';
          return boot();
        }).catch(function (e) { alert(e.message); });
      }
    }, ['Stop'])
  ]));
  tick();
  impersonationTimer = setInterval(tick, 15000);
}

function navRemembered(id) {
  try { return window.localStorage.getItem('forgerepo.nav.' + id); } catch (e) { return null; }
}

function setGroupOpen(group, open, remember) {
  group.button.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (!remember) return;
  try {
    window.localStorage.setItem('forgerepo.nav.' + group.id, open ? 'open' : 'closed');
  } catch (e) { /* private window, fold just isn't remembered. oh well */ }
}

function buildShell() {
  clear(root);
  var links = {};
  var groups = [];
  var sidebar = h('nav', { class: 'sidebar', id: 'sidebar', 'aria-label': 'Main' }, []);

  NAV_GROUPS.forEach(function (g) {
    var items = g.items.filter(function (item) { return can(item.perm); });
    if (!items.length) return;

    var listId = 'nav-' + g.id;
    var button = h('button', { type: 'button', class: 'group-label', 'aria-expanded': 'true', 'aria-controls': listId }, [
      svgIcon(g.icon, 'group-icon'),
      h('span', null, [g.label]),
      svgIcon('chev', 'chev')
    ]);
    var list = h('div', { class: 'group-links', id: listId }, items.map(function (item) {
      links[item.id] = h('a', { href: '#' + item.id }, [svgIcon(item.icon), h('span', null, [item.label])]);
      return links[item.id];
    }));

    var group = { id: g.id, button: button, ids: items.map(function (item) { return item.id; }) };
    button.addEventListener('click', function () {
      setGroupOpen(group, button.getAttribute('aria-expanded') !== 'true', true);
    });
    setGroupOpen(group, navRemembered(g.id) !== 'closed', false);
    groups.push(group);
    sidebar.appendChild(h('div', { class: 'nav-group' }, [button, list]));
  });

  sidebar.appendChild(h('div', { class: 'sidebar-foot' }, ['ForgeRepo ' + (state.version || '')]));

  sidebar.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('a')) sidebar.classList.remove('open');
  });
  var menu = h('button', {
    type: 'button', class: 'btn sm menu-toggle', 'aria-label': 'Menu', 'aria-controls': 'sidebar',
    onclick: function () { sidebar.classList.toggle('open'); }
  }, ['\u2630']);

  var topbar = h('header', { class: 'topbar' }, [
    h('div', { class: 'left' }, [
      menu,
      h('a', { href: '#dash', class: 'brand' }, [brandMark(), h('span', null, [state.registryName || 'ForgeRepo'])])
    ]),
    h('div', { class: 'right' }, [
      h('span', { class: 'badge' + (state.auditMode ? ' pending' : ''), title: 'The policy the registry is running' }, [
        (state.policyMode || '') + ' mode' + (state.auditMode ? ', audit only' : '')
      ]),
      // stays in sight on every page until someone brings it back to normal
      state.registryMode && state.registryMode !== 'normal'
        ? h('a', { href: '#dash', class: 'badge mode-' + state.registryMode, title: 'Registry mode, changed on the dashboard' }, [state.registryMode.toUpperCase()])
        : null,
      h('a', { href: '#docs', class: 'docs-link', title: 'Documentation written for your account' }, ['Docs']),
      h('a', { href: '#account', class: 'who' }, [state.me.username, h('span', { class: 'faint' }, [' (' + state.me.role + ')'])]),
      link('Sign out', function () {
        api('POST', '/logout', {}).then(function () { window.location.reload(); });
      })
    ])
  ]);

  var content = h('div', { class: 'wrap' }, []);
  var app = h('div', { class: 'app' }, [
    topbar,
    h('div', { class: 'layout' }, [sidebar, h('main', { class: 'content', id: 'content' }, [content])])
  ]);
  root.appendChild(app);
  impersonationBar(app);

  shell = { key: shellKey(), sidebar: sidebar, links: links, groups: groups, content: content };
}

function renderFrame(current) {
  if (!shell || shell.key !== shellKey() || !root.contains(shell.content)) buildShell();

  Object.keys(shell.links).forEach(function (id) {
    var a = shell.links[id];
    if (id === current) {
      a.className = 'active';
      a.setAttribute('aria-current', 'page');
    } else {
      a.className = '';
      a.removeAttribute('aria-current');
    }
  });
  // show the current page's fold open, but don't remember it
  shell.groups.forEach(function (group) {
    if (group.ids.indexOf(current) >= 0) setGroupOpen(group, true, false);
  });
  shell.sidebar.classList.remove('open');

  // Each page draws into its own container, so a slow one finishing late scribbles off screen
  // instead of over the next page. ask me how I know.
  clear(shell.content);
  window.scrollTo(0, 0);
  var page = h('div', { class: 'page' }, []);
  shell.content.appendChild(page);
  return page;
}

function show(view, builder) {
  var body = renderFrame(view);
  body.appendChild(h('p', { class: 'muted' }, ['Loading...']));
  Promise.resolve(builder(body)).catch(function (err) {
    clear(body);
    body.appendChild(notice(err.message, 'err'));
  });
}

function section(body, title, hint) {
  clear(body);
  body.appendChild(h('h2', null, [title]));
  if (hint) body.appendChild(h('p', { class: 'hint' }, [hint]));
  return body;
}

export { NAV, forgetShell, renderFrame, section, show, stopImpersonationTimer };
