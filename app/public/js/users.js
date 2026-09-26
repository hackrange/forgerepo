// ForgeRepo portal: users.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { can, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { boot, route } from './routing.js';

function viewUsers(body) {
  return api('GET', '/users').then(function (d) {
    section(body, 'Users', 'Roles decide what someone can do. The server checks every time, not just the menu.');

    body.appendChild(h('dl', { class: 'facts' }, [
      h('dt', null, ['viewer']), h('dd', null, ['reads the rules, packages and traffic']),
      h('dt', null, ['developer']), h('dd', null, ['all of the above, plus asks for packages and manages their own tokens']),
      h('dt', null, ['publisher']), h('dd', null, ['a developer who may also publish packages under the reserved names, usually a CI account']),
      h('dt', null, ['approver']), h('dd', null, ['all of the above, plus edits rules and decides on requests']),
      h('dt', null, ['admin']), h('dd', null, ['everything, including users, settings and access control'])
    ]));

    if (can('users:write')) {
      var uname = h('input', { type: 'text', placeholder: 'jsmith' });
      var full = h('input', { type: 'text', placeholder: 'Jane Smith' });
      var email = h('input', { type: 'text', placeholder: 'optional' });
      var pass = h('input', { type: 'password' });
      var role = h('select', null, d.roles.map(function (r) {
        return h('option', { value: r, selected: r === 'developer' }, [r]);
      }));

      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Add someone']),
        h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Username']), uname]),
          h('div', null, [h('label', null, ['Name']), full]),
          h('div', null, [h('label', null, ['Email']), email]),
          h('div', null, [h('label', null, ['Role']), role])
        ]),
        h('p', { class: 'hint' }, [
          'A username can be a plain name or a whole email address. Single sign on names an ' +
          'account after the address the provider sends, so match that shape if you are making ' +
          'one ahead of somebody signing in for the first time.'
        ]),
        h('label', null, ['Password they start with']), pass,
        h('p', { class: 'hint' }, ['They have to change it the first time they sign in.']),
        h('button', {
          onclick: function () {
            api('POST', '/users', {
              username: uname.value.trim(),
              full_name: full.value.trim(),
              email: email.value.trim(),
              password: pass.value,
              role: role.value,
              must_change_password: true
            }).then(route).catch(function (e) { alert(e.message); });
          }
        }, ['Create the account'])
      ]));
    }

    body.appendChild(table(
      ['Username', 'Name', 'Role', 'Status', 'Created', 'Last sign in', 'Actions'],
      d.users.map(function (u) {
        var actions = h('span', { class: 'actions' }, []);
        if (can('users:write')) {
          var picker = h('select', null, d.roles.map(function (r) {
            return h('option', { value: r, selected: r === u.role }, [r]);
          }));
          picker.addEventListener('change', function () {
            api('PATCH', '/users/' + u.id, { role: picker.value }).then(route).catch(function (e) {
              alert(e.message);
              route();
            });
          });
          actions.appendChild(picker);
          actions.appendChild(link(u.disabled ? 'switch on' : 'switch off', function () {
            api('PATCH', '/users/' + u.id, { disabled: !u.disabled }).then(route).catch(function (e) { alert(e.message); });
          }));
          actions.appendChild(link('rename', function () {
            var n = prompt('New username for ' + u.username + '. Their role, tokens and history all stay as they are.', u.username);
            if (n === null) return;
            n = n.trim();
            if (!n || n === u.username) return;
            api('PATCH', '/users/' + u.id, { username: n })
              .then(route)
              .catch(function (e) { alert(e.message); });
          }));
          if (u.locked) {
            actions.appendChild(link('unlock', function () {
              api('PATCH', '/users/' + u.id, { unlock: true }).then(route).catch(function (e) { alert(e.message); });
            }));
          }
          actions.appendChild(link('reset password', function () {
            var p = prompt('New password for ' + u.username + '. They will have to change it again at sign in.');
            if (!p) return;
            api('PATCH', '/users/' + u.id, { password: p, must_change_password: true })
              .then(function () { alert('Done.'); route(); })
              .catch(function (e) { alert(e.message); });
          }));
          if (u.role !== 'admin' && !u.disabled && u.id !== state.me.id && !state.impersonation) {
            actions.appendChild(link('impersonate', function () {
              if (!confirm('Act as ' + u.username + ' (' + u.role + ') for up to 30 minutes?\n\n' +
                'You see and can do exactly what they can. Everything is recorded in the audit trail as you acting as them, ' +
                'and a banner with a Stop button stays on screen the whole time.')) return;
              api('POST', '/users/' + u.id + '/impersonate', {}).then(function () {
                window.location.hash = '#dash';
                return boot();
              }).catch(function (e) { alert(e.message); });
            }));
          }
          actions.appendChild(link('delete', function () {
            if (!confirm('Delete ' + u.username + '?')) return;
            api('DELETE', '/users/' + u.id).then(route).catch(function (e) { alert(e.message); });
          }, 'deny'));
        }
        return [
          u.username,
          u.full_name || '',
          u.role,
          h('span', { class: u.disabled ? 'deny' : 'allow' }, [
            u.disabled ? 'switched off' : u.locked ? 'locked out' : 'active'
          ]),
          when(u.created_at),
          u.last_login_at ? when(u.last_login_at) : 'never',
          actions
        ];
      })
    ));
  });
}

export { viewUsers };
