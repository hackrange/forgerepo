// ForgeRepo portal: access control.
// Author: Tim Rice

import { h, link } from './dom.js';
import { can, clear, notice, table, tabs, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { route } from './routing.js';

// which whitelist tab was last open, so a redraw after a change stays on it
var whitelistTab = 'portal';

function viewAcl(body) {
  return Promise.all([api('GET', '/acl'), api('GET', '/acl/keys'), api('GET', '/acl/grants'), api('GET', '/registry-acl')])
    .then(function (results) {
      var acl = results[0];
      var keys = results[1];
      var grants = results[2];
      var clients = results[3];
      var writable = can('settings:write');

      section(body, 'Whitelists',
        'Two separate lists. Whitelist Admin Portal decides which networks can reach this portal, Whitelist Clients ' +
        'decides which networks npm and pip can install from. Getting one wrong never changes the other.');
      var tab = tabs(body, whitelistTab, [
        { id: 'portal', label: 'Whitelist Admin Portal' },
        { id: 'clients', label: 'Whitelist Clients' }
      ], function (id) { whitelistTab = id; });

      tab.portal.appendChild(h('p', { class: 'hint' }, [
        'Which networks may reach this portal, and the break glass keys that get you back in from anywhere else. ' +
        'While the filter is off, anyone who can reach this box gets the login page.'
      ]));

      tab.portal.appendChild(notice(
        'You are connecting from ' + acl.yourIp + '. The filter is currently ' + (acl.enabled ? 'on.' : 'off, so every address gets through.'),
        acl.enabled ? 'ok' : ''
      ));

      if (writable) {
        var cidr = h('input', { type: 'text', placeholder: '203.0.113.0/24 or a single address' });
        var label = h('input', { type: 'text', placeholder: 'office, vpn, and so on' });
        tab.portal.appendChild(h('fieldset', null, [
          h('legend', null, ['Allow a network']),
          h('div', { class: 'row' }, [
            h('div', null, [h('label', null, ['Network or address']), cidr]),
            h('div', null, [h('label', null, ['Label']), label])
          ]),
          h('button', {
            onclick: function () {
              api('POST', '/acl', { cidr: cidr.value.trim(), label: label.value.trim() })
                .then(route).catch(function (e) { alert(e.message); });
            }
          }, ['Add it']),
          h('button', {
            onclick: function () {
              api('POST', '/acl', { cidr: acl.yourIp, label: 'added from the portal' })
                .then(route).catch(function (e) { alert(e.message); });
            }
          }, ['Add the address I am on']),
          h('button', {
            class: acl.enabled ? 'danger' : null,
            onclick: function () {
              var turningOn = !acl.enabled;
              if (turningOn && !confirm('Switch the filter on? Make sure your own address is on the list first.')) return;
              api('PUT', '/settings', { acl_enabled: turningOn ? '1' : '0' })
                .then(route).catch(function (e) { alert(e.message); });
            }
          }, [acl.enabled ? 'Switch the filter off' : 'Switch the filter on'])
        ]));
      }

      tab.portal.appendChild(h('h3', null, ['Allowed networks']));
      tab.portal.appendChild(table(['Network', 'Label', 'Status', 'Added by', 'When', ''], acl.acl.map(function (a) {
        return [
          h('span', { class: 'mono' }, [a.cidr]),
          a.label || '',
          h('span', { class: a.enabled ? 'allow' : 'muted' }, [a.enabled ? 'active' : 'off']),
          a.created_by || '',
          when(a.created_at),
          writable ? h('span', { class: 'actions' }, [
            link(a.enabled ? 'disable' : 'enable', function () {
              api('PATCH', '/acl/' + a.id, { enabled: !a.enabled }).then(route).catch(function (e) { alert(e.message); });
            }),
            link('delete', function () {
              if (!confirm('Remove ' + a.cidr + '?')) return;
              api('DELETE', '/acl/' + a.id).then(route).catch(function (e) { alert(e.message); });
            }, 'deny')
          ]) : ''
        ];
      })));

      tab.portal.appendChild(h('h3', null, ['Break glass keys']));
      tab.portal.appendChild(h('p', { class: 'hint' }, [
        'A key is a uuid. From a blocked address the portal is a flat 404, and the only way in is to visit ' +
        '/_admin?bgt=THE-UUID or /admin?bgt=THE-UUID, which grants access from that address for a while. ' +
        'Only the hash is stored, so a lost key cannot be looked up, only replaced.'
      ]));

      if (writable) {
        var klabel = h('input', { type: 'text', placeholder: 'who it is for' });
        var uses = h('input', { type: 'number', value: '1', min: '0', max: '1000' });
        var mins = h('input', { type: 'number', value: '60', min: '5', max: '1440' });
        var kdays = h('input', { type: 'number', value: '90', min: '0', max: '3650' });
        var kout = h('div', null, []);

        tab.portal.appendChild(h('fieldset', null, [
          h('legend', null, ['Make a key']),
          h('div', { class: 'row' }, [
            h('div', null, [h('label', null, ['Label']), klabel]),
            h('div', null, [h('label', null, ['Times it can be used, 0 for unlimited']), uses]),
            h('div', null, [h('label', null, ['Minutes of access it grants']), mins]),
            h('div', null, [h('label', null, ['Days until the key itself expires']), kdays])
          ]),
          h('button', {
            onclick: function () {
              api('POST', '/acl/keys', {
                label: klabel.value.trim(),
                max_uses: uses.value,
                grant_minutes: mins.value,
                expires_days: kdays.value
              }).then(function (r) {
                clear(kout);
                kout.appendChild(notice('Write this down now. It cannot be shown again.', 'ok'));
                kout.appendChild(h('pre', { class: 'out' }, [r.uuid]));
              }).catch(function (e) { alert(e.message); });
            }
          }, ['Make a key'])
        ]));
        tab.portal.appendChild(kout);
      }

      tab.portal.appendChild(table(
        ['Label', 'Starts with', 'Uses', 'Grants', 'Made by', 'Expires', 'Last used', 'Status', ''],
        keys.keys.map(function (k) {
          return [
            k.label,
            h('span', { class: 'mono' }, [k.hint + '...']),
            k.uses + ' of ' + (k.max_uses || 'unlimited'),
            k.grant_minutes + ' min',
            k.created_by || '',
            k.expires_at ? when(k.expires_at) : 'never',
            k.last_used_at ? when(k.last_used_at) + ' from ' + (k.last_used_ip || '?') : 'never',
            h('span', { class: k.status === 'live' ? 'allow' : 'muted' }, [k.status]),
            writable ? link('delete', function () {
              if (!confirm('Delete the key ' + k.label + '?\n\n' +
                'It stops working at once, and anybody it already let in is cut off. ' +
                'This cannot be undone. The audit trail keeps the record.')) return;
              api('DELETE', '/acl/keys/' + k.id).then(route).catch(function (e) { alert(e.message); });
            }, 'deny') : ''
          ];
        })
      ));

      tab.portal.appendChild(h('h3', null, ['Access granted by a key']));
      tab.portal.appendChild(table(['Ref', 'Address', 'Key', 'Started', 'Runs out', 'Status'], grants.grants.map(function (g) {
        return [
          h('span', { class: 'mono' }, [g.id]),
          g.ip,
          g.key_label || 'a deleted key',
          when(g.created_at),
          when(g.expires_at),
          h('span', { class: g.active ? 'allow' : 'muted' }, [g.active ? 'active' : g.revoked ? 'revoked' : 'expired'])
        ];
      })));

      if (writable) {
        tab.portal.appendChild(h('button', {
          class: 'danger',
          onclick: function () {
            if (!confirm('Cut off everyone who got in with a key?')) return;
            api('POST', '/acl/grants/revoke-all', {}).then(route).catch(function (e) { alert(e.message); });
          }
        }, ['Revoke every active grant']));
      }

      // ---- client allow list, its own list and its own switch ----
      var clientBox = h('fieldset', null, []);
      clientBox.appendChild(h('legend', null, ['Registry clients']));

      var tick = h('input', { type: 'checkbox', checked: clients.enabled ? 'checked' : null });
      if (!writable) tick.setAttribute('disabled', 'disabled');
      // saved on its own - switching on with an empty list gets refused, mustn't strand the other fields
      tick.addEventListener('change', function () {
        api('PUT', '/settings', { registry_acl_enabled: tick.checked ? '1' : '0' })
          .then(route)
          .catch(function (e) { tick.checked = !tick.checked; alert(e.message); });
      });

      clientBox.appendChild(h('label', null, [tick, ' Only allow npm clients from the networks below']));
      clientBox.appendChild(h('p', { class: 'hint' }, [
        'This is the registry, not the portal, and it is a separate list from Whitelist Admin Portal. ' +
        'The machines that run installs are rarely the machines you administer from. ' +
        'Blocked clients get a plain 403 saying their network is not accepted, since a developer needs to know why. ' +
        'Getting this wrong cannot lock you out of the portal, so you can always come back and undo it. ' +
        'You are connecting from ' + clients.yourIp + '.'
      ]));
      if (clients.enabled && !clients.acl.filter(function (a) { return a.enabled; }).length &&
          !(clients.github && clients.github.ranges)) {
        clientBox.appendChild(notice('The filter is on but no network is active, so everything is getting through.', ''));
      }

      if (writable) {
        var ccidr = h('input', { type: 'text', placeholder: '10.0.0.0/8 or a single address' });
        var clabel = h('input', { type: 'text', placeholder: 'ci runners, dev vlan, and so on' });
        clientBox.appendChild(h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Network or address']), ccidr]),
          h('div', null, [h('label', null, ['Label']), clabel])
        ]));
        clientBox.appendChild(h('div', null, [
          h('button', {
            onclick: function () {
              api('POST', '/registry-acl', { cidr: ccidr.value.trim(), label: clabel.value.trim() })
                .then(route).catch(function (e) { alert(e.message); });
            }
          }, ['Add it']),
          h('button', {
            onclick: function () {
              api('POST', '/registry-acl', { cidr: clients.yourIp, label: 'added from the portal' })
                .then(route).catch(function (e) { alert(e.message); });
            }
          }, ['Add the address I am on'])
        ]));
      }

      // ---- a token as a way past the list ----
      var tokenTick = h('input', { type: 'checkbox', checked: clients.tokenOk ? 'checked' : null });
      if (!writable) tokenTick.setAttribute('disabled', 'disabled');
      tokenTick.addEventListener('change', function () {
        api('PUT', '/settings', { registry_acl_token_ok: tokenTick.checked ? '1' : '0' })
          .then(route)
          .catch(function (e) { tokenTick.checked = !tokenTick.checked; alert(e.message); });
      });
      clientBox.appendChild(h('label', null, [tokenTick, ' Let a valid token through from any network']));
      clientBox.appendChild(h('p', { class: 'hint' }, [
        'An address is a guess about who is calling and a token is an answer, so a machine holding one issued from ' +
        'this portal gets through wherever it is. A request that sends no token is still judged on its address, so ' +
        'this is worth pairing with Require a token from npm clients, under Settings, Access.'
      ]));

      // ---- github's own ranges, fetched rather than typed ----
      var gh = clients.github || { sections: [], ranges: 0 };
      var ghTick = h('input', { type: 'checkbox', checked: gh.enabled ? 'checked' : null });
      if (!writable) ghTick.setAttribute('disabled', 'disabled');
      ghTick.addEventListener('change', function () {
        api('PUT', '/settings', { registry_acl_github: ghTick.checked ? '1' : '0' })
          .then(function () {
            // saving already kicks off a fetch, wait on that one instead of starting another
            if (!ghTick.checked) return null;
            return api('POST', '/registry-acl/github/refresh', {}).catch(function (e) { alert(e.message); });
          })
          .then(route)
          .catch(function (e) { ghTick.checked = !ghTick.checked; alert(e.message); });
      });
      clientBox.appendChild(h('label', null, [ghTick, ' Allow GitHub SaaS']));
      clientBox.appendChild(h('p', { class: 'hint' }, [
        'GitHub hosted runners have no fixed address, so there is nothing useful to type above. Tick this and the ' +
        'ranges GitHub publish at api.github.com/meta are fetched and kept on this list, rechecked every ' +
        (gh.hours || 24) + ' hours. ' +
        'Read what it buys you before you rely on it: those ranges belong to every GitHub customer, so this says ' +
        'installs may come from GitHub, not that they came from your organization. If that distinction matters, ' +
        'require a token as well.'
      ]));

      if (gh.enabled) {
        var sectionTicks = {};
        clientBox.appendChild(h('div', { class: 'row' }, (gh.sections || []).map(function (sec) {
          var t = h('input', { type: 'checkbox', checked: sec.chosen ? 'checked' : null });
          if (!writable) t.setAttribute('disabled', 'disabled');
          sectionTicks[sec.key] = t;
          t.addEventListener('change', function () {
            var picked = Object.keys(sectionTicks).filter(function (k) { return sectionTicks[k].checked; });
            api('PUT', '/settings', { registry_acl_github_sections: picked.join(',') })
              .then(function () {
                return api('POST', '/registry-acl/github/refresh', {}).catch(function (e) { alert(e.message); });
              })
              .then(route)
              .catch(function (e) { t.checked = !t.checked; alert(e.message); });
          });
          return h('div', null, [
            h('label', null, [t, ' ' + sec.label + (sec.ranges ? ' (' + sec.ranges + ')' : '')]),
            h('p', { class: 'hint' }, [sec.note])
          ]);
        })));

        clientBox.appendChild(h('p', { class: 'hint' }, [
          gh.ranges
            ? gh.ranges + ' network(s) fetched from GitHub, last changed ' + when(gh.syncedAt) +
              ', last checked ' + when(gh.checkedAt) + '.'
            : 'Nothing fetched yet. Until something is, these ranges allow nobody and nothing is blocked on their account.'
        ]));
        if (gh.error) clientBox.appendChild(notice('The last fetch did not work: ' + gh.error, 'err'));

        if (writable) {
          var ghHours = h('input', { type: 'number', value: gh.hours === undefined ? 24 : gh.hours });
          ghHours.addEventListener('change', function () {
            api('PUT', '/settings', { registry_acl_github_hours: ghHours.value })
              .then(route)
              .catch(function (e) { alert(e.message); });
          });
          clientBox.appendChild(h('div', null, [
            h('label', null, ['Hours between rechecks']),
            ghHours,
            h('p', { class: 'hint' }, ['0 stops the rechecks and leaves the ranges as they are.'])
          ]));

          var ghOut = h('span', { class: 'muted' }, ['']);
          clientBox.appendChild(h('div', null, [
            h('button', {
              onclick: function () {
                ghOut.textContent = ' fetching...';
                api('POST', '/registry-acl/github/refresh', {})
                  .then(route)
                  .catch(function (e) { ghOut.textContent = ''; alert(e.message); });
              }
            }, ['Fetch them now']),
            ghOut
          ]));
        }
      }

      clientBox.appendChild(table(['Network', 'Label', 'Status', 'Added by', ''], clients.acl.map(function (a) {
        return [
          h('span', { class: 'mono' }, [a.cidr]),
          a.label || '',
          h('span', { class: a.enabled ? 'allow' : 'muted' }, [a.enabled ? 'active' : 'off']),
          a.created_by || '',
          writable ? h('span', { class: 'actions' }, [
            link(a.enabled ? 'disable' : 'enable', function () {
              api('PATCH', '/registry-acl/' + a.id, { enabled: !a.enabled })
                .then(route).catch(function (e) { alert(e.message); });
            }),
            link('delete', function () {
              if (!confirm('Remove ' + a.cidr + ' from the client list?')) return;
              api('DELETE', '/registry-acl/' + a.id).then(route).catch(function (e) { alert(e.message); });
            }, 'deny')
          ]) : ''
        ];
      })));
      tab.clients.appendChild(clientBox);
    });
}

export { viewAcl };
