// ForgeRepo portal: tokens.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { can, clear, notice, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { labelOptions, unassigned } from './labels.js';
import { route } from './routing.js';

function viewTokens(body) {
  var all = can('tokens:read:all');
  var canToggle = can('settings:write');
  // the settings read is admin only, so only ask when they can act on it
  return Promise.all([
    api('GET', '/tokens' + (all ? '?all=1' : '')),
    canToggle ? api('GET', '/settings') : Promise.resolve(null),
    api('GET', '/applications'),
    api('GET', '/environments')
  ]).then(function (results) {
    var d = results[0];
    var requireAuth = results[1] ? String(results[1].settings.require_auth) === '1' : false;
    var apps = results[2].entries;
    var envs = results[3].entries;

    section(body, 'Registry tokens',
      'These go in a developer .npmrc. A token is shown once when you make it and never again.');

    // same switch as Settings, handy here. only drawn for people who can flip it
    if (canToggle) {
      var toggle = h('input', { type: 'checkbox', checked: requireAuth ? 'checked' : null });
      var toggleOut = h('div', null, []);

      toggle.addEventListener('change', function () {
        var wanted = toggle.checked;
        if (wanted && !confirm('Turn on token checks? Any npm client without a token stops working straight away, including CI.')) {
          toggle.checked = false;
          return;
        }
        api('PUT', '/settings', { require_auth: wanted ? '1' : '0' })
          .then(function () {
            clear(toggleOut);
            toggleOut.appendChild(notice(
              wanted
                ? 'Token checks are on. Every npm client needs a token from this page now.'
                : 'Token checks are off. Anyone who can reach the registry can pull approved packages.',
              'ok'
            ));
          })
          .catch(function (e) {
            toggle.checked = !wanted;
            clear(toggleOut);
            toggleOut.appendChild(notice(e.message, 'err'));
          });
      });

      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Who can pull packages']),
        h('label', null, [toggle, 'Require tokens']),
        h('p', { class: 'hint' }, [
          requireAuth
            ? 'On right now. An npm client without a valid token gets a 401, whatever the rules say about the package.'
            : 'Off right now. Anyone who can reach this registry can pull anything the rules allow, no token needed. ' +
              'That is usually fine when only your own network can reach it.'
        ])
      ]));
      body.appendChild(toggleOut);
    }

    var name = h('input', { type: 'text', placeholder: 'laptop, ci runner, and so on' });
    var days = h('input', { type: 'number', value: '365', min: '0', max: '3650' });
    var tokenEmail = h('input', { type: 'text', placeholder: 'builds@example.com' });
    // rules can be scoped by these, so only an admin decides where a token belongs
    var labelsWritable = can('settings:write');
    var newApp = labelsWritable ? h('select', null, labelOptions(apps, null)) : null;
    var newEnv = labelsWritable ? h('select', null, labelOptions(envs, null)) : null;
    var out = h('div', null, []);

    body.appendChild(h('fieldset', null, [
      h('legend', null, ['New token']),
      h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['What is it for']), name]),
        h('div', null, [h('label', null, ['Days until it expires, 0 for never']), days]),
        h('div', null, [h('label', null, ['Who to write to about it']), tokenEmail])
      ]),
      labelsWritable ? h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Application']), newApp]),
        h('div', null, [h('label', null, ['Environment']), newEnv])
      ]) : h('p', { class: 'hint' }, [
        'An admin puts a token in an application and environment, since rules can be scoped by them. ' +
        'Make the token, then ask an admin to set where it belongs.'
      ]),
      h('p', { class: 'hint' }, [
        'The application and environment go onto every request this token makes, so the traffic log can say ' +
        'where a package landed. That is the answer you want ready before a version turns out to be malicious, ' +
        'not after. One token per application per environment is what makes it worth having: a token shared ' +
        'across two applications can only ever name one of them. The lists are kept in Settings by an admin.'
      ]),
      h('p', { class: 'hint' }, [
        'The address is optional and is worth setting on a shared build token. When an install using this ' +
        'token gets blocked, the digest about what happened to it goes there rather than to whoever made ' +
        'the token. Leave it empty and it goes to your own account address.'
      ]),
      h('button', {
        onclick: function () {
          api('POST', '/tokens', {
            name: name.value.trim(),
            expires_days: days.value,
            email: tokenEmail.value.trim(),
            application_id: newApp ? newApp.value : '',
            environment_id: newEnv ? newEnv.value : ''
          })
            .then(function (r) {
              clear(out);
              out.appendChild(notice('Copy this now. It will not be shown again.', 'ok'));
              out.appendChild(h('pre', { class: 'out' }, [r.token]));
              out.appendChild(h('p', { class: 'hint' }, ['Set it up with:']));
              out.appendChild(h('pre', { class: 'out' }, [
                'npm config set registry ' + window.location.origin + '/\n' +
                'npm config set //' + window.location.host + '/:_authToken ' + r.token
              ]));
              if ((state.ecosystems || []).some(function (t) { return t.id === 'pypi'; })) {
                out.appendChild(h('p', { class: 'hint' }, ['For pip, and for uv and poetry, the token goes in the index address:']));
                out.appendChild(h('pre', { class: 'out' }, [
                  'pip config set global.index-url ' + window.location.protocol + '//__token__:' + r.token + '@' +
                  window.location.host + '/pypi/simple/'
                ]));
              }
              if ((state.ecosystems || []).some(function (t) { return t.id === 'oci'; })) {
                out.appendChild(h('p', { class: 'hint' }, ['For docker, podman or skopeo, the token is the password:']));
                out.appendChild(h('pre', { class: 'out' }, [
                  'docker login ' + window.location.host + ' --username ' + (state.me && state.me.username ? state.me.username : 'you') + ' --password-stdin <<< ' + r.token + '\n' +
                  'docker pull ' + window.location.host + '/nginx:latest'
                ]));
              }
              // wipe the token after 30s, but only if this page is still the one showing
              setTimeout(function () { if (out.isConnected) route(); }, 30000);
            })
            .catch(function (e) { alert(e.message); });
        }
      }, ['Make one'])
    ]));
    body.appendChild(out);

    var cols = ['Name', 'Application', 'Environment', 'Write to', 'Starts with', 'Made', 'Expires',
      'Last used', 'Status', ''];
    if (all) cols.splice(1, 0, 'Owner');

    // moving a token only affects future traffic, old rows keep the name copied at the time
    function picker(t, field, entries, currentId) {
      if (t.revoked || !labelsWritable) {
        return t[field] ? h('span', null, [t[field]]) : unassigned();
      }
      var select = h('select', null, labelOptions(entries, currentId));
      select.addEventListener('change', function () {
        var payload = {};
        payload[field + '_id'] = select.value;
        api('PUT', '/tokens/' + t.id, payload).then(route).catch(function (e) {
          alert(e.message);
          route();
        });
      });
      return select;
    }

    body.appendChild(table(cols, d.tokens.map(function (t) {
      // contact is the only thing worth changing, the token itself lives in someone's .npmrc
      var contact = t.revoked
        ? h('span', { class: 'muted' }, [t.email || ''])
        : link(t.email || 'set an address', function () {
          var next = prompt('Where should mail about the ' + t.name + ' token go? Empty sends it to the account instead.', t.email || '');
          if (next === null) return;
          api('PUT', '/tokens/' + t.id, { email: next.trim() }).then(route).catch(function (e) { alert(e.message); });
        }, t.email ? null : 'muted');

      var row = [
        t.name,
        picker(t, 'application', apps, t.application_id),
        picker(t, 'environment', envs, t.environment_id),
        contact,
        h('span', { class: 'mono' }, [t.prefix + '...']),
        when(t.created_at),
        t.expires_at ? when(t.expires_at) : 'never',
        t.last_used_at ? when(t.last_used_at) + ' from ' + (t.last_used_ip || '?') : 'never used',
        h('span', { class: t.revoked ? 'deny' : 'allow' }, [t.revoked ? 'revoked' : 'live']),
        t.revoked ? '' : link('revoke', function () {
          if (!confirm('Revoke ' + t.name + '? Anything using it stops working straight away.')) return;
          api('DELETE', '/tokens/' + t.id).then(route).catch(function (e) { alert(e.message); });
        }, 'deny')
      ];
      if (all) row.splice(1, 0, t.username || '');
      return row;
    })));
  });
}

export { viewTokens };
