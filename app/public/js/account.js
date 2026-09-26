// ForgeRepo portal: account.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';
import { clear, notice } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { boot } from './routing.js';

function viewAccount(body) {
  section(body, 'Your account', null);

  body.appendChild(h('dl', { class: 'facts' }, [
    h('dt', null, ['Username']), h('dd', null, [state.me.username]),
    h('dt', null, ['Role']), h('dd', null, [state.me.role]),
    h('dt', null, ['Name']), h('dd', null, [state.me.fullName || 'not set'])
  ]));

  if (state.me.mustChangePassword) {
    body.appendChild(notice('You need to pick a new password before you can do anything else.', 'err'));
  }

  var current = h('input', { type: 'password', autocomplete: 'current-password' });
  var next = h('input', { type: 'password', autocomplete: 'new-password' });
  var again = h('input', { type: 'password', autocomplete: 'new-password' });
  var out = h('div', null, []);

  body.appendChild(h('fieldset', null, [
    h('legend', null, ['Change your password']),
    h('label', null, ['Current password']), current,
    h('label', null, ['New password']), next,
    h('label', null, ['New password again']), again,
    h('p', { class: 'hint' }, ['At least twelve characters, and three of these four: lower case, upper case, numbers, symbols.']),
    h('button', {
      onclick: function () {
        if (next.value !== again.value) {
          clear(out);
          out.appendChild(notice('Those two do not match.', 'err'));
          return;
        }
        api('POST', '/me/password', { current_password: current.value, new_password: next.value })
          .then(function () {
            clear(out);
            out.appendChild(notice('Password changed. Any other sessions you had are signed out.', 'ok'));
            current.value = next.value = again.value = '';
            return boot(true);
          })
          .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
      }
    }, ['Change it'])
  ]));
  body.appendChild(out);
}

export { viewAccount };
