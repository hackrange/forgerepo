// ForgeRepo portal: login.
// Author: Tim Rice

import { root, state } from './state.js';
import { h } from './dom.js';
import { brandMark, clear, notice, setTitle, svgIcon } from './ui.js';
import { api } from './api.js';
import { forgetShell } from './frame.js';
import { boot } from './routing.js';

// What sign in offers comes from the server, never guessed. Guessing used to draw a
// password form on provider-only boxes that could only ever say no.
function showLogin(message) {
  state.me = null;
  forgetShell();
  return fetch('/_api/me', { credentials: 'same-origin' })
    .then(function (res) {
      if (!res.ok) throw new Error('the server said ' + res.status);
      return res.json();
    })
    .then(function (d) {
      // signed in after all, in another tab. surprise
      if (d && d.loggedIn) return boot();
      if (!d || !d.sso) throw new Error('the server did not say how to sign in');
      state.sso = d.sso;
      state.registryName = d.registryName;
      state.brandIcon = d.brandIcon;
      setTitle();
      renderLogin(message, d.sso);
    })
    .catch(function (err) { renderUnreachable(err); });
}

function loginBox(kids) {
  clear(root);
  forgetShell();
  root.appendChild(h('div', { class: 'login-wrap' }, [
    h('div', { class: 'login-box' }, [
      h('div', { class: 'brand' }, [brandMark(), h('span', null, [state.registryName || 'ForgeRepo'])]),
      h('div', { class: 'sub' }, ['Package registry management'])
    ].concat(kids))
  ]));
}

function renderUnreachable(err) {
  loginBox([
    notice('Could not reach the server to find out how to sign in' + (err && err.message ? ', ' + err.message : '') + '.', 'err'),
    h('button', { type: 'button', class: 'primary', onclick: function () { showLogin(); } }, ['Try again'])
  ]);
}

function renderLogin(message, sso) {
  if (!sso) return showLogin(message);

  // provider reports errors via the hash, only way it can
  var hash = window.location.hash || '';
  var failed = hash.indexOf('sso_error=') >= 0
    ? decodeURIComponent(hash.slice(hash.indexOf('sso_error=') + 10).split('&')[0])
    : null;
  if (failed) window.location.hash = '';

  var user = h('input', { type: 'text', id: 'u', autocomplete: 'username', autofocus: 'autofocus' });
  var pass = h('input', { type: 'password', id: 'p', autocomplete: 'current-password' });
  var msg = h('div', null, [
    message ? notice(message, 'err') : '',
    failed ? notice('Single sign on did not work: ' + failed, 'err') : ''
  ]);

  var form = h('form', {
    onsubmit: function (e) {
      e.preventDefault();
      api('POST', '/login', { username: user.value, password: pass.value })
        .then(function (data) {
          state.csrf = data.csrf;
          return boot();
        })
        .catch(function (err) {
          clear(msg);
          msg.appendChild(notice(err.message, 'err'));
          pass.value = '';
          pass.focus();
        });
    }
  }, [
    h('label', { for: 'u' }, ['Username']), user,
    h('label', { for: 'p' }, ['Password']), pass,
    h('button', { type: 'submit', class: 'primary' }, ['Sign in'])
  ]);

  // plain link not fetch, the browser itself has to reach the provider
  var ssoButton = sso.enabled
    ? h('a', { href: '/_api/sso/login', class: 'btn primary' }, [svgIcon('shield'), h('span', null, [sso.label || 'Sign in with SSO'])])
    : null;

  loginBox([
    msg,
    ssoButton,
    sso.enabled && sso.passwordAllowed ? h('div', { class: 'login-divider' }, ['or with an account on this box']) : null,
    sso.passwordAllowed ? form : null
  ]);
  if (sso.passwordAllowed) user.focus();
}

export { renderLogin, renderUnreachable, showLogin };
