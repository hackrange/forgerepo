// ForgeRepo portal: api.
// Author: Tim Rice

import { state } from './state.js';
import { h } from './dom.js';
import { showLogin } from './login.js';

function api(method, path, body) {
  var opts = { method: method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (state.csrf) opts.headers['x-csrf-token'] = state.csrf;

  return fetch('/_api' + path, opts).then(function (res) {
    if (res.status === 204) return {};
    return res.json().catch(function () { return {}; }).then(function (data) {
      // session ran out. the login form handles its own 401, don't eat the username they just typed
      if (res.status === 401 && path !== '/login') {
        showLogin(data.error);
        throw new Error(data.error || 'log in again');
      }
      if (res.status === 403 && data.mustChangePassword) {
        window.location.hash = '#account';
        throw new Error(data.error);
      }
      if (!res.ok) throw new Error(data.error || 'that did not work (' + res.status + ')');
      return data;
    });
  });
}

// like download(), but posts something first (the reviewed file only exists in this browser)
function downloadPost(path, body, filename) {
  var opts = {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' }
  };
  if (state.csrf) opts.headers['x-csrf-token'] = state.csrf;
  opts.body = JSON.stringify(body);

  return fetch('/_api' + path, opts)
    .then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () { return {}; }).then(function (d) {
          throw new Error(d.error || 'export failed');
        });
      }
      return res.blob();
    })
    .then(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = h('a', { href: url, download: filename });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    })
    .catch(function (err) { alert(err.message); });
}

function download(path, filename) {
  fetch('/_api' + path, { credentials: 'same-origin' })
    .then(function (res) {
      if (!res.ok) throw new Error('export failed');
      return res.blob();
    })
    .then(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = h('a', { href: url, download: filename });
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    })
    .catch(function (err) { alert(err.message); });
}

export { api, download, downloadPost };
