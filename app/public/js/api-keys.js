// ForgeRepo portal: Settings, API. keys for other products, the spec downloads, and a page to try calls on.
// Author: Tim Rice

import { h, link } from './dom.js';
import { clear, notice, table, when } from './ui.js';
import { api, download } from './api.js';

function stamp(ts) {
  return ts ? new Date(Number(ts) * 1000).toLocaleString() : 'never';
}

function status(k) {
  if (k.revoked_at) return h('span', { class: 'deny' }, ['revoked ' + when(k.revoked_at) + (k.revoked_by ? ' by ' + k.revoked_by : '')]);
  if (k.expires_ts && Number(k.expires_ts) * 1000 < Date.now()) return h('span', { class: 'deny' }, ['expired']);
  return h('span', { class: 'allow' }, ['active']);
}

// ---------------------------------------------------------------- the keys

function keyForm(d, onDone, existing) {
  var name = h('input', { type: 'text', value: existing ? existing.name : '', placeholder: 'the product that will use it' });
  var cidrs = h('textarea', { rows: '4', spellcheck: 'false', placeholder: '203.0.113.7\n10.20.0.0/16' },
    [existing ? existing.allowed_cidrs.join('\n') : '']);
  var maxPriority = h('input', { type: 'number', min: '-1000', max: '1000', value: existing ? String(existing.max_priority) : '0' });
  var days = h('input', { type: 'number', min: '1', max: '1825', placeholder: 'until revoked' });
  var boxes = d.scopes.map(function (sc) {
    var on = existing ? existing.scopes.indexOf(sc) >= 0 : true;
    return { scope: sc, box: h('input', { type: 'checkbox', checked: on ? 'checked' : null }) };
  });
  var out = h('div', null, []);

  return h('fieldset', null, [
    h('legend', null, [existing ? 'Edit ' + existing.name : 'Make a key']),
    h('div', { class: 'row' }, [
      h('div', null, [h('label', null, ['Name']), name]),
      h('div', null, [h('label', null, ['Highest priority its rules may have']), maxPriority]),
      existing ? null : h('div', null, [h('label', null, ['Key lasts, in days']), days])
    ]),
    h('label', null, ['Scopes']),
    h('div', { class: 'row' }, boxes.map(function (b) { return h('label', null, [b.box, ' ' + b.scope]); })),
    h('label', null, ['Allowed from (required)']), cidrs,
    h('p', { class: 'hint' }, [
      'One address or network per line, in CIDR form. A bare address means just that one (/32, or /128 for IPv6). ' +
      'The key is refused from anywhere else. This browser is coming from ' + (d.your_ip || 'an unknown address') +
      ', add it if you want to try the key on this page.'
    ]),
    h('div', null, [
      h('button', {
        onclick: function () {
          clear(out);
          var body = {
            name: name.value.trim(),
            allowed_cidrs: cidrs.value,
            max_priority: maxPriority.value,
            scopes: boxes.filter(function (b) { return b.box.checked; }).map(function (b) { return b.scope; })
          };
          if (!existing && days.value.trim()) body.expires_in_days = days.value.trim();
          (existing ? api('PATCH', '/api-keys/' + existing.id, body) : api('POST', '/api-keys', body))
            .then(function (r) {
              if (!existing) {
                out.appendChild(notice('Copy this now. It will not be shown again.', 'ok'));
                out.appendChild(h('pre', { class: 'out' }, [r.key]));
                out.appendChild(h('p', { class: 'hint' }, ['Use it like this:']));
                out.appendChild(h('pre', { class: 'out' }, [
                  'curl -X POST ' + location.origin + d.base + '/rules \\\n' +
                  '  -H "Authorization: Bearer ' + r.key + '" \\\n' +
                  '  -H "Content-Type: application/json" \\\n' +
                  '  -d \'{"kind":"whitelist","ecosystem":"npm","pattern":"left-pad","expires":"7d","note":"CHG0012345"}\''
                ]));
                out.appendChild(h('button', { onclick: onDone }, ['Done, I have it']));
              } else {
                onDone();
              }
            })
            .catch(function (e) { out.appendChild(notice(e.message, 'err')); });
        }
      }, [existing ? 'Save changes' : 'Make key']),
      existing ? h('button', { onclick: onDone }, ['Cancel']) : null
    ]),
    out
  ]);
}

function keysPanel(panel, d, redraw) {
  var editBox = h('div', null, []);
  panel.appendChild(h('fieldset', null, [
    h('legend', null, ['API keys']),
    h('p', { class: 'hint' }, [
      'Keys for another product to file temporary whitelist and blacklist rules through the REST API at ' + d.base + '. ' +
      'Only admins see this. A key only sees and changes the rules it made, never the ones people made, ' +
      'and a whitelist rule from the API always expires (a day unless it says otherwise). ' +
      'Revoke a key to stop it straight away, then it can be deleted. The rules it made stay either way.'
    ]),
    table(['Name', 'Key', 'Scopes', 'Allowed from', { label: 'Max priority', num: true }, { label: 'Rules', num: true },
      'Expires', 'Last used', 'Made by', 'Status', ''],
    d.keys.map(function (k) {
      var acts = h('span', { class: 'actions' }, []);
      if (!k.revoked_at) {
        acts.appendChild(link('edit', function () {
          clear(editBox);
          editBox.appendChild(keyForm(d, redraw, k));
          editBox.scrollIntoView({ block: 'nearest' });
        }));
        acts.appendChild(link('revoke', function () {
          if (!confirm('Revoke ' + k.name + '? Anything using it stops working straight away.')) return;
          api('POST', '/api-keys/' + k.id + '/revoke', {}).then(redraw).catch(function (e) { alert(e.message); });
        }, 'deny'));
      } else {
        acts.appendChild(link('delete', function () {
          if (!confirm('Delete the revoked key ' + k.name + '? The ' + k.rule_count + ' rule(s) it made stay.')) return;
          api('DELETE', '/api-keys/' + k.id).then(redraw).catch(function (e) { alert(e.message); });
        }, 'deny'));
      }
      return [
        k.name,
        h('code', null, [k.prefix + '…']),
        k.scopes.join(', '),
        h('span', null, k.allowed_cidrs.map(function (c, i) { return h('div', null, [c]); })),
        String(k.max_priority),
        String(k.rule_count),
        stamp(k.expires_ts),
        k.last_used_at ? when(k.last_used_at) + (k.last_used_ip ? ' from ' + k.last_used_ip : '') : h('span', { class: 'muted' }, ['never']),
        k.created_by || '',
        status(k),
        acts
      ];
    }))
  ]));
  panel.appendChild(editBox);
  panel.appendChild(keyForm(d, redraw, null));
}

// ---------------------------------------------------------------- the spec, and trying it

function specPanel(panel, d) {
  panel.appendChild(h('fieldset', null, [
    h('legend', null, ['Spec']),
    h('p', { class: 'hint' }, [
      'OpenAPI 3 for Swagger and most code generators, and a Postman collection with baseUrl and apiKey variables ready to fill in.'
    ]),
    h('div', null, [
      h('button', { type: 'button', onclick: function () { download('/api-keys/openapi.json', 'forgerepo-openapi.json'); } }, ['Download OpenAPI (Swagger)']),
      h('button', { type: 'button', onclick: function () { download('/api-keys/postman.json', 'forgerepo.postman_collection.json'); } }, ['Download Postman collection'])
    ])
  ]));

  // the key lives in this box and nowhere else, not in storage, not sent to the portal api
  var key = h('input', { type: 'password', placeholder: 'frk_...', autocomplete: 'off' });
  var opPick = h('select', null, d.operations.map(function (op, i) {
    return h('option', { value: String(i) }, [op.method + ' ' + op.path + ' — ' + op.summary]);
  }));
  var params = h('div', null, []);
  var bodyBox = h('textarea', { rows: '8', spellcheck: 'false' }, []);
  var bodyWrap = h('div', null, [h('label', null, ['Body (JSON)']), bodyBox]);
  var result = h('div', null, []);
  var inputs = {};

  function current() { return d.operations[Number(opPick.value)]; }

  function draw() {
    var op = current();
    clear(params);
    inputs = {};
    var fields = [];
    if (op.path.indexOf('{id}') >= 0) fields.push('id');
    fields = fields.concat(op.query);
    if (fields.length) {
      params.appendChild(h('div', { class: 'row' }, fields.map(function (f) {
        inputs[f] = h('input', { type: 'text', placeholder: f === 'id' ? 'rule id (required)' : 'optional' });
        return h('div', null, [h('label', null, [f]), inputs[f]]);
      })));
    }
    bodyWrap.style.display = op.method === 'POST' || op.method === 'PATCH' ? '' : 'none';
    bodyBox.value = op.example ? JSON.stringify(op.example, null, 2) : '';
    params.appendChild(h('p', { class: 'hint' }, [op.scope ? 'Needs the ' + op.scope + ' scope.' : 'Any valid key.']));
  }
  opPick.addEventListener('change', draw);

  function send() {
    var op = current();
    clear(result);
    if (!key.value.trim()) return result.appendChild(notice('Paste a key first.', 'err'));
    var path = op.path;
    if (path.indexOf('{id}') >= 0) {
      var id = inputs.id.value.trim();
      if (!/^\d+$/.test(id)) return result.appendChild(notice('Give the rule id.', 'err'));
      path = path.replace('{id}', id);
    }
    var qs = op.query.filter(function (q) { return inputs[q].value.trim(); })
      .map(function (q) { return encodeURIComponent(q) + '=' + encodeURIComponent(inputs[q].value.trim()); }).join('&');
    var url = d.base + path + (qs ? '?' + qs : '');
    var opts = { method: op.method, credentials: 'omit', headers: { authorization: 'Bearer ' + key.value.trim() } };
    var hasBody = op.method === 'POST' || op.method === 'PATCH';
    if (hasBody) {
      try { JSON.parse(bodyBox.value || '{}'); } catch (e) { return result.appendChild(notice('That body is not valid JSON.', 'err')); }
      opts.headers['content-type'] = 'application/json';
      opts.body = bodyBox.value || '{}';
    }
    var curl = 'curl -X ' + op.method + " '" + location.origin + url + "' \\\n  -H 'Authorization: Bearer <your key>'" +
      (hasBody ? " \\\n  -H 'Content-Type: application/json' \\\n  -d '" + (opts.body || '{}').replace(/'/g, "'\\''") + "'" : '');
    var started = Date.now();
    fetch(url, opts).then(function (res) {
      return res.text().then(function (text) {
        var pretty = text;
        try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (e) { /* not json, show as is */ }
        result.appendChild(h('p', null, [
          h('strong', { class: res.ok ? 'allow' : 'deny' }, [res.status + ' ' + res.statusText]),
          ' in ' + (Date.now() - started) + ' ms' +
          (res.headers.get('ratelimit-remaining') ? ', ' + res.headers.get('ratelimit-remaining') + ' calls left this minute' : '') +
          (res.headers.get('location') ? ', location ' + res.headers.get('location') : '')
        ]));
        result.appendChild(h('pre', { class: 'out' }, [pretty || '(no body)']));
        result.appendChild(h('p', { class: 'hint' }, ['The same call with curl:']));
        result.appendChild(h('pre', { class: 'out' }, [curl]));
      });
    }).catch(function (e) { result.appendChild(notice(e.message, 'err')); });
  }

  panel.appendChild(h('fieldset', null, [
    h('legend', null, ['Try it']),
    h('p', { class: 'hint' }, [
      'Real calls against this box with a real key, so a POST really files a rule. The key stays in this page and is ' +
      'gone when you leave it. It has to allow ' + (d.your_ip || 'this browser\'s address') + ' to work from here.'
    ]),
    h('div', { class: 'row' }, [
      h('div', null, [h('label', null, ['API key']), key]),
      h('div', null, [h('label', null, ['Call']), opPick])
    ]),
    params,
    bodyWrap,
    h('div', null, [h('button', { onclick: send }, ['Send'])]),
    result
  ]));
  draw();
}

function apiPanel(panel) {
  function redraw() {
    clear(panel);
    return api('GET', '/api-keys').then(function (d) {
      keysPanel(panel, d, redraw);
      specPanel(panel, d);
    }).catch(function (e) { panel.appendChild(notice(e.message, 'err')); });
  }
  return redraw();
}

export { apiPanel };
