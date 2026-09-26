// ForgeRepo portal: integrations.
// Author: Tim Rice

import { h, link } from './dom.js';
import { clear, notice, table, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { route } from './routing.js';

var INTEGRATION_KINDS = [['webhook', 'Webhook'], ['splunk_hec', 'Splunk HEC'], ['syslog', 'Syslog']];

function integrationWhere(i) {
  return i.kind === 'syslog' ? i.transport + '://' + i.host + ':' + i.port + ' (' + i.format + ')' : i.url;
}

function viewIntegrations(body) {
  return api('GET', '/integrations').then(function (d) {
    section(body, 'Integrations',
      'Security events sent as they happen to a webhook, Splunk HEC, or syslog (JSON or CEF): packages requested, cached, blocked, quarantined, approved and released, ' +
      'integrity changes, vulnerabilities found and cleared, malware, policy violations, and waivers granted and expired. ' +
      'Events are queued and retried with backoff, so a SIEM that is down never holds up an install. They carry the package, version, hash, user, token name, ' +
      'application, environment and address, and never a password, token or key.');

    if (d.writable) {
      var kind = h('select', null, INTEGRATION_KINDS.map(function (k) { return h('option', { value: k[0] }, [k[1]]); }));
      var name = h('input', { type: 'text', maxlength: '64', placeholder: 'splunk prod' });
      var url = h('input', { type: 'url', maxlength: '512', placeholder: 'https://hooks.example.com/forgerepo' });
      var secret = h('input', { type: 'password', maxlength: '512', autocomplete: 'new-password', placeholder: 'at least 16 characters' });
      var host = h('input', { type: 'text', maxlength: '255', placeholder: 'syslog.internal' });
      var port = h('input', { type: 'number', min: '1', max: '65535', value: '6514' });
      var transport = h('select', null, ['tls', 'tcp', 'udp'].map(function (t) { return h('option', { value: t }, [t]); }));
      var format = h('select', null, [h('option', { value: 'json' }, ['JSON']), h('option', { value: 'cef' }, ['CEF'])]);
      var all = h('input', { type: 'checkbox', checked: 'checked' });
      var boxes = d.events.map(function (e) { return { name: e, box: h('input', { type: 'checkbox' }) }; });
      var picks = h('div', { class: 'row' }, boxes.map(function (b) { return h('label', null, [b.box, b.name]); }));
      var secretHint = h('p', { class: 'hint' }, ['']);
      var out = h('div', null, []);
      var httpRow = h('div', null, [
        h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Address']), url]), h('div', null, [h('label', null, ['Secret']), secret])]),
        secretHint
      ]);
      var syslogRow = h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Host']), host]),
        h('div', null, [h('label', null, ['Port']), port]),
        h('div', null, [h('label', null, ['Transport']), transport]),
        h('div', null, [h('label', null, ['Format']), format])
      ]);
      var show = function () {
        syslogRow.hidden = kind.value !== 'syslog';
        httpRow.hidden = kind.value === 'syslog';
        picks.hidden = all.checked;
        secretHint.textContent = kind.value === 'splunk_hec'
          ? 'The HEC token. The address is the collector, like https://splunk.internal:8088/services/collector/event.'
          : 'Optional. When set, each request carries x-forgerepo-signature: sha256=HMAC of "timestamp.body", with the timestamp in x-forgerepo-timestamp.';
      };
      kind.addEventListener('change', show);
      all.addEventListener('change', show);
      show();
      var add = function () {
        clear(out);
        var chosen = all.checked ? ['*'] : boxes.filter(function (b) { return b.box.checked; }).map(function (b) { return b.name; });
        var payload = { kind: kind.value, name: name.value.trim(), events: chosen };
        if (kind.value === 'syslog') {
          payload.host = host.value.trim(); payload.port = port.value; payload.transport = transport.value; payload.format = format.value;
        } else {
          payload.url = url.value.trim();
          if (secret.value) payload.secret = secret.value;
        }
        api('POST', '/integrations', payload).then(route).catch(function (e) { out.appendChild(notice(e.message, 'err')); });
      };
      body.appendChild(h('fieldset', null, [
        h('legend', null, ['Add an integration']),
        h('div', { class: 'row' }, [h('div', null, [h('label', null, ['Kind']), kind]), h('div', null, [h('label', null, ['Name']), name])]),
        httpRow, syslogRow,
        h('label', null, [all, 'Every event']), picks,
        h('p', { class: 'hint' }, ['Webhooks and Splunk need https. Addresses on this box itself and cloud metadata addresses are refused, private networks are fine. Webhooks never follow redirects.']),
        h('div', null, [h('button', { type: 'button', onclick: add }, ['Add'])]),
        out
      ]));
    }

    var detail = h('div', null, []);
    if (!d.entries.length) {
      body.appendChild(h('p', { class: 'hint' }, ['No integrations yet.']));
    } else {
      body.appendChild(table(['Name', 'Kind', 'Sends to', 'Events', 'Status', { label: 'Waiting', num: true }, { label: 'Failed', num: true }, 'Last delivered', ''], d.entries.map(function (i) {
        var actions = [link('deliveries', function () { integrationDeliveries(detail, i, d.writable); })];
        if (d.writable) {
          actions.push(document.createTextNode(' '));
          actions.push(link('test', function () {
            api('POST', '/integrations/' + i.id + '/test', {}).then(function (r) {
              alert(r.ok ? 'The test event was delivered.' : 'The test event failed: ' + r.error);
              route();
            }).catch(function (e) { alert(e.message); });
          }));
          actions.push(document.createTextNode(' '));
          actions.push(link(i.enabled ? 'disable' : 'enable', function () {
            api('PATCH', '/integrations/' + i.id, { enabled: i.enabled ? '0' : '1' }).then(route).catch(function (e) { alert(e.message); });
          }));
          actions.push(document.createTextNode(' '));
          actions.push(link('delete', function () {
            if (!confirm('Delete ' + i.name + '? Events waiting for it are dropped.')) return;
            api('DELETE', '/integrations/' + i.id).then(route).catch(function (e) { alert(e.message); });
          }, 'deny'));
        }
        var status = !i.enabled ? h('span', { class: 'muted' }, ['disabled'])
          : i.last_status === 'failed' ? h('span', { class: 'deny', title: i.last_error || '' }, ['failing: ' + (i.last_error || '')])
          : i.last_status === 'ok' ? h('span', { class: 'allow' }, ['working']) : h('span', { class: 'muted' }, ['nothing sent yet']);
        return [i.name, (INTEGRATION_KINDS.filter(function (k) { return k[0] === i.kind; })[0] || [0, i.kind])[1],
          h('span', { class: 'mono' }, [integrationWhere(i)]), i.events.indexOf('*') !== -1 ? 'all' : i.events.join(', '),
          status, String(i.pending), String(i.failed), when(i.last_success_at), h('span', { class: 'actions' }, actions)];
      })));
    }
    body.appendChild(detail);
  });
}

function integrationDeliveries(box, i, writable) {
  clear(box);
  api('GET', '/integrations/' + i.id + '/deliveries').then(function (d) {
    box.appendChild(h('h3', null, ['Latest events for ' + i.name]));
    if (writable && i.failed) {
      box.appendChild(h('button', { type: 'button', onclick: function () {
        api('POST', '/integrations/' + i.id + '/retry', {}).then(route).catch(function (e) { alert(e.message); });
      } }, ['Retry the ' + i.failed + ' that gave up']));
    }
    if (!d.entries.length) return box.appendChild(h('p', { class: 'hint' }, ['Nothing has been queued for it yet.']));
    box.appendChild(table(['Event', 'Status', { label: 'Tries', num: true }, 'Queued', 'Delivered', 'Problem'], d.entries.map(function (e) {
      return [e.event_type, e.status, String(e.attempts), when(e.created_at), e.delivered_at ? when(e.delivered_at) : '', e.last_error || ''];
    })));
  }).catch(function (e) { box.appendChild(notice(e.message, 'err')); });
}

export { viewIntegrations };
