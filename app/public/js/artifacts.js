// ForgeRepo portal: artifacts.
// Author: Tim Rice

import { state } from './state.js';
import { ecoPkg } from './ecosystems.js';
import { h, link } from './dom.js';
import { bytes, can, clear, notice, pager, table, when } from './ui.js';
import { api, download } from './api.js';
import { section } from './frame.js';
import { route } from './routing.js';

var artifactsPage = 1;
var artifactsFilter = { ecosystem: '', q: '', license: '', property: '', stage: '' };
var STAGES = ['quarantine', 'development', 'test', 'approved', 'production', 'blocked'];

var LICENSE_CLASS = { allowed: 'allow', review: 'warn', blocked: 'deny' };
function licenseCell(expression, verdict, checked) {
  if (!checked) return h('span', { class: 'muted' }, ['-']);
  return h('span', { class: LICENSE_CLASS[verdict] || 'muted', title: verdict || '' }, [expression || 'unknown']);
}

function viewArtifacts(body) {
  var types = state.ecosystems || [];
  if (artifactsFilter.ecosystem && (types.length < 2 || !types.some(function (t) { return t.id === artifactsFilter.ecosystem; }))) {
    artifactsFilter.ecosystem = '';
  }
  var typeName = function (id) {
    var t = types.filter(function (x) { return x.id === id; })[0];
    return t ? t.name : id;
  };
  var query = '?page=' + artifactsPage +
    (artifactsFilter.ecosystem ? '&ecosystem=' + encodeURIComponent(artifactsFilter.ecosystem) : '') +
    (artifactsFilter.q ? '&q=' + encodeURIComponent(artifactsFilter.q) : '') +
    (artifactsFilter.license ? '&license=' + encodeURIComponent(artifactsFilter.license) : '') +
    (artifactsFilter.property ? '&property=' + encodeURIComponent(artifactsFilter.property) : '') +
    (artifactsFilter.stage ? '&stage=' + encodeURIComponent(artifactsFilter.stage) : '');

  return api('GET', '/artifacts' + query).then(function (d) {
    section(body, 'Artifacts', 'Every exact file in the cache, pinned by its SHA-256. The first copy of a file is the one that gets served.');

    body.appendChild(h('p', { class: 'hint' }, [
      d.total + ' file(s) here, ' + bytes(d.bytes) + '. The blob store holds ' + d.blobs.count +
      ' blob(s), ' + bytes(d.blobs.bytes) + ' (identical files are stored once).'
    ]));
    var b = d.backfill;
    if (b && b.running) {
      body.appendChild(notice('Moving files cached by an older version into the blob store: ' +
        b.npm.adopted + ' npm and ' + b.pypi.adopted + ' PyPI so far.', 'info'));
    }

    var type = types.length > 1
      ? h('select', null, [h('option', { value: '' }, ['All'])].concat(types.map(function (t) {
        return h('option', { value: t.id, selected: artifactsFilter.ecosystem === t.id }, [t.name]);
      })))
      : null;
    var q = h('input', { type: 'text', value: artifactsFilter.q, placeholder: 'package, file or sha256' });
    var prop = h('input', { type: 'text', value: artifactsFilter.property, placeholder: 'owner=security, or just owner' });
    var stage = h('select', null, [h('option', { value: '' }, ['Any'])].concat(STAGES.map(function (s) {
      return h('option', { value: s, selected: artifactsFilter.stage === s }, [s]);
    })));
    var lic = h('select', null, [['', 'Any'], ['allowed', 'allowed'], ['review', 'review'], ['blocked', 'blocked'], ['unchecked', 'not read yet']].map(function (o) {
      return h('option', { value: o[0], selected: artifactsFilter.license === o[0] }, [o[1]]);
    }));
    body.appendChild(h('form', {
      class: 'row',
      onsubmit: function (e) {
        e.preventDefault();
        artifactsFilter.ecosystem = type ? type.value : '';
        artifactsFilter.q = q.value.trim();
        artifactsFilter.license = lic.value;
        artifactsFilter.property = prop.value.trim();
        artifactsFilter.stage = stage.value;
        artifactsPage = 1;
        route();
      }
    }, [
      type ? h('div', null, [h('label', null, ['Type']), type]) : null,
      h('div', null, [h('label', null, ['Search']), q]),
      h('div', null, [h('label', null, ['License']), lic]),
      h('div', null, [h('label', null, ['Property']), prop]),
      h('div', null, [h('label', null, ['Stage']), stage]),
      h('div', null, [h('button', { type: 'submit' }, ['Filter'])])
    ]));

    var detail = h('div', null, []);
    body.appendChild(detail);

    var cols = ['Package', 'Version', 'File', 'SHA-256', { label: 'Size', num: true }, 'First seen', { label: 'Downloads', num: true }, 'License', 'Provenance', 'Status'];
    body.appendChild(table(cols, d.artifacts.map(function (a) {
      var row = [
        ecoPkg(a.ecosystem, a.package_name),
        a.version || '',
        // an image blob is named by its digest, all 71 characters of it. short here, whole on hover and in the detail
        h('span', { title: a.filename }, [link(/^sha256:[0-9a-f]{64}$/.test(a.filename) ? a.filename.slice(0, 19) + '...' : a.filename,
          function () { showArtifact(detail, a.id); })]),
        h('span', { class: 'mono', title: a.sha256 }, [a.sha256.slice(0, 12)]),
        bytes(a.size),
        when(a.first_seen),
        String(a.download_count),
        licenseCell(a.license_expression, a.license_verdict, a.license_checked_at),
        provenanceCell(a.provenance_status),
        a.status === 'quarantined' || a.status === 'blocked'
          ? h('a', { href: '#quarantine', class: 'deny' }, [a.status])
          : h('span', { class: a.status === 'approved' ? 'allow' : 'muted' }, [a.status === 'unknown' ? '-' : a.status])
      ];
      return row;
    })));

    body.appendChild(pager(d.page, d.total, d.limit, function (p) { artifactsPage = p; route(); }));
  });
}

var PROVENANCE_WORDS = { VERIFIED: 'verified', PRESENT_UNVERIFIED: 'unverified', MISSING: 'none', INVALID: 'INVALID' };
function provenanceCell(status) {
  if (!status) return h('span', { class: 'muted' }, ['-']);
  var cls = status === 'VERIFIED' ? 'allow' : status === 'INVALID' ? 'deny' : status === 'PRESENT_UNVERIFIED' ? 'warn' : 'muted';
  return h('span', { class: cls, title: status }, [PROVENANCE_WORDS[status] || status]);
}

// key=value metadata on this version or its whole package. approvers and admins set them, anyone who can see the file reads them
function propertiesBox(a, list) {
  var box = h('div', { class: 'properties' }, []);
  var target = function (onVersion) {
    return { ecosystem: a.ecosystem, name: a.package_name, version: onVersion ? (a.version || '') : '' };
  };
  var reload = function () {
    var t = target(true);
    return api('GET', '/properties?ecosystem=' + encodeURIComponent(t.ecosystem) + '&name=' + encodeURIComponent(t.name) + '&version=' + encodeURIComponent(t.version))
      .then(function (r) { draw(r.effective || (r.properties || []).map(function (p) { return Object.assign({ scope: 'package' }, p); })); });
  };
  var send = function (onVersion, change) {
    return api('PUT', '/properties', Object.assign(target(onVersion), change)).then(reload).catch(function (e) { alert(e.message); });
  };
  var draw = function (props) {
    clear(box);
    box.appendChild(h('h3', null, ['Properties']));
    if (!props.length) box.appendChild(h('p', { class: 'hint' }, ['Nothing is set on this version or its package.']));
    else {
      box.appendChild(table(['Property', 'Value', 'On', 'Set', ''], props.map(function (p) {
        return [h('span', { class: 'mono' }, [p.k]), p.v, p.scope === 'version' ? 'this version' : 'every version',
          (p.set_by || '') + ', ' + when(p.set_at),
          can('rules:write') ? link('remove', function () { send(p.scope === 'version', { remove: [p.k] }); }, 'deny') : ''];
      })));
    }
    if (!can('rules:write')) return;
    var key = h('input', { type: 'text', placeholder: 'owner', maxlength: '64' });
    var value = h('input', { type: 'text', placeholder: 'security', maxlength: '255' });
    var wide = h('input', { type: 'checkbox' });
    box.appendChild(h('div', { class: 'row' }, [
      h('div', null, [h('label', null, ['Property']), key]),
      h('div', null, [h('label', null, ['Value']), value]),
      h('div', null, [h('label', null, [wide, ' on every version of the package'])]),
      h('div', null, [h('button', {
        type: 'button',
        onclick: function () {
          if (!key.value.trim() || !value.value.trim()) return alert('A property needs a name and a value.');
          var set = {};
          set[key.value.trim()] = value.value.trim();
          send(!wide.checked, { set: set });
        }
      }, ['Set'])])
    ]));
  };
  draw(list || []);
  return box;
}

// stages are per exact version, so a file with no version has none
function lifecycleBox(a) {
  if (!a.version) return null;
  var box = h('div', { class: 'lifecycle' }, []);
  var target = { ecosystem: a.ecosystem, name: a.package_name, version: a.version };
  var load = function () {
    return api('GET', '/lifecycle?ecosystem=' + encodeURIComponent(target.ecosystem) + '&name=' + encodeURIComponent(target.name) +
      '&version=' + encodeURIComponent(target.version)).then(draw);
  };
  var draw = function (d) {
    clear(box);
    box.appendChild(h('h3', null, ['Lifecycle']));
    box.appendChild(h('p', null, [d.stage
      ? 'Stage: ' + d.stage + ', moved by ' + (d.setBy || 'unknown') + ', ' + when(d.setAt) + (d.reason ? ' - ' + d.reason : '')
      : 'No stage yet.']));
    if (!d.enforcing) box.appendChild(h('p', { class: 'hint' }, ['Stages are only information until lifecycle enforcement is switched on in Settings.']));
    if (d.history.length) {
      box.appendChild(table(['From', 'To', 'Why', 'Who', 'When'], d.history.map(function (x) {
        return [x.from_stage || 'none', x.to_stage, x.reason || '', x.moved_by || '', when(x.moved_at)];
      })));
    }
    if (!d.canMove) return;
    var to = h('select', null, d.stages.filter(function (s) { return s !== d.stage; }).map(function (s) {
      return h('option', { value: s }, [s]);
    }));
    var why = h('input', { type: 'text', placeholder: 'passed QA, CHG-1234', maxlength: '500' });
    box.appendChild(h('div', { class: 'row' }, [
      h('div', null, [h('label', null, ['Move to']), to]),
      h('div', null, [h('label', null, ['Why']), why]),
      h('div', null, [h('button', {
        type: 'button',
        onclick: function () {
          if (!why.value.trim()) return alert('Say why, every move is kept with its reason.');
          api('POST', '/lifecycle/move', Object.assign({ stage: to.value, from: d.stage || '', reason: why.value.trim() }, target))
            .then(load).catch(function (e) { alert(e.message); load(); });
        }
      }, ['Move'])])
    ]));
  };
  load().catch(function (e) { box.appendChild(h('p', { class: 'deny' }, [e.message])); });
  return box;
}

function showArtifact(holder, id) {
  clear(holder);
  return api('GET', '/artifacts/' + id).then(function (d) {
    var a = d.artifact;
    var msg = h('div', null, []);
    var rows = [
      ['Package', ecoPkg(a.ecosystem, a.package_name)],
      ['Version', a.version || ''],
      ['File', h('span', { class: 'mono' }, [a.filename])],
      ['SHA-256', h('span', { class: 'mono' }, [a.sha256])],
      ['Size', bytes(a.size)],
      ['Content type', a.content_type],
      ['Came from', a.upstream || 'unknown'],
      ['First seen', when(a.first_seen)],
      ['Last download', when(a.last_access)],
      ['Downloads', String(a.download_count)],
      ['Blob', d.blob.present
        ? 'on disk' + (d.blob.verifiedAt ? ', bytes last checked ' + when(d.blob.verifiedAt) : '')
        : 'missing, it downloads again next time and has to match the SHA-256 above'],
      ['Same bytes as', d.sharedWith ? d.sharedWith + ' other file(s)' : 'nothing else'],
      ['License', a.license_checked_at
        ? h('span', null, [licenseCell(a.license_expression, a.license_verdict, true), ' (' + a.license_verdict + ')' + (a.license_note ? ' - ' + a.license_note : '')])
        : h('span', { class: 'muted' }, ['not read yet'])]
    ];
    if (a.metadata && a.metadata.integrity) rows.push(['npm integrity', h('span', { class: 'mono' }, [a.metadata.integrity])]);
    var p = d.provenance;
    rows.push(['Provenance', p
      ? h('span', null, [provenanceCell(p.status), ' ' + (p.reason || '') + (p.stale ? ' (checked on an earlier copy, checked again soon)' : '') + ', checked ' + when(p.checked_at)])
      : h('span', { class: 'muted' }, ['not checked yet'])]);
    if (p && p.status === 'VERIFIED') {
      [['Built from', p.source_repository], ['Commit', p.source_commit], ['Ref', p.source_ref], ['Workflow', p.workflow], ['Builder', p.builder],
        ['Identity issuer', p.issuer], ['Attestation covers', p.subject_digest], ['Logged in Rekor', p.verified_at ? when(p.verified_at) : null]]
        .forEach(function (r) { if (r[1]) rows.push([r[0], h('span', { class: 'mono' }, [r[1]])]); });
    }
    if (p && p.registry_signature) rows.push(['npm registry signature', h('span', { class: p.registry_signature === 'VERIFIED' ? 'allow' : p.registry_signature === 'INVALID' ? 'deny' : 'muted' }, [p.registry_signature.toLowerCase().replace('_', ' ')])]);

    var check = can('cache:purge') ? h('button', {
      onclick: function () {
        clear(msg);
        api('POST', '/artifacts/' + a.id + '/verify', {}).then(function (r) {
          msg.appendChild(r.ok
            ? notice('The bytes on disk still hash to their SHA-256.', 'ok')
            : notice('The bytes on disk did not match their SHA-256 (or were gone). The bad copy was removed, a clean one downloads next time.', 'err'));
        }).catch(function (e) { msg.appendChild(notice(e.message, 'err')); });
      }
    }, ['Check the bytes']) : null;
    var reprove = can('cache:purge') ? h('button', {
      onclick: function () {
        clear(msg);
        api('POST', '/artifacts/' + a.id + '/provenance', {}).then(function (r) {
          // redrawn first so the new status shows, then the answer goes on top of it
          return showArtifact(holder, id).then(function () {
            holder.insertBefore(notice('Provenance is ' + r.status + (r.reason ? ': ' + r.reason : '') + '.', r.status === 'INVALID' ? 'err' : r.status === 'VERIFIED' ? 'ok' : 'info'), holder.firstChild);
          });
        }).catch(function (e) { msg.appendChild(notice(e.message, 'err')); });
      }
    }, ['Check provenance']) : null;
    var purge = can('packages:purge') ? h('button', {
      class: 'danger',
      onclick: function () {
        if (!confirm('Purge ' + a.filename + ' from the cache? It downloads again the next time someone asks.')) return;
        api('POST', '/artifacts/' + a.id + '/purge', {}).then(route).catch(function (e) { alert(e.message); });
      }
    }, ['Purge']) : null;

    holder.appendChild(h('fieldset', null, [
      h('legend', null, [a.filename]),
      table(['Field', 'Value'], rows),
      propertiesBox(a, d.properties),
      lifecycleBox(a),
      h('p', null, ['SBOM of this file and what it depends on: ',
        link('CycloneDX', function () { download('/artifacts/' + a.id + '/sbom?format=cyclonedx', a.filename + '.cdx.json'); }), ' or ',
        link('SPDX', function () { download('/artifacts/' + a.id + '/sbom?format=spdx', a.filename + '.spdx.json'); })]),
      d.integrity && d.integrity.length ? h('p', null, [
        h('a', { href: '#integrity', class: d.integrity.some(function (x) { return x.status === 'open'; }) ? 'deny' : null },
          [d.integrity.length + ' integrity alert(s) for this file']),
        ' - latest: ' + (d.integrity[0].kind === 'content' ? 'downloaded bytes' : 'published digest') + ' changed, ' + d.integrity[0].status
      ]) : null,
      d.scans && d.scans.length ? table(['Scanner', 'Verdict', 'Signature', 'Scanned'], d.scans.map(function (sc) {
        var cls = sc.status === 'MALICIOUS' ? 'deny' : sc.status === 'SUSPICIOUS' || sc.status === 'ERROR' ? 'warn' : sc.status === 'CLEAN' ? 'allow' : 'muted';
        return [
          sc.scanner + (sc.scanner_version ? ' ' + sc.scanner_version : ''),
          h('span', { class: cls, title: (sc.findings || []).join('\n') }, [sc.status]),
          sc.signature || '',
          when(sc.scan_time)
        ];
      })) : h('p', { class: 'hint' }, ['Not scanned for malware.']),
      d.holds && d.holds.length ? h('p', null, [
        h('a', { href: '#quarantine', class: d.holds.some(function (x) { return x.status !== 'released'; }) ? 'deny' : null },
          [d.holds.length + ' quarantine hold(s)']),
        ' - latest: ' + d.holds[0].reason + ' (' + d.holds[0].status + ')'
      ]) : null,
      h('div', null, [check, reprove, purge,
        can('cache:purge') ? h('button', {
          onclick: function () {
            var reason = prompt('Hold ' + a.filename + ' in quarantine. Why?', '');
            if (reason === null) return;
            api('POST', '/artifacts/' + a.id + '/hold', { reason: reason })
              .then(function () { showArtifact(holder, a.id); })
              .catch(function (e) { alert(e.message); });
          }
        }, ['Hold']) : null,
        can('cache:purge') ? h('button', {
          onclick: function (e) {
            var btn = e.target;
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            api('POST', '/artifacts/' + a.id + '/scan', {})
              .then(function () { showArtifact(holder, a.id); })
              .catch(function (err) { btn.disabled = false; btn.textContent = 'Scan now'; alert(err.message); });
          }
        }, ['Scan now']) : null, h('button', { onclick: function () { clear(holder); } }, ['Close'])]),
      msg
    ]));
    holder.scrollIntoView({ block: 'nearest' });
  }).catch(function (e) { holder.appendChild(notice(e.message, 'err')); });
}

// open the page already filtered, from another page's link
function showArtifacts(ecosystem, q) {
  artifactsFilter = { ecosystem: ecosystem || '', q: q || '', license: '', property: '', stage: '' };
  artifactsPage = 1;
  window.location.hash = '#artifacts';
}

export { LICENSE_CLASS, viewArtifacts, showArtifacts };
