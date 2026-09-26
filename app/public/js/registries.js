// ForgeRepo portal: upstream registries, drawn inside Settings > Registries.
// Author: Tim Rice

import { h, link } from './dom.js';
import { clear, notice, table } from './ui.js';
import { api } from './api.js';
import { ecoHints, ecoName, ecoSelect } from './ecosystems.js';

// One default registry plus a row per pattern owner.
// Tokens are write only: stars back when set, stars sent up = leave it alone, empty clears it.
var TOKEN_STARS = '********';

// rows save as they're edited, so only this box redraws and unsaved settings fields stay put
function upstreamsPanel(box) {
  var reload = function () { return upstreamsPanel(box); };
  var failed = function (e) { alert(e.message); };
  return api('GET', '/upstreams').then(function (d) {
    clear(box);
    box.appendChild(h('p', { class: 'hint' }, [
      'Where packages are pulled from. Every registry can have its own token. ' +
      'The default takes everything no pattern claims. Add a registry with a pattern like ',
      h('span', { class: 'mono' }, ['@acme/*']),
      ', and every package matching it comes from there and only from there. First match wins, ' +
      'an exact name beats a glob, and a longer glob beats a shorter one, so the order you add ' +
      'them in never decides anything.'
    ]));
    box.appendChild(h('p', { class: 'hint' }, [
      'It is patterns rather than asking each registry in turn on purpose. Asking around until ' +
      'somebody answers is how dependency confusion works: a package published on the public ' +
      'registry under one of your supplier names answers first and wins. A pattern means that ' +
      'scope can only ever come from the registry written against it.'
    ]));
    box.appendChild(h('p', { class: 'hint' }, [
      'Everything cached remembers which registry it came from. A copy from a registry that no ' +
      'longer serves that name is never handed out, it is fetched again from wherever the name ' +
      'points now, so adding or removing one needs no cache purge.'
    ]));

    // ---- add ----
    if (d.writable) {
      var name = h('input', { type: 'text', placeholder: 'what to call it' });
      var url = h('input', { type: 'text', placeholder: ecoHints('npm').url });
      var pattern = h('input', { type: 'text', placeholder: ecoHints('npm').pattern });
      var token = h('input', { type: 'password', placeholder: 'only if it wants auth', autocomplete: 'new-password' });
      var out = h('div', null, []);

      // a mirror type (RPM) has no pattern: each one is a whole repository at its own address, with two options
      var mirrors = d.mirrors || {};
      // only drawn when a mirror type is switched on, a box with npm alone looks the way it always did
      var anyMirror = (d.ecosystems || []).some(function (e) { return !!mirrors[e.id]; });
      var filtered = h('input', { type: 'checkbox' });
      var feed = h('select', null, []);
      var mirrorBox = !anyMirror ? null : h('div', { class: 'row' }, [
        h('div', null, [h('label', null, [filtered, ' Filtered index']), h('p', { class: 'hint' }, [
          'Off: the index goes out as the distro signed it, and each download is checked. On: the index lists only what the rules allow, and clients have to turn off checking the index signature (repo_gpgcheck=0). Package signatures are checked either way.'
        ])]),
        h('div', null, [h('label', null, ['Advisories from']), feed])
      ]);
      var tokenHint = h('p', { class: 'hint' }, ['']);
      // type picker only with more than one type, npm-only boxes look like they always did
      var typeHint = h('p', { class: 'hint' }, []);
      var hints = function () {
        var eco = type ? type.value : 'npm';
        var hasDefault = (d.defaults || []).indexOf(eco) >= 0;
        url.setAttribute('placeholder', ecoHints(eco).url);
        token.setAttribute('placeholder', eco === 'oci' ? 'username:access-token, if it wants a login' : 'only if it wants auth');
        tokenHint.textContent = eco === 'oci'
          ? 'For an image registry, write the token as username:access-token, for example your Docker Hub user name and a personal access token. It is sent as a login to that registry only. '
            + 'It is never shown again once saved, and never leaves this box in an export.'
          : 'The token is sent as a bearer credential to that registry only. It is never shown again once saved, and never leaves this box in an export.';
        pattern.setAttribute('placeholder', hasDefault ? ecoHints(eco).pattern : 'empty makes it the ' + ecoName(eco) + ' default');
        // swift publishes no checksums, so there is nothing to require
        if (eco === 'swift') addHash.value = '';
        addHash.disabled = eco === 'swift';
        clear(typeHint);
        var isMirror = !!mirrors[eco];
        patternCell.style.display = isMirror ? 'none' : '';
        if (mirrorBox) mirrorBox.style.display = isMirror ? '' : 'none';
        if (isMirror) {
          clear(feed);
          feed.appendChild(h('option', { value: '' }, ['none']));
          mirrors[eco].forEach(function (f) { feed.appendChild(h('option', { value: f }, [f])); });
          typeHint.appendChild(document.createTextNode('A ' + ecoName(eco) + ' mirror is one distro repository, its address is the folder that holds repodata/, like ' +
            ecoHints(eco).url + '. Clients reach it at /' + eco + '/<its name>/. In whitelist mode, add an allow rule of * for ' + ecoName(eco) +
            ' and then deny or kill what you do not want. Pick the advisory feed of its distro so its packages are checked against the right advisories.'));
        } else if (eco !== 'npm') {
          typeHint.appendChild(document.createTextNode('A ' + ecoName(eco) + ' registry only ever serves ' +
            ecoName(eco) + ' packages, and rules and registries for other types never apply to it. ' + (hasDefault
            ? 'Give it a pattern like ' + ecoHints(eco).pattern + ' and those come from here instead of the ' + ecoName(eco) + ' default.'
            : 'There is no ' + ecoName(eco) + ' default yet, so leaving the pattern empty makes this the registry every one of them comes from.')));
        }
      };
      var addHash = h('select', null, [
        h('option', { value: '' }, ['what this kind does by default']),
        h('option', { value: '1' }, ['required']),
        h('option', { value: '0' }, ['not required'])
      ]);
      var patternCell = h('div', null, [h('label', null, ['Pattern']), pattern]);
      var type = ecoSelect(d.ecosystems, { label: true, onchange: hints });
      hints();

      box.appendChild(h('fieldset', null, [
        h('legend', null, ['Add a registry']),
        h('div', { class: 'row' }, [
          type ? h('div', null, [h('label', null, ['Type']), type]) : null,
          h('div', null, [h('label', null, ['Name']), name]),
          h('div', null, [h('label', null, ['Checksums']), addHash]),
          h('div', null, [h('label', null, ['Address']), url]),
          patternCell,
          h('div', null, [h('label', null, ['Token']), token])
        ]),
        mirrorBox,
        typeHint,
        tokenHint,
        h('button', {
          type: 'button',
          onclick: function () {
            api('POST', '/upstreams', {
              ecosystem: type ? type.value : 'npm',
              name: name.value.trim(),
              url: url.value.trim(),
              pattern: mirrors[type ? type.value : 'npm'] ? '' : pattern.value.trim(),
              token: token.value,
              options: (function () {
          var o = mirrors[type ? type.value : 'npm'] ? { filtered: filtered.checked, advisories: feed.value } : {};
          if (addHash.value !== '') o.requireHash = addHash.value === '1';
          return o;
        }())
            }).then(function (r) {
              if (r && r.note) alert(r.note);
              reload();
            }).catch(function (e) {
              clear(out);
              out.appendChild(notice(e.message, 'err'));
            });
          }
        }, ['Add registry']),
        out
      ]));
    }

    // ---- the list, editable in place ----
    var labels = d.labels || {};
    var showType = (d.ecosystems || []).length > 1 ||
      d.upstreams.some(function (u) { return u.ecosystem && u.ecosystem !== 'npm'; });

    var rows = d.upstreams.map(function (u) {
      var url = h('input', { type: 'text', value: u.url });
      var pattern = h('input', {
        type: 'text',
        value: u.is_default ? '' : u.pattern,
        placeholder: u.is_default ? 'everything else' : ecoHints(u.ecosystem).pattern
      });
      var priority = h('input', { type: 'number', value: String(u.priority) });
      var token = h('input', {
        type: 'password',
        value: u.has_token ? TOKEN_STARS : '',
        placeholder: u.has_token ? '' : 'none set',
        autocomplete: 'new-password'
      });
      // the default claims whatever is left over, so it never gets a pattern
      if (u.is_default) pattern.setAttribute('disabled', 'disabled');
      // a mirror has its address where others have a pattern, and its options
      var mirrorFeeds = (d.mirrors || {})[u.ecosystem];
      var rowFiltered = h('input', { type: 'checkbox', checked: !!(u.options && u.options.filtered) });
      var rowFeed = h('select', null, [h('option', { value: '' }, ['no advisories'])].concat((mirrorFeeds || []).map(function (f) {
        return h('option', { value: f, selected: !!(u.options && u.options.advisories === f) }, [f]);
      })));
      // a file with no published checksum can not be checked against anything. some kinds publish one for
      // everything, some have nothing to offer, so the default is the kind's and this says otherwise
      var chosen = u.options && typeof u.options.requireHash === 'boolean';
      var rowHash = u.ecosystem === 'swift' ? h('select', { disabled: 'disabled' }, [
        h('option', { value: '', selected: true }, ['no checksums for Swift'])
      ]) : h('select', null, [
        h('option', { value: '', selected: !chosen }, [u.hash_expected ? 'checksum required (default)' : 'checksum not required (default)']),
        h('option', { value: '1', selected: chosen && u.options.requireHash === true }, ['checksum required']),
        h('option', { value: '0', selected: chosen && u.options.requireHash === false }, ['checksum not required'])
      ]);
      if (!d.writable) [rowFiltered, rowFeed, rowHash].forEach(function (i) { i.setAttribute('disabled', 'disabled'); });
      if (!d.writable) {
        [url, pattern, priority, token].forEach(function (i) { i.setAttribute('disabled', 'disabled'); });
      }

      function save() {
        var payload = { url: url.value.trim(), priority: priority.value };
        var opts = mirrorFeeds ? { filtered: rowFiltered.checked, advisories: rowFeed.value } : {};
        if (rowHash.value !== '') opts.requireHash = rowHash.value === '1';
        payload.options = opts;
        if (!mirrorFeeds && !u.is_default) payload.pattern = pattern.value.trim();
        if (u.hash_expected && rowHash.value === '0' && !confirm(
          u.name + ' publishes a checksum for every file it serves. Without that check a file that was swapped on '
          + 'the way here is kept and handed out as if it were the real one.\n\nOnly do this for a registry that '
          + 'genuinely publishes none.\n\nLeave the checksum check off?'
        )) return;
        // stars = untouched, anything else (empty included) is a change
        if (token.value !== TOKEN_STARS) payload.token = token.value;
        api('PUT', '/upstreams/' + u.id, payload).then(reload).catch(failed);
      }

      var cells = [
        h('span', { class: 'mono' }, [u.name + (u.is_default ? ' (default)' : '')]),
        url,
        mirrorFeeds ? h('div', null, [
          h('span', { class: 'mono' }, [u.path]),
          h('label', null, [rowFiltered, ' filtered index']),
          rowFeed,
          rowHash
        ]) : h('div', null, [pattern, rowHash]),
        priority,
        token,
        h('span', { class: u.enabled ? 'allow' : 'muted' }, [u.enabled ? 'active' : 'off']),
        d.writable ? h('span', { class: 'actions' }, [
          link('save', save),
          link(u.enabled ? 'disable' : 'enable', function () {
            api('PUT', '/upstreams/' + u.id, { enabled: !u.enabled }).then(reload).catch(failed);
          }),
          mirrorFeeds ? '' : link(u.fallback ? 'stop falling back' : 'fall back', function () {
            if (!u.fallback && !confirm(
              'Ask the default registry as well when ' + u.name + ' says 404?\n\n' +
              'It is convenient, and it is also the gap dependency confusion walks through: a ' +
              'name that misses here would then be looked for on the public registry, where ' +
              'anybody can publish one.')) return;
            api('PUT', '/upstreams/' + u.id, { fallback: !u.fallback }).then(reload).catch(failed);
          }),
          u.is_default ? '' : link('remove', function () {
            if (!confirm('Remove the ' + u.name + ' registry?\n\n' + (mirrorFeeds
              ? 'Clients using ' + u.path + ' stop getting packages from it. '
              : 'Anything matching ' + u.pattern + ' goes back to coming from the default. ') +
              'What it cached stays on disk but stops being served.')) return;
            api('DELETE', '/upstreams/' + u.id).then(function (r) {
              if (r.note) alert(r.note);
              return reload();
            }).catch(failed);
          }, 'deny')
        ]) : ''
      ];
      if (showType) cells.splice(1, 0, h('span', null, [labels[u.ecosystem || 'npm'] || ecoName(u.ecosystem)]));
      return cells;
    });

    var cols = ['Name', 'Address', 'Pattern', { label: 'Priority', num: true }, 'Token', 'Status', ''];
    if (showType) cols.splice(1, 0, 'Type');
    box.appendChild(table(cols, rows));

    box.appendChild(h('p', { class: 'hint' }, [
      d.upstreams.filter(function (u) { return u.fallback; }).length
        ? 'One or more registries fall back to the default when they answer 404. That is worth ' +
          'a second look: it is the gap dependency confusion walks through.'
        : 'No registry falls back to the default, which is the safe setting.'
    ]));

    if (!d.writable) {
      box.appendChild(h('p', { class: 'hint muted' }, ['Only an admin can change these.']));
    }
  }).catch(function (e) {
    clear(box);
    box.appendChild(notice(e.message, 'err'));
  });
}

export { upstreamsPanel };
