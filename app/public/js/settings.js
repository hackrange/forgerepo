// ForgeRepo portal: settings.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';
import { anvilMark, brandMark, bytes, can, clear, notice, table, tabs, when } from './ui.js';
import { api } from './api.js';
import { section } from './frame.js';
import { LICENSE_CLASS } from './artifacts.js';
import { labelEditor } from './labels.js';
import { ecoName, ecoPkg } from './ecosystems.js';
import { upstreamsPanel } from './registries.js';
import { boot } from './routing.js';

// which tab was last on screen, kept out here so a redraw comes back to it
var settingsTab = 'policy';

// what switching a type on means, for the ones that can be switched
var TYPE_HINTS = {
  pypi: 'Adds PyPI as a type of registry below, so a Python index can be set up next to npm and pip, uv and poetry can install through this box. Rules and registries for one never apply to the other.',
  oci: 'Answers docker pull, podman and skopeo at /v2/, mirroring images from a registry set up below. Everything is kept by digest and a tag that moves is recorded. Publishers can push images under the names reserved below.',
  nuget: 'Answers dotnet restore, dotnet add package and Visual Studio at /nuget/v3/index.json, mirroring a NuGet feed set up below, like https://api.nuget.org/v3/index.json. Rules and registries for one type never apply to another.',
  maven: 'Answers mvn, gradle and sbt at /maven/, mirroring a Maven repository set up below, like https://repo1.maven.org/maven2. Releases only, no snapshots.',
  rubygems: 'Answers gem install and bundler at /rubygems/, mirroring a gem source set up below, like https://rubygems.org. Every gem is checked against the checksum its source lists.',
  cocoapods: 'Answers pod install at /cocoapods/, mirroring a CocoaPods CDN set up below, like https://cdn.cocoapods.org. The code of each pod is fetched by this box from its git tag and scanned.',
  swift: 'Answers SwiftPM at /swift/ as a package registry. Set up a git host below, like https://github.com: each semver tag of a repository is a release, fetched once and scanned.',
  composer: 'Answers composer at /composer/, in front of a Composer repository set up below, like https://repo.packagist.org. Each archive is fetched by this box from the commit its release points at, and scanned.',
  rpm: 'Answers dnf and yum at /rpm/<mirror>/, mirroring distro repositories set up below, like AlmaLinux 9 BaseOS. Every package is checked against the checksum in the repository index, the rules and its advisories, and scanned.',
  apt: 'Answers apt at /apt/<mirror>/, mirroring Debian and Ubuntu archives set up below, like https://deb.debian.org/debian. Every package is checked against the SHA256 in the archive index, the rules and its advisories, and scanned.'
};

function viewSettings(body) {
  return Promise.all([
    api('GET', '/settings'),
    // never the reason the page refuses to draw
    api('GET', '/email/log?page=1&limit=10').catch(function () { return null; }),
    api('GET', '/applications'),
    api('GET', '/environments')
  ]).then(function (results) {
    var d = results[0];
    var mailLog = results[1];
    var apps = results[2];
    var envs = results[3];
    var s = d.settings;
    var writable = d.writable.length > 0;
    section(body, 'Settings', writable ? 'Changes take effect straight away.' : 'Read only for your role.');

    var tab = tabs(body, settingsTab, [
      { id: 'policy', label: 'Policy' },
      { id: 'registries', label: 'Registries' },
      { id: 'cache', label: 'Cache' },
      { id: 'storage', label: 'Storage' },
      { id: 'vuln', label: 'Vuln scanning' },
      { id: 'malware', label: 'Malware' },
      { id: 'license', label: 'Licenses' },
      { id: 'email', label: 'Email' },
      { id: 'sso', label: 'SSO' },
      { id: 'access', label: 'Access' },
      { id: 'apps', label: 'Applications' }
    ], function (id) { settingsTab = id; });

    var fields = {};
    function field(key, label, hint, type, options) {
      var input;
      if (options) {
        input = h('select', null, options.map(function (o) {
          return h('option', { value: o, selected: String(s[key]) === o }, [o]);
        }));
      } else if (type === 'check') {
        input = h('input', { type: 'checkbox', checked: String(s[key]) === '1' ? 'checked' : null });
      } else if (type === 'textarea') {
        input = h('textarea', { rows: '5', spellcheck: 'false' }, [s[key] === undefined ? '' : s[key]]);
      } else {
        // browsers see url box + password box and helpfully paste your login into them
        input = h('input', {
          type: type || 'text',
          value: s[key] === undefined ? '' : s[key],
          autocomplete: type === 'password' ? 'new-password' : 'off'
        });
      }
      if (!writable) input.setAttribute('disabled', 'disabled');
      fields[key] = { input: input, type: type };
      return h('div', null, [
        h('label', null, type === 'check' ? [input, label] : [label]),
        type === 'check' ? null : input,
        hint ? h('p', { class: 'hint' }, [hint]) : null
      ]);
    }

    tab.policy.appendChild(h('fieldset', null, [
      h('legend', null, ['Policy']),
      field('policy_mode', 'Mode', 'whitelist blocks anything not on the list. blacklist allows anything not on it.', null, ['whitelist', 'blacklist']),
      field('audit_mode', 'Audit only (learning mode)',
        'Serve everything, and log what would have been blocked. Anything pulled that no allow rule covers also opens a request under Requests, listing the exact versions used, so approving it writes the allow rule for you. Works in either mode: with whitelist it learns everything not yet approved, with blacklist everything not explicitly allowed.',
        'check'),
      field('quarantine_mode', 'Quarantine',
        'permissive still serves a held file, with a warning npm prints during install. strict refuses it and leaves it out of npm and PyPI metadata until an admin releases it. A rejected file is refused either way.',
        null, ['permissive', 'strict']),
      field('push_secret_scan', 'Secrets in what is published here',
        'A published or pushed package that looks like it carries a private key, a cloud or registry token or a .env file. hold keeps it from everyone, in both quarantine modes, until an admin releases it; warn only logs it. A package built to trick whatever unpacks it is always refused.',
        null, ['hold', 'warn', 'off']),
      field('safe_resolution', 'Safe version resolution',
        'Also leave versions with a known advisory out of npm and PyPI metadata, and refuse them when a lockfile asks directly, so clients pick a clean version inside the range they asked for. Nothing outside that range is ever swapped in. Answers that left something out are logged under Resolutions.',
        'check'),
      field('safe_resolution_severity', 'Leave out advisories from', 'The lowest severity that gets a version left out.',
        null, ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']),
      field('safe_resolution_kev', 'Also leave out what is exploited in the wild',
        'A version with an advisory CISA lists as known exploited (KEV) is left out whatever its severity says. Needs the threat intelligence feeds on.', 'check'),
      field('safe_resolution_epss', 'Also leave out likely exploits, EPSS from',
        'A version whose advisory has at least this EPSS score (the chance it is exploited in the next 30 days) is left out whatever its severity says, like 0.1 or 10%. Empty is off.'),
      field('cooloff_hours', 'Cooling off, in hours',
        'A version published less than this long ago is left out of npm and PyPI metadata, and refused if asked for by name, until it is old enough. Hijacked releases are usually caught and pulled within a few days, so 72 is a sensible start. 0 is off. An allow rule pinned to that exact version skips the wait. Audit only mode ignores it.',
        'number'),
      field('cooloff_exempt', 'Never cooled off',
        'Package names or patterns with *, one per line, such as @yourcompany/* for your own builds, will bypass the Cooling off rules. Every other check still applies. PyPI has no scopes, so list exact project names there, since a pattern like acme-* would also let anyone\'s new acme-something straight through.',
        'textarea'),
      field('provenance_invalid', 'When provenance is INVALID',
        'Provenance that is published but does not hold up: the Sigstore signature fails, it names different bytes, or it disagrees with its signing certificate. warn records it and sends an event, hold also puts the file in quarantine.',
        null, ['warn', 'hold']),
      field('provenance_downgrade', 'When provenance goes backward',
        'A new npm or PyPI version with no provenance when an older version had verified provenance, or with verified provenance from a different source repository. That is what a stolen publishing token usually looks like. hold puts it in quarantine, warn records it and sends an event.',
        null, ['hold', 'warn', 'off']),
      field('install_script_check', 'When a release starts running code at install',
        'An npm version whose tarball has a preinstall, install or postinstall script, or a binding.gyp, when the version before it had none. A PyPI release with no wheel when the one before it had wheels, so installing it runs setup.py. warn records it and sends an event, hold also puts it in quarantine.',
        null, ['warn', 'hold', 'off']),
      field('manifest_confusion', 'When an npm listing disagrees with its tarball',
        'npm installs from the tarball, so a registry listing that hides scripts or dependencies the package.json inside has is a way to slip them past anyone who only reads the listing. A different name, version, install script or dependency is held; a different license, bin or peer dependency is only warned about.',
        null, ['hold', 'warn', 'off']),
      field('takeover_signals', 'When a release looks like a takeover',
        'A version published by somebody who had not published that package before, a maintainer who joined or left around it, or a package that lay still for a year and then moved. Any of those can be perfectly ordinary, so warn records it and sends an event; hold also puts the file in quarantine.',
        null, ['warn', 'hold', 'off']),
      field('waiver_max_days', 'Longest waiver, in days',
        'No waiver can be granted for longer than this, 1 to 365. When it runs out the finding applies again, and approvers get a reminder the week before.',
        'number'),
      field('typosquat_mode', 'Typosquat checks',
        'Names that imitate a well known package, like lodahs for lodash. warn serves them, logs them under Lookalike packages and has npm print a warning. block refuses them. off does neither. Audit only mode only ever warns.',
        null, ['warn', 'block', 'off']),
      field('typosquat_protected', 'Also protect these names', 'Your own important package names, one per line, so lookalikes of them get caught too. Well known npm and PyPI names are built in.', 'textarea'),
      field('typosquat_exempt', 'Never flag these', 'Package names or patterns with *, one per line, for real packages that happen to look like a famous one.', 'textarea'),
      field('cooloff_unknown', 'A version with no publish time',
        'Some private registries publish no times. allow serves those as usual, hold keeps them back as if they were brand new.', null, ['allow', 'hold']),
      field('auto_request', 'Open a request when an install is blocked', 'Saves developers having to type it in.', 'check'),
      field('approve_clean_dependencies', 'Approving a request can approve its clean dependencies too',
        'The approver is shown the dependency tree and asked. Only packages no rule approves yet, with nothing against them (not blocked, no known advisory, no quarantine hold, not killed), get an allow rule pinned to the version the tree resolved, and the advisory feed is asked about each one again first. Off, every dependency is decided on its own.',
        'check'),
      field('lifecycle_enforce', 'Enforce lifecycle stages: production environments only get versions promoted to production',
        'A version at the blocked stage is refused to everyone, and a token in a production environment only gets versions moved to production. Versions with no stage count as not promoted. Off, stages are only information on the Artifacts page.',
        'check'),
      field('registry_name', 'Name shown in the portal', 'In the header, on the sign in page and as the browser tab title.'),
      field('show_help_url', 'Tell blocked developers where the portal is', 'Off keeps the admin address out of the message npm prints.', 'check')
    ]));

    // icon and favicon save the moment a file is picked, they are not part of Save settings
    var brandBox = h('div', null, []);
    var faviconLink = function (b) {
      var el = document.querySelector('link[rel=icon]');
      if (!el) return;
      el.setAttribute('type', b ? b.type : 'image/svg+xml');
      el.setAttribute('href', b ? '/_admin/brand/favicon?v=' + b.sha256.slice(0, 12) : '/_admin/icon.svg');
    };
    var redrawHeader = function () {
      Array.prototype.forEach.call(document.querySelectorAll('.topbar .brand'), function (el) {
        el.replaceChild(brandMark(), el.firstChild);
      });
    };
    var drawBrand = function (b, said) {
      clear(brandBox);
      brandBox.appendChild(h('p', { class: 'hint' }, [
        'PNG, JPEG, GIF or WebP, and the favicon can also be an ICO. ' + b.minSide + ' to ' + b.maxSide + ' pixels a side, ' +
        bytes(b.maxBytes) + ' at most. A square image looks best. SVG is not accepted, it can carry script.'
      ]));
      var msg = h('div', null, said ? [notice(said, 'ok')] : []);
      [
        ['icon', 'Header icon', 'Next to the name at the top of every page and on the sign in page, instead of the anvil.', 'image/png,image/jpeg,image/gif,image/webp'],
        ['favicon', 'Favicon', 'The little picture on the browser tab.', 'image/png,image/x-icon,image/vnd.microsoft.icon,.ico,image/gif,image/jpeg,image/webp']
      ].forEach(function (k) {
        var kind = k[0];
        var cur = b[kind];
        var preview = cur
          ? h('img', { class: 'brand-preview', src: '/_admin/brand/' + kind + '?v=' + cur.sha256.slice(0, 12), alt: '' })
          : h('span', { class: 'brand-preview', title: 'the default' }, [anvilMark()]);
        var input = h('input', { type: 'file', accept: k[3], 'aria-label': k[1] });
        if (!writable) input.setAttribute('disabled', 'disabled');
        input.addEventListener('change', function () {
          clear(msg);
          var file = input.files && input.files[0];
          if (!file) return;
          if (file.size > b.maxBytes) {
            msg.appendChild(notice(file.name + ' is ' + bytes(file.size) + ', the limit is ' + bytes(b.maxBytes) + '.', 'err'));
            input.value = '';
            return;
          }
          var reader = new FileReader();
          reader.onload = function () {
            api('PUT', '/branding/' + kind, { data: String(reader.result) }).then(function (r) {
              if (kind === 'icon') {
                state.brandIcon = r.sha256.slice(0, 12);
                redrawHeader();
              }
              return api('GET', '/branding').then(function (nb) {
                if (kind === 'favicon') faviconLink(nb.favicon);
                drawBrand(nb, k[1] + ' saved, ' + r.width + 'x' + r.height + '.');
              });
            }).catch(function (e) {
              msg.appendChild(notice(e.message, 'err'));
              input.value = '';
            });
          };
          reader.readAsDataURL(file);
        });
        var reset = cur && writable ? h('button', {
          type: 'button',
          onclick: function () {
            if (!confirm('Go back to the default ' + k[1].toLowerCase() + '?')) return;
            api('DELETE', '/branding/' + kind).then(function () {
              if (kind === 'icon') {
                state.brandIcon = null;
                redrawHeader();
              } else {
                faviconLink(null);
              }
              return api('GET', '/branding').then(function (nb) { drawBrand(nb, k[1] + ' is back to the default.'); });
            }).catch(function (e) { msg.appendChild(notice(e.message, 'err')); });
          }
        }, ['Use the default']) : null;
        brandBox.appendChild(h('div', { class: 'brand-row' }, [
          h('label', null, [k[1]]),
          h('div', { class: 'brand-pick' }, [preview, input, reset]),
          h('p', { class: 'hint' }, [k[2] + (cur ? ' Now ' + cur.width + 'x' + cur.height + ', set by ' + (cur.updatedBy || 'someone') + ' ' + when(cur.updatedAt) + '.' : '')])
        ]));
      });
      brandBox.appendChild(msg);
    };
    tab.policy.appendChild(h('fieldset', null, [h('legend', null, ['Branding']), brandBox]));
    api('GET', '/branding').then(function (b) { drawBrand(b); })
      .catch(function (e) { clear(brandBox); brandBox.appendChild(notice(e.message, 'err')); });

    // what this box answers for, who may ask, and where it goes to fetch. the types come from the server
    tab.registries.appendChild(h('fieldset', null, [h('legend', null, ['Package types'])].concat(
      (d.ecosystems || []).map(function (e) {
        return e.setting
          ? field(e.setting, e.label, TYPE_HINTS[e.id] || null, 'check')
          : h('p', { class: 'hint' }, [e.label + ' is always on.']);
      }),
      [field('upstream_enabled', 'Upstream registry enabled', 'Off and this box never calls out to any of them. Anything already cached still gets served, anything else gets a 503. Use it to ride out a bad day upstream on known good copies only.', 'check')]
    )));
    tab.registries.appendChild(h('fieldset', null, [
      h('legend', null, ['Clients']),
      field('npm_clients_only', 'Only answer package managers',
        'npm, yarn, pnpm and bun, and pip, uv, poetry and friends for PyPI. Anything else asking for a package gets a plain 404. npm has a package published under nearly every filename worth guessing, so a scanner walking a webserver wordlist otherwise gets a 200 and a json body for /config.json, /phpmyadmin and the rest, and reports them as exposed files. Turn this on and they get nothing. It does stop anything that pulls packages with curl, so check your build scripts first.',
        'check'),
      field('require_auth', 'Require a token from package managers', 'Turn this on and every developer needs a token: in .npmrc for npm, in the index address for pip, in nuget.config for dotnet, in settings.xml for mvn, in the gem source address for bundler, in ~/.netrc for pod, swift package-registry login for SwiftPM, composer config http-basic for Composer, username and password in the .repo file for dnf, /etc/apt/auth.conf.d for apt, and docker login for images.', 'check')
    ]));
    // registry rows save as they're edited, like applications. Save settings has nothing to do with them
    var upstreamBox = h('div', null, [h('p', { class: 'muted' }, ['Loading...'])]);
    tab.registries.appendChild(h('fieldset', null, [h('legend', null, ['Upstream registries']), upstreamBox]));
    upstreamsPanel(upstreamBox);

    // reserved names save as they are added, like registry rows
    var reservedBox = h('div', null, [h('p', { class: 'muted' }, ['Loading...'])]);
    tab.registries.appendChild(h('fieldset', null, [h('legend', null, ['Reserved names']), reservedBox]));
    var drawReserved = function () {
      api('GET', '/private-names').then(function (r) {
        clear(reservedBox);
        reservedBox.appendChild(h('p', { class: 'hint' }, [
          'Names that belong to your organization. A reserved name is never fetched from any upstream registry, not even a copy ' +
          'cached before it was reserved, so nobody can publish the same name publicly and have it installed here instead. ' +
          'An exact name, an npm scope like @acme/*, an image namespace like acme/*, or a prefix ending in * like acme-*. ' +
          'Publishers can publish, upload and push only under reserved names.'
        ]));
        if (r.names.length) {
          reservedBox.appendChild(table(['Name', 'Note', 'Added', ''], r.names.map(function (n) {
            return [ecoPkg(n.ecosystem || 'npm', n.pattern), n.note || '', (n.created_by || '') + ', ' + when(n.created_at),
              r.canChange ? link('remove', function () {
                if (!confirm('Stop reserving ' + n.pattern + '? It can be fetched from an upstream again.')) return;
                api('DELETE', '/private-names/' + n.id).then(drawReserved).catch(function (e) { alert(e.message); });
              }, 'deny') : ''];
          })));
        } else {
          reservedBox.appendChild(h('p', { class: 'muted' }, ['Nothing is reserved yet.']));
        }
        if (!r.canChange) return;
        var eco = h('select', null, [h('option', { value: 'npm' }, ['npm']), h('option', { value: 'pypi' }, ['PyPI']),
          h('option', { value: 'oci' }, ['Docker']), h('option', { value: 'nuget' }, ['NuGet']), h('option', { value: 'rubygems' }, ['RubyGems']), h('option', { value: 'maven' }, ['Maven'])]);
        var pattern = h('input', { type: 'text', placeholder: '@acme/*', maxlength: '214' });
        eco.onchange = function () { pattern.placeholder = { npm: '@acme/*', pypi: 'acme-*', oci: 'acme/*', nuget: 'Acme.*', rubygems: 'acme-*', maven: 'com.acme:*' }[eco.value]; };
        var note = h('input', { type: 'text', placeholder: 'optional, like platform team', maxlength: '255' });
        reservedBox.appendChild(h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Type']), eco]),
          h('div', null, [h('label', null, ['Reserved name']), pattern]),
          h('div', null, [h('label', null, ['Note']), note]),
          h('div', null, [h('button', {
            type: 'button',
            onclick: function () {
              if (!pattern.value.trim()) return alert('Type the name, scope or prefix to reserve.');
              api('POST', '/private-names', { ecosystem: eco.value, pattern: pattern.value.trim(), note: note.value.trim() })
                .then(drawReserved).catch(function (e) { alert(e.message); });
            }
          }, ['Reserve'])])
        ]));
      }).catch(function (e) { clear(reservedBox); reservedBox.appendChild(notice(e.message, 'err')); });
    };
    drawReserved();

    // who has to have signed an image, per repository. saved as added, like reserved names
    var trustBox = h('div', null, [h('p', { class: 'muted' }, ['Loading...'])]);
    tab.registries.appendChild(h('fieldset', null, [h('legend', null, ['Image signatures']), trustBox]));
    var drawTrust = function () {
      api('GET', '/image-trust').then(function (r) {
        clear(trustBox);
        trustBox.appendChild(h('p', { class: 'hint' }, [
          'Images of a repository here have to carry a cosign signature from someone you trust: a public key (cosign.pub), or a ' +
          'keyless signer identity, like the GitHub workflow that built it. Keyless signatures are checked against the Sigstore ' +
          'Fulcio roots and must be in the Rekor transparency log. Require refuses an image nobody trusted signed; warn lets it ' +
          'through and logs it. A signed multi-platform list covers the platform images it names.'
        ]));
        if (r.policies.length) {
          trustBox.appendChild(table(['Repository', 'Mode', 'Trusted signers', 'Added', ''], r.policies.map(function (p) {
            var who = p.keys.map(function (k) { return 'key ' + k.name; })
              .concat(p.identities.map(function (i) { return i.subject + ' (' + i.issuer + ')'; }));
            return [p.pattern, p.mode + (p.requireLog ? ', logged' : ''), who.join(', '), (p.created_by || '') + ', ' + when(p.created_at),
              r.canChange ? link('remove', function () {
                if (!confirm('Remove the trust policy for ' + p.pattern + '? Its images no longer need a signature.')) return;
                api('DELETE', '/image-trust/' + p.id).then(drawTrust).catch(function (e) { alert(e.message); });
              }, 'deny') : ''];
          })));
        } else {
          trustBox.appendChild(h('p', { class: 'muted' }, ['No repository needs a signature yet.']));
        }
        if (!r.canChange) return;
        var pattern = h('input', { type: 'text', placeholder: 'acme/* or library/nginx', maxlength: '255' });
        var mode = h('select', null, [h('option', { value: 'require' }, ['require']), h('option', { value: 'warn' }, ['warn'])]);
        var keys = h('textarea', { rows: '4', spellcheck: 'false', placeholder: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----' });
        var ids = h('textarea', { rows: '3', spellcheck: 'false', placeholder: 'https://token.actions.githubusercontent.com https://github.com/acme/*' });
        var logged = h('input', { type: 'checkbox' });
        var note = h('input', { type: 'text', placeholder: 'optional', maxlength: '255' });
        trustBox.appendChild(h('div', { class: 'row' }, [
          h('div', null, [h('label', null, ['Repository']), pattern]),
          h('div', null, [h('label', null, ['Mode']), mode]),
          h('div', null, [h('label', null, ['Note']), note])
        ]));
        trustBox.appendChild(h('label', null, ['Trusted public keys, PEM, one or more']));
        trustBox.appendChild(keys);
        trustBox.appendChild(h('label', null, ['Trusted keyless signers, one per line: issuer, a space, then subject. A * can end an address with its owner in it, or stand for the name in an email']));
        trustBox.appendChild(ids);
        trustBox.appendChild(h('label', null, [logged, ' Keyed signatures must be in the transparency log too']));
        trustBox.appendChild(h('div', null, [h('button', {
          type: 'button',
          onclick: function () {
            var pems = keys.value.match(/-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----/g) || [];
            var identities = ids.value.split('\n').map(function (l) { return l.trim(); }).filter(Boolean).map(function (l) {
              var parts = l.split(/\s+/);
              return { issuer: parts[0], subject: parts.slice(1).join(' ') };
            });
            if (!pattern.value.trim()) return alert('Type the repository, namespace or prefix.');
            api('POST', '/image-trust', { pattern: pattern.value.trim(), mode: mode.value, keys: pems, identities: identities, requireLog: logged.checked, note: note.value.trim() })
              .then(drawTrust).catch(function (e) { alert(e.message); });
          }
        }, ['Add trust policy'])]));
      }).catch(function (e) { clear(trustBox); trustBox.appendChild(notice(e.message, 'err')); });
    };
    drawTrust();

    tab.cache.appendChild(h('fieldset', null, [
      h('legend', null, ['Cache']),
      field('public_url', 'Public url', 'The address developers use. Tarball links are rewritten to it.'),
      field('cache_tarballs', 'Keep tarballs on disk', null, 'check'),
      field('cache_latest_on_allow', 'Cache the current version of any-version rules',
        'When an allow rule covers every version of a package and nothing of it is cached yet, the version that is current right then is downloaded in the background, if the kill switch and the rules let it through. Rules naming exact versions use Warm on the Rules page instead.',
        'check'),
      field('packument_ttl', 'Seconds before metadata is refetched', null, 'number'),
      field('stale_ok_seconds', 'Seconds we will serve stale metadata if upstream is down', null, 'number'),
      field('log_retention_days', 'Days of traffic log to keep', 'The audit trail is kept four times as long.', 'number'),
      field('consumption_retention_days', 'Days to remember who consumed what',
        'Consumers keeps one small row per version per consumer, so it can reach back much further than the traffic log. A consumer nobody has seen for this long is forgotten. 0 keeps them forever.',
        'number'),
      field('dashboard_cache_minutes', 'Minutes to keep the dashboard numbers',
        'The dashboard counts its way through the traffic log and the cache, so the answer is kept for a while. Zero counts on every visit. The page has a button either way.', 'number')
    ]));

    tab.malware.appendChild(h('fieldset', null, [
      h('legend', null, ['Malware scanning']),
      h('p', { class: 'hint' }, [
        'Every cached npm and PyPI file can be run past these scanners. MALICIOUS and SUSPICIOUS verdicts go through ' +
        'quarantine, so they show on the Quarantine page and in the audit trail.'
      ]),
      field('malware_scanning', 'Scan cached files', 'New files are scanned in the background as they come in. Off scans nothing.', 'check'),
      field('malware_scanners', 'Scanners', 'Comma separated, any of: blocklist, clamav, rest, osv, secrets. secrets reads inside every file kept here, including the layers of a pushed image, and calls one carrying a private key, a token or a .env SUSPICIOUS (public packages are full of test keys, so it is off unless you ask for it). osv asks OSV whether the exact package and version is a known-malicious one (the OpenSSF MAL- feed), before anybody gets it. One that is listed but not set up below is skipped.'),
      field('malicious_auto_kill', 'Kill known-malicious packages by themselves', 'When the vulnerability scan finds a MAL- advisory (a package known to be malicious) against something here, that advisory goes on the kill switch at once and admins are told. Off, it is only a finding.', 'check'),
      field('malware_on_malicious', 'When a scanner says MALICIOUS',
        'reject refuses the file in both quarantine modes until an admin releases it. hold follows the quarantine mode. warn only logs it.',
        null, ['reject', 'hold', 'warn']),
      field('malware_on_suspicious', 'When a scanner says SUSPICIOUS',
        'hold follows the quarantine mode, warn only logs it, ignore does neither.', null, ['hold', 'warn', 'ignore']),
      field('malware_scan_before_serve', 'Scan before serving',
        'A file with no answer yet is scanned before it goes out, and refused with a 503 if that takes over a minute. Off, the first download of a brand new file can go out before its background scan finishes.',
        'check'),
      field('malware_hash_blocklist', 'Hash blocklist', 'SHA-256 values known to be bad, one per line. Anything after # is a note.', 'textarea'),
      field('malware_clamd_host', 'ClamAV clamd host', 'The clamd to stream files to, for example a clamav/clamav container on the same network.'),
      field('malware_clamd_port', 'ClamAV clamd port', null, 'number'),
      field('malware_rest_url', 'REST scanner url', 'Files are POSTed here and a json verdict comes back. The README has the format.'),
      field('malware_rest_token', 'REST scanner token', 'Sent as a bearer token. Stored on the box and never sent back out. Leave the stars alone to keep the one already set.', 'password')
    ]));

    // what the scanners say about themselves, and the rescan buttons
    var malwareBox = h('div', null, []);
    var drawMalware = function (m) {
      clear(malwareBox);
      malwareBox.appendChild(notice(m.enabled
        ? 'Scanning is on' + (m.beforeServe ? ', and new files are scanned before they are served.' : ', in the background.')
        : 'Scanning is off.', m.enabled ? 'ok' : 'info'));
      malwareBox.appendChild(table(['Scanner', 'Listed', 'State'], m.scanners.map(function (sc) {
        return [sc.name, sc.selected ? 'yes' : 'no',
          sc.problem ? h('span', { class: sc.selected ? 'warn' : 'muted' }, [sc.problem]) : h('span', { class: 'allow' }, ['ready'])];
      })));
      var c = m.counts || {};
      malwareBox.appendChild(h('p', { class: 'hint' }, [
        'Files with a result: clean ' + (c.CLEAN || 0) + ', suspicious ' + (c.SUSPICIOUS || 0) + ', malicious ' + (c.MALICIOUS || 0) +
        ', errors ' + (c.ERROR || 0) + '. Never scanned: ' + m.unscanned + '.'
      ]));
      var j = m.job || {};
      if (j.running) malwareBox.appendChild(h('p', { class: 'hint' }, ['Scanning the cache: ' + j.done + ' of ' + j.total + '...']));
      else if (j.finishedAt) malwareBox.appendChild(h('p', { class: 'hint' }, ['Last run: ' + j.done + ' of ' + j.total + ' scanned.' + (j.errors && j.errors.length ? ' First error: ' + j.errors[0] : '')]));
      if (can('cache:purge')) {
        var fire = function (force) {
          api('POST', '/malware/rescan', { force: force }).then(loadMalware).catch(function (e) { alert(e.message); });
        };
        malwareBox.appendChild(h('div', null, [
          h('button', { onclick: function () { fire(false); } }, ['Scan what has not been scanned']),
          h('button', { onclick: function () { if (confirm('Rescan every cached file with every scanner? That can take a while.')) fire(true); } }, ['Rescan everything']),
          j.running ? h('button', { class: 'danger', onclick: function () { api('POST', '/malware/rescan/cancel', {}).then(loadMalware); } }, ['Stop']) : null
        ]));
      }
      if (m.flagged && m.flagged.length) {
        malwareBox.appendChild(h('h3', null, ['Recently flagged']));
        malwareBox.appendChild(table(['When', 'Package', 'File', 'Scanner', 'Verdict', 'Signature'], m.flagged.map(function (x) {
          return [when(x.scan_time), ecoPkg(x.ecosystem, x.package_name),
            h('span', { class: 'mono' }, [x.filename]), x.scanner,
            h('span', { class: x.status === 'MALICIOUS' ? 'deny' : 'warn' }, [x.status]), x.signature || ''];
        })));
      }
      if (j.running) setTimeout(function () { if (malwareBox.isConnected) loadMalware(); }, 2000);
    };
    var loadMalware = function () {
      api('GET', '/malware').then(drawMalware).catch(function (e) { clear(malwareBox); malwareBox.appendChild(notice(e.message, 'err')); });
    };
    tab.malware.appendChild(h('fieldset', null, [h('legend', null, ['Scanner status']), malwareBox]));
    loadMalware();

    // ---- storage: this disk, or a bucket with this disk in front of it
    // where they go comes first, a box on its own disk never needs to see a bucket setting
    var savedBackend = String(s.storage_backend || 'local');
    var backendInput = h('input', { type: 'hidden', value: savedBackend });
    fields.storage_backend = { input: backendInput, type: null };
    var cloudActions = null;
    var onLocal = h('input', { type: 'radio', name: 'storage-where', value: 'local', checked: savedBackend === 'local' ? 'checked' : null });
    var onCloud = h('input', { type: 'radio', name: 'storage-where', value: 'cloud', checked: savedBackend === 'local' ? null : 'checked' });
    var provider = h('select', null, [['s3', 'S3, or anything that speaks S3'], ['azure', 'Azure Blob']].map(function (o) {
      return h('option', { value: o[0], selected: savedBackend === o[0] }, [o[1]]);
    }));
    var s3Box = h('div', null, [
      field('s3_endpoint', 'Endpoint', 'Only the address, like https://s3.eu-west-1.amazonaws.com. Plain http only for a bucket on your own network.'),
      field('s3_region', 'Region', 'us-east-1 unless your provider says otherwise.'),
      field('s3_bucket', 'Bucket', 'Create it first. Once files are in it, the endpoint, bucket and folder are fixed.'),
      field('s3_prefix', 'Folder inside the bucket', 'Optional, like forgerepo/. Everything goes under it.'),
      field('s3_path_style', 'Path style addresses', 'On for MinIO and most self hosted stores, off for AWS.', 'check'),
      field('s3_access_key_id', 'Access key id', d.storageEnv && d.storageEnv.s3AccessKeyId ? 'S3_ACCESS_KEY_ID is set in the environment, and that one is used instead.' : null),
      field('s3_secret_access_key', 'Secret access key', d.storageEnv && d.storageEnv.s3SecretAccessKey
        ? 'S3_SECRET_ACCESS_KEY is set in the environment, and that one is used instead.'
        : 'Stored on the box and never sent back out. Leave the stars alone to keep the one already set. S3_SECRET_ACCESS_KEY in the environment keeps it out of the database.', 'password')
    ]);
    var azureBox = h('div', null, [
      field('az_account', 'Azure storage account', 'For azure. The account name, like forgerepocache.'),
      field('az_container', 'Azure container', 'Create it first. Once files are in it, the account, container, folder and endpoint are fixed.'),
      field('az_prefix', 'Folder inside the container', 'Optional, like forgerepo/.'),
      field('az_endpoint', 'Azure endpoint', 'Leave empty for https://<account>.blob.core.windows.net. An emulator or private endpoint goes here.'),
      field('az_account_key', 'Azure account key', d.storageEnv && d.storageEnv.azureAccountKey
        ? 'AZURE_STORAGE_KEY is set in the environment, and that one is used instead.'
        : 'Stored on the box and never sent back out. Leave the stars alone to keep the one already set. AZURE_STORAGE_KEY in the environment keeps it out of the database.', 'password')
    ]);
    var cloudBox = h('div', null, [
      h('p', { class: 'hint' }, [
        'New files still land on this disk first and go up in the background, where the bucket checks each one against its SHA-256, ' +
        'and a local copy is only ever dropped after the bucket holds it. Switching a box that already has a cache uploads all of it the same way.'
      ]),
      h('div', null, [h('label', null, ['Cloud provider']), provider]),
      h('p', { class: 'hint' }, ['S3 covers AWS and anything that speaks S3, such as MinIO, Cloudflare R2 or Wasabi.']),
      s3Box,
      azureBox,
      field('storage_cache_mb', 'Local copies to keep, in MB',
        'With a bucket, files it already holds are dropped from disk, least recently used first, once they add up to more than this. 0 keeps none. A file not uploaded yet is never dropped.', 'number')
    ]);
    var syncWhere = function () {
      cloudBox.hidden = !onCloud.checked;
      s3Box.hidden = provider.value !== 's3';
      azureBox.hidden = provider.value !== 'azure';
      backendInput.value = onCloud.checked ? provider.value : 'local';
      if (cloudActions) cloudActions.hidden = !onCloud.checked;
    };
    [onLocal, onCloud, provider].forEach(function (el) {
      if (!writable) el.setAttribute('disabled', 'disabled');
      el.addEventListener('change', syncWhere);
    });
    tab.storage.appendChild(h('fieldset', null, [
      h('legend', null, ['Keep cached files in']),
      h('div', { class: 'switch', role: 'radiogroup', 'aria-label': 'Keep cached files in' }, [
        h('label', null, [onLocal, 'Local disk']),
        h('label', null, [onCloud, 'Cloud'])
      ]),
      h('p', { class: 'hint' }, ['Local disk keeps every cached file on this box. Cloud keeps them in a bucket with this disk in front of it. ' +
        'Saving a switch to the cloud tests the bucket first, and changes nothing if the test fails.']),
      cloudBox
    ]));

    var storageBox = h('div', null, []);
    var storageOut = h('p', { class: 'hint' }, []);
    var drawStorage = function (st) {
      clear(storageBox);
      var c = st.counts || {};
      var inCloud = st.backend === 's3' || st.backend === 'azure';
      storageBox.appendChild(notice(inCloud
        ? 'Cached files are kept in the bucket. ' + c.inBucket + ' of ' + c.blobs + ' are there, ' + bytes(c.bucketBytes) + ' of ' + bytes(c.bytes) + '.'
        : 'Cached files are kept on this box\'s disk: ' + c.blobs + ' files, ' + bytes(c.bytes) + '.',
      inCloud && c.inBucket === c.blobs ? 'ok' : 'info'));
      if (inCloud && c.blobs > c.inBucket) {
        storageBox.appendChild(h('p', { class: 'hint' }, [(c.blobs - c.inBucket) + ' still to upload' + (c.failing ? ', ' + c.failing + ' of them failing so far' : '') + '.']));
      }
      if (st.failing && st.failing.length) {
        storageBox.appendChild(table(['File', 'Size', 'Tries', 'Last error'], st.failing.map(function (f) {
          return [f.sha256.slice(0, 12), bytes(f.size), String(f.attempts), f.error || ''];
        })));
      }
      var u = st.uploader || {};
      if (u.running) storageBox.appendChild(h('p', { class: 'hint' }, ['Uploading now, ' + u.uploaded + ' sent so far.']));
    };
    var loadStorage = function () {
      api('GET', '/storage').then(drawStorage).catch(function (e) {
        clear(storageBox);
        storageBox.appendChild(notice(e.message, 'err'));
      });
    };
    var storageKeys = ['s3_endpoint', 's3_region', 's3_bucket', 's3_prefix', 's3_path_style', 's3_access_key_id', 's3_secret_access_key',
      'az_endpoint', 'az_account', 'az_container', 'az_prefix', 'az_account_key', 'storage_cache_mb'];
    cloudActions = writable ? h('div', null, [
      h('button', {
        type: 'button',
        onclick: function () {
          storageOut.textContent = 'testing...';
          // save first or the test uses the saved settings, not the ones on screen
          var payload = {};
          storageKeys.forEach(function (key) {
            var f = fields[key];
            payload[key] = f.type === 'check' ? (f.input.checked ? '1' : '0') : f.input.value;
          });
          api('PUT', '/settings', payload)
            // tests the kind picked on screen, so azure can be tried before switching to it
            .then(function () { return api('POST', '/storage/test', { kind: fields.storage_backend.input.value === 'azure' ? 'azure' : 's3' }); })
            .then(function (r) { storageOut.textContent = 'the bucket ' + r.bucket + ' took a file, gave it back and deleted it, in ' + r.ms + 'ms.'; })
            .catch(function (e) { storageOut.textContent = 'it did not work: ' + e.message; });
        }
      }, ['Save and test the bucket']),
      h('button', {
        type: 'button',
        onclick: function () {
          storageOut.textContent = 'uploading and tidying...';
          api('POST', '/storage/sync', {})
            .then(function (r) {
              storageOut.textContent = r.uploaded.uploaded + ' uploaded, ' + r.uploaded.failed + ' failed, ' + r.cache.removed + ' local copies dropped.';
              loadStorage();
            })
            .catch(function (e) { storageOut.textContent = e.message; });
        }
      }, ['Upload and tidy now'])
    ]) : null;
    tab.storage.appendChild(h('fieldset', null, [
      h('legend', null, ['What is where']),
      storageBox,
      cloudActions,
      storageOut
    ]));
    syncWhere();
    loadStorage();

    tab.license.appendChild(h('fieldset', null, [
      h('legend', null, ['Licenses']),
      h('p', { class: 'hint' }, [
        'Every cached file has its license read from the package metadata and turned into an SPDX expression where it can be. ' +
        'With "MIT OR GPL-3.0-only" the better choice counts, with "MIT AND GPL-3.0-only" the worse part does. Nothing is ever guessed: ' +
        'a license that cannot be read counts as unknown.'
      ]),
      field('license_enforcement', 'What to do about it',
        'off only reads and records. warn logs it, and npm prints a notice during install. enforce holds review licenses in quarantine and rejects blocked ones. In audit only (learning) mode enforce acts like warn.',
        null, ['off', 'warn', 'enforce']),
      field('license_allowed', 'Allowed', 'SPDX ids, one per line. * is a wildcard, so BSD-* covers every BSD. "GPL-2.0-only WITH Classpath-exception-2.0" names one exception.', 'textarea'),
      field('license_review', 'Needs review', 'Held in quarantine under enforce, until an admin releases or rejects the file.', 'textarea'),
      field('license_blocked', 'Blocked', 'Rejected under enforce. A license on more than one list gets the strictest of them.', 'textarea'),
      field('license_unlisted', 'A license on no list is', null, null, ['review', 'allowed', 'blocked']),
      field('license_unknown', 'No readable license is', 'Includes SEE LICENSE IN files, license text with no identifier, and PyPI indexes with no JSON API.', null, ['review', 'allowed', 'blocked'])
    ]));

    var licenseBox = h('div', null, []);
    var loadLicenses = function () {
      api('GET', '/licenses').then(function (m) {
        clear(licenseBox);
        var c = m.counts || {};
        var said = { off: 'License checks are off', warn: 'Licenses are checked and warned about', enforce: 'Licenses are enforced' }[m.mode];
        licenseBox.appendChild(notice(said + (m.mode === 'enforce' && m.learning ? ', acting as warn while audit only is on' : '') + '.', m.mode === 'off' ? 'info' : 'ok'));
        licenseBox.appendChild(h('p', { class: 'hint' }, [
          'Files: allowed ' + (c.allowed || 0) + ', review ' + (c.review || 0) + ', blocked ' + (c.blocked || 0) + ', not read yet ' + (c.unchecked || 0) +
          '. License holds: ' + m.holds.open + ' open, ' + m.holds.rejected + ' rejected.' +
          (m.job.running ? ' Reading licenses now, ' + m.job.read + ' so far.' : '')
        ]));
        if (can('cache:purge') && m.mode !== 'off') {
          licenseBox.appendChild(h('div', null, [h('button', {
            onclick: function () {
              if (!confirm('Read every cached file\'s license again from the registry metadata?')) return;
              api('POST', '/licenses/recheck', {}).then(loadLicenses).catch(function (e) { alert(e.message); });
            }
          }, ['Read them all again'])]));
        }
        if (m.inUse.length) {
          licenseBox.appendChild(h('h3', null, ['In use']));
          licenseBox.appendChild(table(['License', 'Verdict', { label: 'Packages', num: true }, { label: 'Files', num: true }], m.inUse.map(function (x) {
            return [h('span', { class: 'mono' }, [x.expression || 'unknown']), h('span', { class: LICENSE_CLASS[x.verdict] || 'muted' }, [x.verdict || '-']),
              String(x.packages), String(x.files)];
          })));
        }
        if (m.job.running) setTimeout(function () { if (licenseBox.isConnected) loadLicenses(); }, 3000);
      }).catch(function (e) { clear(licenseBox); licenseBox.appendChild(notice(e.message, 'err')); });
    };
    tab.license.appendChild(h('fieldset', null, [h('legend', null, ['Licenses in use']), licenseBox]));
    loadLicenses();

    tab.vuln.appendChild(h('fieldset', null, [
      h('legend', null, ['Vulnerability scanning']),
      field('cve_scan_hours', 'Hours between scans of the allow list',
        'Rechecks every version the rules allow against the public advisory feed and lists what has gone bad, ' +
        'on the Vulnerabilities page. It never blocks anything on its own. 0 switches it off, 168 is a week.',
        'number'),
      field('intel_feeds_enabled', 'Fetch CISA KEV and FIRST EPSS',
        'Marks findings whose CVE is on the CISA Known Exploited Vulnerabilities list, and adds the EPSS chance of it being exploited. ' +
        'Only the feeds\' public addresses are fetched, and EPSS is only asked about CVEs this box already has findings or advisories for. Neither ever blocks anything.',
        'check'),
      field('intel_feed_hours', 'Hours between intel fetches', '1 to 168. A failed fetch is tried again an hour later.', 'number')
    ]));

    // how the two feeds last went, filled in once it answers
    var intelBox = h('div', null, [h('p', { class: 'muted' }, ['Loading...'])]);
    var loadIntel = function () {
      api('GET', '/intel').then(drawIntel).catch(function (e) { clear(intelBox); intelBox.appendChild(notice(e.message, 'err')); });
    };
    var drawIntel = function (st) {
      clear(intelBox);
      var names = { kev: 'CISA Known Exploited Vulnerabilities', epss: 'FIRST EPSS scores' };
      var byFeed = {};
      (st.feeds || []).forEach(function (f) { byFeed[f.feed] = f; });
      intelBox.appendChild(table(['Feed', 'Last fetched', { label: 'Entries', num: true }, 'Last problem'], ['kev', 'epss'].map(function (k) {
        var f = byFeed[k] || {};
        return [names[k], f.synced_at ? when(f.synced_at) : h('span', { class: 'muted' }, ['never']), f.synced_at ? String(f.entries) : '',
          f.error ? h('span', { class: 'deny' }, [f.error]) : ''];
      })));
      intelBox.appendChild(h('p', { class: 'hint' }, [
        st.counts.kevFindings + ' finding(s) name a CVE on the KEV list, and ' + st.counts.epss + ' CVE(s) have an EPSS score.' +
        (st.enabled ? '' : ' Fetching is switched off.')
      ]));
      if (writable) {
        intelBox.appendChild(h('button', {
          type: 'button',
          onclick: function () {
            clear(intelBox);
            intelBox.appendChild(h('p', { class: 'muted' }, ['Fetching both feeds, this can take a minute...']));
            api('POST', '/intel/sync', {}).then(loadIntel).catch(function (e) { clear(intelBox); intelBox.appendChild(notice(e.message, 'err')); });
          }
        }, ['Fetch now']));
      }
    };
    tab.vuln.appendChild(h('fieldset', null, [h('legend', null, ['Known exploited, and likely to be']), intelBox]));
    loadIntel();

    // ---- email, and the digest that goes out over it ----
    var emailBox = h('fieldset', null, [h('legend', null, ['Email'])]);
    emailBox.appendChild(h('p', { class: 'hint' }, [
      'One digest an hour at the very most, and only to somebody who has something new to hear. ' +
      'Developers get what happened to the requests they opened; approvers get what has landed on the ' +
      'list since the last one. Nothing that was in an earlier mail is sent again, so a quiet week is ' +
      'a quiet inbox. An address only ever hears about what happened after it was first seen here.'
    ]));
    if (d.emailProblem) {
      emailBox.appendChild(notice('Mail cannot go out yet: ' + d.emailProblem, ''));
    }
    emailBox.appendChild(field('email_enabled', 'Send email', 'Off and nothing on this box ever sends a message. The test below works either way.', 'check'));
    emailBox.appendChild(field('email_transport', 'How it goes out', 'smtp is a relay on your network. graph is Microsoft 365 with an app registration, for a tenant with smtp auth switched off.', null, ['smtp', 'graph']));
    emailBox.appendChild(field('email_from', 'From address', 'Has to be one the relay or the tenant will let this box send as.'));
    emailBox.appendChild(field('email_from_name', 'From name', 'Optional. The registry name is used when this is empty.'));
    emailBox.appendChild(field('email_malware_alerts', 'Email admins when malware is found',
      'Goes out within a minute of a scan flagging a file MALICIOUS or SUSPICIOUS, to every admin with an email address. Several detections close together share one mail. A file flagged before is not mailed again.', 'check'));
    emailBox.appendChild(field('email_malware_daily', 'Daily malware digest',
      'Once a day, admins get the list of files still held or rejected by a malware scan. Nothing is sent on a day with nothing flagged.', 'check'));

    emailBox.appendChild(h('h3', null, ['Over smtp']));
    emailBox.appendChild(field('smtp_host', 'Server'));
    emailBox.appendChild(field('smtp_port', 'Port', '587 for starttls, 465 for tls, 25 for a relay that wants neither.', 'number'));
    emailBox.appendChild(field('smtp_security', 'Encryption', 'starttls upgrades a plain connection and is what nearly everything wants. tls is encrypted from the first byte. none sends in the clear, and a username and password will be refused over it.', null, ['starttls', 'tls', 'none']));
    emailBox.appendChild(field('smtp_user', 'Username', 'Leave empty for a relay that accepts internal senders without a login.'));
    emailBox.appendChild(field('smtp_password', 'Password', 'Stored on the box and never sent back out. Leave the stars alone to keep the one already set.', 'password'));
    emailBox.appendChild(field('smtp_allow_self_signed', 'Accept a certificate this box cannot verify',
      'For a relay with a certificate somebody made themselves. It means the connection is encrypted but not proven, so only turn it on for a server you can already reach on your own network.', 'check'));

    emailBox.appendChild(h('h3', null, ['Over Microsoft 365']));
    emailBox.appendChild(h('p', { class: 'hint' }, [
      'Register an application in Entra, give it the Mail.Send application permission, grant admin consent, ' +
      'and put the details here. Worth scoping that permission to the one mailbox with an application access ' +
      'policy, or the registration can send as anybody in the tenant.'
    ]));
    emailBox.appendChild(field('graph_tenant', 'Tenant id'));
    emailBox.appendChild(field('graph_client_id', 'Application (client) id'));
    emailBox.appendChild(field('graph_client_secret', 'Client secret', 'Stored on the box and never sent back out.', 'password'));
    emailBox.appendChild(field('graph_sender', 'Mailbox to send from', 'The account the mail goes out as. The From address is used when this is empty.'));

    if (writable) {
      var testTo = h('input', { type: 'text', placeholder: state.me.email || 'you@example.com' });
      var testOut = h('p', { class: 'hint' }, ['']);
      emailBox.appendChild(h('div', { class: 'row' }, [
        h('div', null, [h('label', null, ['Send a test to']), testTo])
      ]));
      emailBox.appendChild(h('div', null, [
        h('button', {
          type: 'button',
          onclick: function () {
            testOut.textContent = 'sending...';
            // save first or the test checks the saved settings, not the ones on screen
            var payload = {};
            Object.keys(fields).forEach(function (key) {
              if (key.indexOf('email_') !== 0 && key.indexOf('smtp_') !== 0 && key.indexOf('graph_') !== 0) return;
              if (key === 'email_enabled') return;
              var f = fields[key];
              payload[key] = f.type === 'check' ? (f.input.checked ? '1' : '0') : f.input.value;
            });
            api('PUT', '/settings', payload)
              .then(function () { return api('POST', '/email/test', { to: testTo.value.trim() }); })
              .then(function (r) { testOut.textContent = 'sent to ' + r.to + '. If it does not arrive, it left this box, so look at the relay.'; })
              .catch(function (e) { testOut.textContent = 'it did not send: ' + e.message; });
          }
        }, ['Send a test']),
        h('button', {
          type: 'button',
          onclick: function () {
            testOut.textContent = 'running...';
            api('POST', '/email/digest/run', {})
              .then(function (r) {
                testOut.textContent = r.skipped
                  ? 'nothing sent: ' + r.skipped
                  : (r.sent ? 'the digest went to ' + r.sent + ' address(es)' : 'nobody was owed anything, so nothing went out');
              })
              .catch(function (e) { testOut.textContent = 'the digest failed: ' + e.message; });
          }
        }, ['Run the digest now'])
      ]));
      emailBox.appendChild(testOut);
    }

    if (mailLog && mailLog.entries && mailLog.entries.length) {
      emailBox.appendChild(h('h3', null, ['The last few that went out']));
      emailBox.appendChild(table(['When', 'To', 'What', 'How', 'Result'], mailLog.entries.map(function (e) {
        return [
          when(e.ts),
          e.to_address,
          e.subject,
          e.transport,
          h('span', { class: e.ok ? 'allow' : 'deny' }, [e.ok ? 'sent' : (e.error || 'failed')])
        ];
      })));
    }
    tab.email.appendChild(emailBox);

    // ---- single sign on ----
    var ssoBox = h('fieldset', null, [h('legend', null, ['Single sign on'])]);
    ssoBox.appendChild(h('p', { class: 'hint' }, [
      'OpenID Connect, which is what Okta, Entra, Google, Keycloak and the rest all speak. People sign in ' +
      'at your provider and come back here with an identity this box checks the signature on. SAML is not ' +
      'supported.'
    ]));
    if (d.ssoProblem) {
      ssoBox.appendChild(notice('Single sign on cannot be used yet: ' + d.ssoProblem, ''));
    }
    if (d.ssoRedirect) {
      ssoBox.appendChild(h('p', { class: 'hint' }, [
        'Register this exact address at the provider as the sign in redirect: ',
        h('span', { class: 'mono' }, [d.ssoRedirect])
      ]));
    }
    ssoBox.appendChild(field('sso_enabled', 'Allow single sign on', 'Off and the login page is the password form and nothing else.', 'check'));
    ssoBox.appendChild(field('sso_mode', 'What is accepted', 'both keeps the password form beside the button. sso_only refuses a password login even with the right password, which is also everybody locked out if the provider goes down. enable_local_login.sh on the server puts it back.', null, ['both', 'sso_only']));
    ssoBox.appendChild(field('oidc_issuer', 'Provider address', 'The issuer, for example https://acme.okta.com/oauth2/default. The configuration is read from it.'));
    ssoBox.appendChild(field('oidc_client_id', 'Client id'));
    ssoBox.appendChild(field('oidc_client_secret', 'Client secret', 'Stored on the box and never sent back out.', 'password'));
    ssoBox.appendChild(field('oidc_scopes', 'Scopes', 'openid is required. profile and email are what fill in the name and the address.'));
    ssoBox.appendChild(field('oidc_redirect_url', 'Redirect address', 'Only needed if it is not the public url with /_api/sso/callback on the end.'));
    ssoBox.appendChild(field('sso_button_label', 'What the button says'));
    ssoBox.appendChild(field('sso_auto_create', 'Make an account on first sign in',
      'Off and somebody the provider lets through still needs an account here first, made by an admin. On is the usual choice.', 'check'));
    ssoBox.appendChild(field('sso_default_role', 'Role a new account comes in as',
      'Admin is not on this list on purpose. People are matched to an existing account by email address first, and an account that already exists keeps whatever role it has. A group below that grants a role beats this.',
      null, ['viewer', 'developer', 'publisher', 'approver']));
    ssoBox.appendChild(field('sso_role_groups', 'Roles from the provider\'s groups',
      'One rule per line: a role, an equals sign, and the groups that grant it, like admin = okta_npm_admins. Several groups are separated by commas, # starts a comment, and case does not matter. Somebody in two of them gets the stronger role. Leave it empty and roles stay as they are set here, by hand.',
      'textarea'));
    ssoBox.appendChild(field('oidc_groups_claim', 'Which claim holds the groups',
      'groups for Okta and Keycloak, roles for some others. The provider has to actually send it: on an Okta custom authorization server the claim goes on the server, not on the app, or it never appears in the token.'));
    ssoBox.appendChild(field('sso_role_sync', 'Keep roles in step on every sign in',
      'On and the groups decide the role every time somebody signs in, so a promotion made here by hand is undone at their next login. Off and the groups only set the role on the account they first make. The last admin left is never demoted either way.', 'check'));
    ssoBox.appendChild(field('sso_require_role_group', 'Refuse anybody no rule matches',
      'On and somebody the provider lets through, who is in none of the groups above, is turned away rather than let in on the default role. Only does anything while there is a mapping to match against. Worth knowing: if the provider stops sending the groups claim at all, this turns everybody away including you, and enable_local_login.sh on the server is the way back in.', 'check'));

    if (writable) {
      var ssoOut = h('p', { class: 'hint' }, ['']);
      ssoBox.appendChild(h('div', null, [
        h('button', {
          type: 'button',
          onclick: function () {
            ssoOut.textContent = 'asking the provider...';
            var payload = {};
            Object.keys(fields).forEach(function (key) {
              if (key.indexOf('sso_') !== 0 && key.indexOf('oidc_') !== 0) return;
              if (key === 'sso_enabled') return;
              var f = fields[key];
              payload[key] = f.type === 'check' ? (f.input.checked ? '1' : '0') : f.input.value;
            });
            api('PUT', '/settings', payload)
              .then(function () { return api('POST', '/sso/test', {}); })
              .then(function (r) {
                ssoOut.textContent = 'the provider answered. Sign in at ' + r.authorization_endpoint +
                  ', keys at ' + r.jwks_uri + '. Send people back to ' + r.redirect + ', which has to be registered there exactly as it reads.';
              })
              .catch(function (e) { ssoOut.textContent = 'that did not work: ' + e.message; });
          }
        }, ['Check the provider'])
      ]));
      ssoBox.appendChild(ssoOut);
    }
    tab.sso.appendChild(ssoBox);

    tab.access.appendChild(h('fieldset', null, [
      h('legend', null, ['Access']),
      field('breakglass_enabled', 'Allow break glass keys', null, 'check'),
      field('breakglass_grant_minutes', 'Default minutes a key grants', null, 'number'),
      field('session_idle_minutes', 'Portal idle timeout in minutes', '0 turns the idle timeout off.', 'number'),
      field('min_password_length', 'Shortest allowed password', null, 'number'),
      field('max_login_attempts', 'Bad passwords before a lockout', null, 'number'),
      field('lockout_minutes', 'How long a lockout lasts', null, 'number')
    ]));

    // lists save as they're edited, Save below has nothing to do with them
    var labelBox = h('fieldset', null, [h('legend', null, ['Applications and environments'])]);
    labelBox.appendChild(h('p', { class: 'hint' }, [
      'What a token is for, and where it runs. A developer picks one of each when they make a token, ' +
      'and both names are written onto every request that token then makes. That is what turns "a ' +
      'malicious version was pulled" into "it is in the checkout api, in production", months later, ' +
      'without needing the token to still exist. Keep the names as few and as steady as you can: two ' +
      'spellings of one application split every report about it.'
    ]));
    labelEditor(labelBox, 'applications', apps, {
      title: 'Applications',
      hint: 'The thing being built. Retiring one keeps it on the tokens already carrying it and stops ' +
        'it being offered for new ones. Deleting is refused while any token still points at it.',
      placeholder: 'checkout-api'
    });
    labelEditor(labelBox, 'environments', envs, {
      title: 'Environments',
      hint: 'Where it runs. Most places need three or four of these and no more. Tick Production on the ones that are, ' +
        'so a dry run can say which applications in production a change would hit.',
      placeholder: 'production',
      production: true
    });
    tab.apps.appendChild(labelBox);

    if (!writable) return;

    var out = h('div', null, []);
    body.appendChild(h('button', {
      onclick: function () {
        var payload = {};
        Object.keys(fields).forEach(function (key) {
          var f = fields[key];
          payload[key] = f.type === 'check' ? (f.input.checked ? '1' : '0') : f.input.value;
        });
        delete payload.acl_enabled;
        api('PUT', '/settings', payload)
          .then(function () {
            clear(out);
            out.appendChild(notice('Saved.', 'ok'));
            return boot(true).then(function () {
              var name = document.querySelector('.topbar .brand span');
              if (name) name.textContent = state.registryName || 'ForgeRepo';
            });
          })
          .catch(function (e) { clear(out); out.appendChild(notice(e.message, 'err')); });
      }
    }, ['Save settings']));
    body.appendChild(out);
  });
}

// the old registries page opens straight on its tab
function openSettingsTab(id) {
  settingsTab = id;
}

export { openSettingsTab, viewSettings };
