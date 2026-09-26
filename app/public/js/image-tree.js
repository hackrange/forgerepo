// ForgeRepo portal: what an image is made of, drawn for the dependency tree.
// Author: Tim Rice

import { h, link } from './dom.js';
import { bytes, clear, notice, table } from './ui.js';
import { api, download } from './api.js';

function sevCell(c) {
  if (!c.advisories) return h('span', { class: 'muted' }, ['none known']);
  var s = String(c.severity || 'unrated');
  return h('span', { class: s === 'CRITICAL' || s === 'HIGH' ? 'deny' : null }, [s.toLowerCase()]);
}

function scanLine(p) {
  var s = p.scan;
  if (p.queued || (s && (s.status === 'queued' || s.status === 'scanning'))) return 'Being scanned now, the packages show here when it finishes.';
  if (!s) return 'Not scanned yet. An image is scanned when it is pulled through here, or when someone who decides on images starts it below.';
  if (s.status === 'failed') return 'The scan could not finish: ' + (s.error || 'no reason was given') + '.';
  if (s.status === 'skipped') return 'Nothing to scan: ' + ((s.notes || [])[0] || 'it is not an image that runs') + '.';
  return (s.os || 'An operating system that could not be read') + (s.feed ? ', matched against the ' + s.feed + ' advisories. ' : '. ') +
    s.components + ' packages, ' + s.vulnerable + ' with a known advisory.';
}

function platformBox(p, onlyVulnerable) {
  var rows = onlyVulnerable ? p.packages.filter(function (c) { return c.advisories; }) : p.packages;
  var box = h('fieldset', null, [
    h('legend', null, [p.platform]),
    h('p', { class: 'hint mono digest' }, [p.digest]),
    h('p', { class: 'hint' }, [p.layers.length + ' layer' + (p.layers.length === 1 ? '' : 's') + ', ' + bytes(p.bytes) + ' to pull. ' + scanLine(p)]),
    (p.scan && p.scan.notes && p.scan.notes.length) ? h('ul', { class: 'hint' }, p.scan.notes.map(function (n) { return h('li', null, [n]); })) : null
  ]);
  if (p.packages.length) {
    box.appendChild(rows.length
      ? table(['Package', 'Kind', 'Installed', 'Severity', 'Fixed in', 'CVE', 'What it is'], rows.map(function (c) {
        return [
          h('span', { class: 'mono', title: (c.binaries || []).length ? 'installed as ' + c.binaries.join(', ') : null }, [c.name]),
          c.type,
          h('span', { class: 'mono' }, [c.version]),
          sevCell(c),
          c.fixed_in ? h('span', { class: 'mono' }, [c.fixed_in]) : (c.advisories ? h('span', { class: 'muted' }, ['no fix yet']) : ''),
          c.cves || '',
          c.summary || ''
        ];
      }))
      : h('p', { class: 'hint' }, ['No package in this image has a known advisory against it.']));
  }
  var layers = h('details', null, [
    h('summary', null, ['Layers']),
    table(['Digest', { label: 'Size', num: true }], p.layers.map(function (l) {
      return [h('span', { class: 'mono digest' }, [l.digest]), l.size === null ? '' : bytes(l.size)];
    }))
  ]);
  box.appendChild(layers);
  return box;
}

// d is what /tools/resolve answers for an image. again(scan) walks it once more
function drawImageTree(out, d, again) {
  clear(out);
  var s = d.summary;
  out.appendChild(notice(
    d.root + (d.list ? ' is a list of ' + s.platforms + ' platform image' + (s.platforms === 1 ? '' : 's') : ' is one image') +
    ' with ' + s.layers + ' layer' + (s.layers === 1 ? '' : 's') + '. ' +
    (d.allowed ? 'The rules allow it. ' : 'It would be refused right now: ' + d.reason + '. ') +
    (s.scanned ? s.packages + ' packages found inside, ' + s.vulnerable + ' with a known advisory.' : ''),
    d.allowed && !s.vulnerable ? 'ok' : 'err'
  ));
  out.appendChild(h('p', { class: 'hint mono digest' }, [d.digest]));

  var onlyVulnerable = s.vulnerable > 0;
  var boxes = h('div', null, []);
  function draw() {
    clear(boxes);
    d.platforms.forEach(function (p) { boxes.appendChild(platformBox(p, onlyVulnerable)); });
  }
  var controls = h('div', null, []);
  if (s.packages) {
    controls.appendChild(h('button', {
      type: 'button',
      onclick: function (e) {
        onlyVulnerable = !onlyVulnerable;
        e.target.textContent = onlyVulnerable ? 'Every package' : 'Only the vulnerable packages';
        draw();
      }
    }, [onlyVulnerable ? 'Every package' : 'Only the vulnerable packages']));
  }
  var unscanned = d.platforms.filter(function (p) { return !p.scan || p.scan.status === 'failed'; }).length;
  if (unscanned && d.canScan) {
    controls.appendChild(h('button', { type: 'button', class: 'primary', onclick: function () { again(true); } },
      ['Scan ' + (unscanned === 1 ? 'it' : 'the ' + unscanned + ' platform images') + ' now']));
  } else if (unscanned && !d.scanning) {
    out.appendChild(h('p', { class: 'hint muted' }, ['Image scanning is switched off on the Vulnerabilities page.']));
  }
  if (d.skipped && d.skipped.length) {
    var one = d.skipped.length === 1;
    out.appendChild(h('p', { class: 'hint' }, [d.skipped.length + ' entr' + (one ? 'y' : 'ies') + ' in the list left out. ' + (one ? 'It is ' : 'Each is ') +
      d.skipped.map(function (x) { return x.why; }).filter(function (w, i, all) { return all.indexOf(w) === i; }).join(' or ') + '.']));
  }
  // everything found inside, as a file a scanner or an auditor can read
  if (s.scanned && d.repository) {
    var sbomOf = function (format) {
      download('/sbom/image?repository=' + encodeURIComponent(d.repository) + '&reference=' + encodeURIComponent(d.digest) + '&format=' + format,
        d.repository.replace(/[^A-Za-z0-9._-]+/g, '_') + '.' + (format === 'spdx' ? 'spdx' : 'cdx') + '.json');
    };
    controls.appendChild(h('span', { class: 'hint' }, [' SBOM of what is inside: ',
      link('CycloneDX', function () { sbomOf('cyclonedx'); }), ' or ', link('SPDX', function () { sbomOf('spdx'); })]));
  }
  out.appendChild(controls);
  out.appendChild(boxes);
  draw();

  // a scan in flight: look again every few seconds, for a few minutes
  if (s.waiting) {
    var tries = 0;
    var timer = setInterval(function () {
      tries += 1;
      if (!out.isConnected || tries > 60) return clearInterval(timer);
      again(false, function (next) {
        if (!next.summary.waiting) {
          clearInterval(timer);
          drawImageTree(out, next, again);
        }
      });
    }, 5000);
  }
}

function resolveImage(name, range, out) {
  function again(scan, quiet) {
    if (!quiet) {
      clear(out);
      out.appendChild(h('p', { class: 'muted' }, [scan ? 'Starting the scan...' : 'Reading the image...']));
    }
    api('POST', '/tools/resolve', { ecosystem: 'oci', name: name, version_range: range || 'latest', scan: !!scan })
      .then(function (d) {
        if (quiet) return quiet(d);
        drawImageTree(out, d, again);
      })
      .catch(function (e) {
        if (quiet) return;
        clear(out);
        out.appendChild(notice(e.message, 'err'));
      });
  }
  again(false);
}

export { drawImageTree, resolveImage };
