// ForgeRepo portal: diagrams in the documentation, drawn from data so the page and the PDF show the same picture.
// Author: Tim Rice
//
// a diagram is boxes and arrows on a grid. kinds say what a box is (a client, this registry, an outside service, a
// decision, a good or a bad outcome) and the stylesheet colors them, so they follow light and dark mode

import { fill } from './vars.js';

var SVGNS = 'http://www.w3.org/2000/svg';
var specs = {};

function register(id, spec) {
  specs[id] = spec;
}

function el(tag, attrs, kids) {
  var node = document.createElementNS(SVGNS, tag);
  Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
  (kids || []).forEach(function (k) { if (k) node.appendChild(k); });
  return node;
}

// where a line from the middle of a box toward (x, y) leaves the box
function edgePoint(n, x, y) {
  var cx = n.x + n.w / 2;
  var cy = n.y + n.h / 2;
  var dx = x - cx;
  var dy = y - cy;
  if (!dx && !dy) return { x: cx, y: cy };
  var sx = dx ? (n.w / 2) / Math.abs(dx) : Infinity;
  var sy = dy ? (n.h / 2) / Math.abs(dy) : Infinity;
  var s = Math.min(sx, sy);
  return { x: cx + dx * s, y: cy + dy * s };
}

// the lines a label is broken into to fit its box, at roughly 7px a character
function wrap(text, width, charW) {
  var max = Math.max(4, Math.floor((width - 12) / (charW || 7)));
  var lines = [];
  String(text).split('\n').forEach(function (para) {
    var line = '';
    para.split(' ').forEach(function (word) {
      if ((line + ' ' + word).trim().length > max && line) {
        lines.push(line);
        line = word;
      } else {
        line = (line + ' ' + word).trim();
      }
    });
    lines.push(line);
  });
  return lines;
}

function geometry(spec, vars) {
  var byId = {};
  spec.nodes.forEach(function (n) { byId[n.id] = n; });
  var lines = spec.edges.map(function (e) {
    var a = byId[e.from];
    var b = byId[e.to];
    var p1 = edgePoint(a, b.x + b.w / 2, b.y + b.h / 2);
    var p2 = edgePoint(b, a.x + a.w / 2, a.y + a.h / 2);
    return { x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y, label: e.label ? fill(e.label, vars) : '', kind: e.kind || '' };
  });
  return { byId: byId, lines: lines };
}

function diagram(id, vars) {
  var spec = specs[id];
  if (!spec) return document.createTextNode('(diagram ' + id + ' is missing)');
  var g = geometry(spec, vars);
  var svg = el('svg', { viewBox: '0 0 ' + spec.w + ' ' + spec.h, class: 'dgm', role: 'img', 'aria-label': fill(spec.title || id, vars) });
  svg.appendChild(el('defs', {}, [
    el('marker', { id: 'dgm-arrow', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' }, [
      el('path', { d: 'M 0 0 L 10 5 L 0 10 z', class: 'dgm-arrowhead' })
    ])
  ]));
  g.lines.forEach(function (l) {
    svg.appendChild(el('line', { x1: l.x1, y1: l.y1, x2: l.x2, y2: l.y2, class: 'dgm-edge ' + l.kind, 'marker-end': 'url(#dgm-arrow)' }));
  });
  spec.nodes.forEach(function (n) {
    svg.appendChild(el('rect', { x: n.x, y: n.y, width: n.w, height: n.h, rx: n.kind === 'decision' ? 18 : 6, class: 'dgm-node ' + (n.kind || '') }));
    var lines = wrap(fill(n.text, vars), n.w);
    var top = n.y + n.h / 2 - (lines.length - 1) * 8;
    lines.forEach(function (line, i) {
      var t = el('text', { x: n.x + n.w / 2, y: top + i * 16 + 5, class: 'dgm-text' + (n.kind === 'registry' ? ' on-dark' : ''), 'text-anchor': 'middle' });
      t.textContent = line;
      svg.appendChild(t);
    });
  });
  // labels last, centered in the gap between the boxes, so no box is drawn over them
  g.lines.forEach(function (l) {
    if (!l.label) return;
    var t = el('text', { x: (l.x1 + l.x2) / 2, y: (l.y1 + l.y2) / 2 - 5, class: 'dgm-edge-label', 'text-anchor': 'middle' });
    t.textContent = l.label;
    svg.appendChild(t);
  });
  return svg;
}

export { register, diagram, geometry, wrap, specs };
