// ForgeRepo portal: the documentation as a PDF, written in the browser from the same topics the page shows.
// Author: Tim Rice
//
// no library and nothing sent anywhere. US Letter, the standard PDF fonts, screenshots as JPEG, diagrams drawn as
// lines and boxes, and the confidential line at the foot of every page. two passes: lay everything out, then write
// the page numbers once the total is known

import { fill } from './vars.js';
import { plain } from './render.js';
import { geometry, specs, wrap as wrapLabel } from './diagrams.js';

var PAGE_W = 612;
var PAGE_H = 792;
var MARGIN = 54;
var TOP = PAGE_H - 72;
var BOTTOM = 72;
var WIDTH = PAGE_W - MARGIN * 2;
var FOOTER = 'CONFIDENTIAL - For Internal Use Only';

// widths per 1000 units for WinAnsi 32..126
var HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
  278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722,
  667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556,
  333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];
var HELV_B = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
  333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722,
  667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611,
  389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584];

// the standard fonts only know Latin text. curly quotes and the like become their plain forms, anything else a ?
function ascii(text) {
  return String(text).replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"').replace(/[\u2013\u2014]/g, '-')
    .replace(/\u2026/g, '...').replace(/[\u2022\u00b7]/g, '-').replace(/\u00a0/g, ' ').replace(/\t/g, '  ')
    // yarn and friends draw with box characters and arrows, base-14 fonts have none of them
    .replace(/[\u2502\u2503]/g, '|').replace(/[\u2514\u2517\u250c\u250f\u251c\u2523]/g, '+').replace(/[\u2500\u2501]/g, '-')
    .replace(/[\u27a4\u25b6\u2192\u279c]/g, '>').replace(/\u2713/g, 'v').replace(/\u2717/g, 'x')
    .replace(/[^\x20-\x7e\n]/g, '?');
}

function widthOf(text, font, size) {
  if (font === 'C') return text.length * 600 * size / 1000;
  var table = font === 'HB' ? HELV_B : HELV;
  var w = 0;
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charCodeAt(i);
    w += (c >= 32 && c <= 126) ? table[c - 32] : 556;
  }
  return w * size / 1000;
}

function wrapText(text, font, size, width) {
  var out = [];
  ascii(text).split('\n').forEach(function (para) {
    var line = '';
    para.split(' ').forEach(function (word) {
      var next = line ? line + ' ' + word : word;
      if (widthOf(next, font, size) <= width || !line) {
        // a single word wider than the line is cut, rather than running off the page
        while (widthOf(next, font, size) > width && next.length > 1) {
          var cut = next.length - 1;
          while (cut > 1 && widthOf(next.slice(0, cut), font, size) > width) cut -= 1;
          out.push(next.slice(0, cut));
          next = next.slice(cut);
        }
        line = next;
      } else {
        out.push(line);
        line = word;
      }
    });
    out.push(line);
  });
  return out;
}

function esc(text) {
  return ascii(text).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

var FONT_NAME = { H: '/F1', HB: '/F2', C: '/F3' };

function rgb(hex) {
  var n = parseInt(hex.slice(1), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255].map(function (v) { return v.toFixed(3); }).join(' ');
}

// ---------------------------------------------------------------- layout

function Layout(meta) {
  this.meta = meta;
  this.pages = [];
  this.images = [];
  this.newPage();
}

Layout.prototype.newPage = function () {
  this.ops = [];
  this.pages.push(this.ops);
  this.y = TOP;
};

Layout.prototype.ensure = function (height) {
  if (this.y - height < BOTTOM) this.newPage();
};

Layout.prototype.text = function (x, y, text, font, size, color) {
  this.ops.push('BT ' + FONT_NAME[font] + ' ' + size + ' Tf ' + rgb(color || '#141414') + ' rg ' + x.toFixed(2) + ' ' + y.toFixed(2) + ' Td (' + esc(text) + ') Tj ET');
};

Layout.prototype.rect = function (x, y, w, h, fillColor, strokeColor) {
  var op = x.toFixed(2) + ' ' + y.toFixed(2) + ' ' + w.toFixed(2) + ' ' + h.toFixed(2) + ' re ';
  if (fillColor) this.ops.push(rgb(fillColor) + ' rg ' + op + 'f');
  if (strokeColor) this.ops.push(rgb(strokeColor) + ' RG 0.8 w ' + op + 'S');
};

Layout.prototype.line = function (x1, y1, x2, y2, color, width) {
  this.ops.push(rgb(color) + ' RG ' + (width || 1) + ' w ' + x1.toFixed(2) + ' ' + y1.toFixed(2) + ' m ' + x2.toFixed(2) + ' ' + y2.toFixed(2) + ' l S');
};

Layout.prototype.paragraph = function (text, opts) {
  var o = opts || {};
  var size = o.size || 10.5;
  var lead = size * 1.45;
  var indent = o.indent || 0;
  var lines = wrapText(text, o.font || 'H', size, WIDTH - indent);
  var self = this;
  lines.forEach(function (line, i) {
    self.ensure(lead);
    if (i === 0 && o.marker) self.text(MARGIN + indent - 14, self.y - size, o.marker, 'H', size, o.color);
    self.text(MARGIN + indent, self.y - size, line, o.font || 'H', size, o.color);
    self.y -= lead;
  });
  this.y -= o.after === undefined ? 5 : o.after;
};

Layout.prototype.heading = function (text, level) {
  var size = level === 1 ? 18 : 13;
  this.ensure(size * 3);
  this.y -= level === 1 ? 6 : 8;
  this.paragraph(text, { font: 'HB', size: size, after: level === 1 ? 4 : 2 });
  if (level === 1) {
    this.line(MARGIN, this.y + 2, PAGE_W - MARGIN, this.y + 2, '#c8c8c8', 0.8);
    this.y -= 8;
  }
};

// a box of monospaced lines, split across pages if it has to be
Layout.prototype.mono = function (lines, dark, label) {
  var size = 8.5;
  var lead = 11;
  var pad = 7;
  var wrapped = [];
  lines.forEach(function (l) {
    wrapText(l.text, 'C', size, WIDTH - pad * 2).forEach(function (w) { wrapped.push({ text: w, kind: l.kind }); });
  });
  var self = this;
  var i = 0;
  if (label) {
    this.ensure(lead * 3);
    this.text(MARGIN, this.y - 8, label, 'HB', 8, '#5c5c5c');
    this.y -= 12;
  }
  while (i < wrapped.length) {
    var room = Math.floor((this.y - BOTTOM - pad * 2) / lead);
    if (room < 3) {
      this.newPage();
      continue;
    }
    var chunk = wrapped.slice(i, i + room);
    var height = chunk.length * lead + pad * 2;
    this.rect(MARGIN, this.y - height, WIDTH, height, dark ? '#1e1e1e' : '#f3f3f3', dark ? null : '#e0e0e0');
    chunk.forEach(function (l, n) {
      var color = dark ? (l.kind === 'cmd' ? '#ffffff' : '#c8c8c8') : '#141414';
      self.text(MARGIN + pad, self.y - pad - (n + 1) * lead + 3, l.text, 'C', size, color);
    });
    this.y -= height + 8;
    i += chunk.length;
  }
};

Layout.prototype.image = function (img, caption, marks) {
  // a screen pixel printed as a whole point looks blown up next to 10pt text, so small pictures stay small
  var scale = Math.min(0.62, WIDTH / img.w, (TOP - BOTTOM - 40) / img.h);
  // not enough room left: shrink it into the space when that still leaves it readable, instead of a half empty page
  var room = this.y - BOTTOM - 24;
  if (img.h * scale > room && room >= 220 && room >= img.h * scale * 0.6) scale = room / img.h;
  var w = img.w * scale;
  var h = img.h * scale;
  this.ensure(h + 24);
  var x = MARGIN;
  var y = this.y - h;
  var name = '/Im' + (this.images.length + 1);
  this.images.push({ name: name, data: img.data, w: img.pw, h: img.ph });
  this.ops.push('q ' + w.toFixed(2) + ' 0 0 ' + h.toFixed(2) + ' ' + x.toFixed(2) + ' ' + y.toFixed(2) + ' cm ' + name + ' Do Q');
  this.rect(x, y, w, h, null, '#c8c8c8');
  var self = this;
  (marks || []).forEach(function (m, n) {
    var mx = x + m.x / img.w * w;
    var my = y + h - (m.y + m.h) / img.h * h;
    self.ops.push(rgb('#b42318') + ' RG 1.6 w ' + mx.toFixed(2) + ' ' + my.toFixed(2) + ' ' + (m.w / img.w * w).toFixed(2) + ' ' + (m.h / img.h * h).toFixed(2) + ' re S');
    self.rect(mx - 6, my + m.h / img.h * h - 6, 12, 12, '#b42318');
    self.text(mx - 3, my + m.h / img.h * h - 3, String(n + 1), 'HB', 8, '#ffffff');
  });
  this.y = y - 6;
  if (caption) this.paragraph(caption, { size: 9, color: '#5c5c5c', after: 2 });
  (marks || []).forEach(function (m, n) {
    self.paragraph(m.label, { size: 9, indent: 16, marker: (n + 1) + '.', after: 0 });
  });
  this.y -= 6;
};

Layout.prototype.diagram = function (spec, vars, caption) {
  var scale = Math.min(1, WIDTH / spec.w);
  var h = spec.h * scale;
  this.ensure(h + 20);
  var ox = MARGIN;
  var oy = this.y;
  var X = function (x) { return ox + x * scale; };
  var Y = function (y) { return oy - y * scale; };
  var g = geometry(spec, vars);
  var self = this;
  g.lines.forEach(function (l) {
    self.line(X(l.x1), Y(l.y1), X(l.x2), Y(l.y2), '#5c5c5c', 1);
    var ang = Math.atan2(Y(l.y2) - Y(l.y1), X(l.x2) - X(l.x1));
    var ax = X(l.x2);
    var ay = Y(l.y2);
    self.ops.push(rgb('#5c5c5c') + ' rg ' + ax.toFixed(2) + ' ' + ay.toFixed(2) + ' m ' +
      (ax - 7 * Math.cos(ang - 0.4)).toFixed(2) + ' ' + (ay - 7 * Math.sin(ang - 0.4)).toFixed(2) + ' l ' +
      (ax - 7 * Math.cos(ang + 0.4)).toFixed(2) + ' ' + (ay - 7 * Math.sin(ang + 0.4)).toFixed(2) + ' l f');
  });
  var fills = { client: '#eaf1f8', registry: '#141414', outside: '#f6f6f6', decision: '#fdf6e3', good: '#eaf4ec', bad: '#fdeceb' };
  spec.nodes.forEach(function (n) {
    var dark = n.kind === 'registry';
    self.rect(X(n.x), Y(n.y + n.h), n.w * scale, n.h * scale, fills[n.kind] || '#ffffff', '#8a8a8a');
    var lines = wrapLabel(fill(n.text, vars), n.w, 7);
    var size = Math.max(6, 9 * scale);
    lines.forEach(function (line, i) {
      var tw = widthOf(ascii(line), 'H', size);
      var ty = Y(n.y + n.h / 2) + (lines.length - 1) * size * 0.6 - i * size * 1.2 - size * 0.35;
      self.text(X(n.x + n.w / 2) - tw / 2, ty, line, 'H', size, dark ? '#ffffff' : '#141414');
    });
  });
  // labels after the boxes, same as the page
  g.lines.forEach(function (l) {
    if (!l.label) return;
    var text = ascii(l.label);
    self.text(X((l.x1 + l.x2) / 2) - widthOf(text, 'H', 7) / 2, Y((l.y1 + l.y2) / 2) + 3, text, 'H', 7, '#5c5c5c');
  });
  this.y = oy - h - 6;
  if (caption) this.paragraph(caption, { size: 9, color: '#5c5c5c' });
};

// ---------------------------------------------------------------- images

function loadImage(src) {
  return new Promise(function (resolve) {
    var img = new Image();
    img.onload = function () {
      var canvas = document.createElement('canvas');
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      var cx = canvas.getContext('2d');
      cx.fillStyle = '#ffffff';
      cx.fillRect(0, 0, canvas.width, canvas.height);
      cx.drawImage(img, 0, 0);
      var b64 = canvas.toDataURL('image/jpeg', 0.86).split(',')[1];
      var bin = atob(b64);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      resolve({ data: bytes, pw: canvas.width, ph: canvas.height });
    };
    img.onerror = function () { resolve(null); };
    img.src = src;
  });
}

// ---------------------------------------------------------------- the file

function encode(text) {
  var out = new Uint8Array(text.length);
  for (var i = 0; i < text.length; i += 1) out[i] = text.charCodeAt(i) & 255;
  return out;
}

function assemble(pages, images, meta) {
  var chunks = [];
  var offsets = [];
  var length = 0;
  var push = function (part) {
    var bytes = typeof part === 'string' ? encode(part) : part;
    chunks.push(bytes);
    length += bytes.length;
  };
  var objects = [];
  var obj = function (body) {
    objects.push(body);
    return objects.length;
  };
  // 1 catalog, 2 pages, 3-5 fonts, then images, then page contents and pages
  obj(null);
  obj(null);
  var fonts = [obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),
    obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'),
    obj('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>')];
  var imageIds = images.map(function (im) {
    return obj({ head: '<< /Type /XObject /Subtype /Image /Width ' + im.w + ' /Height ' + im.h +
      ' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ' + im.data.length + ' >>', data: im.data });
  });
  var xobjects = images.map(function (im, n) { return im.name + ' ' + imageIds[n] + ' 0 R'; }).join(' ');
  var pageIds = [];
  pages.forEach(function (ops) {
    var stream = ops.join('\n');
    var content = obj('<< /Length ' + encode(stream).length + ' >>\nstream\n' + stream + '\nendstream');
    pageIds.push(obj('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + PAGE_W + ' ' + PAGE_H + '] /Contents ' + content + ' 0 R' +
      ' /Resources << /Font << /F1 ' + fonts[0] + ' 0 R /F2 ' + fonts[1] + ' 0 R /F3 ' + fonts[2] + ' 0 R >>' +
      (xobjects ? ' /XObject << ' + xobjects + ' >>' : '') + ' >> >>'));
  });
  objects[0] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[1] = '<< /Type /Pages /Kids [' + pageIds.map(function (id) { return id + ' 0 R'; }).join(' ') + '] /Count ' + pageIds.length + ' >>';
  var info = obj('<< /Title (' + esc(meta.title) + ') /Producer (' + esc(meta.name) + ') /CreationDate (D:' + meta.stamp + ') >>');

  push('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n');
  objects.forEach(function (body, n) {
    offsets.push(length);
    if (body && body.data) {
      push((n + 1) + ' 0 obj\n' + body.head + '\nstream\n');
      push(body.data);
      push('\nendstream\nendobj\n');
    } else {
      push((n + 1) + ' 0 obj\n' + body + '\nendobj\n');
    }
  });
  var xref = length;
  push('xref\n0 ' + (objects.length + 1) + '\n0000000000 65535 f \n' + offsets.map(function (o) { return String(o).padStart(10, '0') + ' 00000 n \n'; }).join(''));
  push('trailer\n<< /Size ' + (objects.length + 1) + ' /Root 1 0 R /Info ' + info + ' 0 R >>\nstartxref\n' + xref + '\n%%EOF\n');
  return new Blob(chunks, { type: 'application/pdf' });
}

// guide: { title, groups: [{ label, topics }] }, ctx: { vars, shots, terminals, imageBase }
async function build(guide, ctx) {
  var vars = ctx.vars;
  var meta = { name: vars.name, title: vars.name + ' ' + guide.title, stamp: vars.today.replace(/-/g, '') + '000000' };
  var L = new Layout(meta);

  // cover
  if (ctx.logo) {
    var logo = await loadImage(ctx.logo);
    if (logo) {
      var name = '/Im' + (L.images.length + 1);
      L.images.push({ name: name, data: logo.data, w: logo.pw, h: logo.ph });
      L.ops.push('q 64 0 0 64 ' + MARGIN + ' ' + (TOP - 90) + ' cm ' + name + ' Do Q');
    }
  }
  L.y = TOP - 130;
  L.paragraph(vars.name, { font: 'HB', size: 30, after: 6 });
  L.paragraph(guide.title, { font: 'H', size: 20, color: '#5c5c5c', after: 24 });
  L.paragraph('For ' + vars.host, { size: 12, after: 4 });
  L.paragraph('Prepared for ' + vars.user + ' on ' + vars.today, { size: 12, color: '#5c5c5c', after: 30 });
  L.paragraph('Every address and example in this guide is written for ' + vars.host + '. It covers what your account is allowed to do, so another person may see a different guide.', { size: 10.5, color: '#5c5c5c' });

  // contents, filled in with page numbers once the rest is laid out
  L.newPage();
  var tocPage = L.pages.length - 1;
  var tocEntries = [];
  guide.groups.forEach(function (g) {
    tocEntries.push({ label: g.label, group: true });
    g.topics.forEach(function (t) { tocEntries.push({ label: fill(t.title, vars), id: t.id }); });
  });
  var perPage = Math.floor((TOP - BOTTOM - 40) / 16);
  var tocPages = Math.max(1, Math.ceil(tocEntries.length / perPage));
  for (var p = 1; p < tocPages; p += 1) L.newPage();

  var startPage = {};
  for (var gi = 0; gi < guide.groups.length; gi += 1) {
    var group = guide.groups[gi];
    for (var ti = 0; ti < group.topics.length; ti += 1) {
      var topic = group.topics[ti];
      L.newPage();
      startPage[topic.id] = L.pages.length;
      L.paragraph(group.label.toUpperCase(), { font: 'HB', size: 8, color: '#8a8a8a', after: 2 });
      L.heading(fill(topic.title, vars), 1);
      if (topic.summary) L.paragraph(plain(topic.summary, vars), { size: 11, color: '#5c5c5c', after: 8 });
      for (var bi = 0; bi < (topic.blocks || []).length; bi += 1) {
        var b = topic.blocks[bi];
        if (b.t === 'p') L.paragraph(plain(b.text, vars));
        else if (b.t === 'h') L.heading(fill(b.text, vars), 2);
        else if (b.t === 'list') b.items.forEach(function (item) { L.paragraph(plain(item, vars), { indent: 16, marker: '-', after: 2 }); });
        else if (b.t === 'steps') b.items.forEach(function (item, n) { L.paragraph(plain(item, vars), { indent: 18, marker: (n + 1) + '.', after: 3 }); });
        else if (b.t === 'tip' || b.t === 'note' || b.t === 'warn') {
          var label = { tip: 'Tip. ', note: 'Good to know. ', warn: 'Be careful. ' }[b.t];
          L.y -= 2;
          var before = L.y;
          L.paragraph(label + plain(b.text, vars), { indent: 10, size: 10, after: 4 });
          if (L.y < before) L.rect(MARGIN, L.y + 4, 3, before - L.y - 4, b.t === 'warn' ? '#9a6700' : '#1f4f82');
        } else if (b.t === 'code') {
          L.mono(fill(b.text, vars).split('\n').map(function (text) { return { text: text }; }), false, b.file ? fill(b.file, vars) : null);
        } else if (b.t === 'term' && ctx.terminals[b.id]) {
          var session = ctx.terminals[b.id];
          var lines = [];
          session.steps.forEach(function (s) {
            lines.push({ text: '$ ' + fill(s.cmd, vars), kind: 'cmd' });
            fill(s.out || '', vars).replace(/\n$/, '').split('\n').forEach(function (text) { if (text || s.out) lines.push({ text: text, kind: 'out' }); });
          });
          L.mono(lines, true, fill(session.title || 'Terminal', vars));
        } else if (b.t === 'shot' && ctx.shots[b.id]) {
          var s = ctx.shots[b.id];
          var loaded = await loadImage(ctx.imageBase + s.file);
          if (loaded) L.image({ data: loaded.data, pw: loaded.pw, ph: loaded.ph, w: s.w, h: s.h }, b.caption, s.marks);
        } else if (b.t === 'table') {
          var cols = b.head.length;
          var colW = WIDTH / cols;
          var rowOut = function (cells, bold) {
            var wrapped = cells.map(function (c) { return wrapText(plain(c, vars), bold ? 'HB' : 'H', 9, colW - 8); });
            var height = Math.max.apply(null, wrapped.map(function (w) { return w.length; })) * 12 + 6;
            L.ensure(height);
            if (bold) L.rect(MARGIN, L.y - height, WIDTH, height, '#f3f3f3');
            wrapped.forEach(function (w, ci) {
              w.forEach(function (line, li) { L.text(MARGIN + ci * colW + 4, L.y - 12 - li * 12, line, bold ? 'HB' : 'H', 9); });
            });
            L.y -= height;
            L.line(MARGIN, L.y, PAGE_W - MARGIN, L.y, '#e0e0e0', 0.5);
          };
          rowOut(b.head, true);
          b.rows.forEach(function (r) { rowOut(r, false); });
          L.y -= 8;
        } else if (b.t === 'diagram' && specs[b.id]) {
          L.diagram(specs[b.id], vars, b.caption ? fill(b.caption, vars) : null);
        }
      }
    }
  }

  // contents with page numbers
  var tocLine = 0;
  for (var e = 0; e < tocEntries.length; e += 1) {
    var page = tocPage + Math.floor(tocLine / perPage);
    var y = TOP - 30 - (tocLine % perPage) * 16;
    L.ops = L.pages[page];
    if (tocLine % perPage === 0) L.text(MARGIN, TOP, 'Contents', 'HB', 16);
    var entry = tocEntries[e];
    if (entry.group) {
      L.text(MARGIN, y, entry.label, 'HB', 10.5);
    } else {
      var num = String(startPage[entry.id] || '');
      L.text(MARGIN + 14, y, entry.label, 'H', 10);
      L.text(PAGE_W - MARGIN - widthOf(num, 'H', 10), y, num, 'H', 10);
    }
    tocLine += 1;
  }

  // header and the confidential footer on every page
  var total = L.pages.length;
  L.pages.forEach(function (ops, n) {
    L.ops = ops;
    if (n > 0) {
      L.text(MARGIN, PAGE_H - 36, ascii(vars.name + ' ' + guide.title), 'H', 8, '#8a8a8a');
      L.line(MARGIN, PAGE_H - 42, PAGE_W - MARGIN, PAGE_H - 42, '#e0e0e0', 0.5);
    }
    L.line(MARGIN, 50, PAGE_W - MARGIN, 50, '#e0e0e0', 0.5);
    L.text((PAGE_W - widthOf(FOOTER, 'HB', 8.5)) / 2, 36, FOOTER, 'HB', 8.5, '#b42318');
    L.text(MARGIN, 36, vars.host, 'H', 8, '#8a8a8a');
    var label = 'Page ' + (n + 1) + ' of ' + total;
    L.text(PAGE_W - MARGIN - widthOf(label, 'H', 8), 36, label, 'H', 8, '#8a8a8a');
  });

  return assemble(L.pages, L.images, meta);
}

export { build, wrapText, widthOf, ascii, FOOTER };
