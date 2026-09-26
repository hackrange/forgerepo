// ForgeRepo portal: drawing a documentation topic from its blocks.
// Author: Tim Rice
//
// topics are data, not html. text goes in with textContent, so nothing written in a topic can turn into markup,
// and the same blocks make the page, the search index and the PDF

import { h } from '../dom.js';
import { svgIcon } from '../ui.js';
import { fill } from './vars.js';
import { terminal, copyText } from './terminal.js';
import { diagram } from './diagrams.js';

// **bold**, `code` and [words](#docs/topic) inside a line of text. nothing else is special
function inline(text, vars) {
  var s = fill(text, vars);
  var out = [];
  var re = /\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\((#[a-z0-9/?=&._-]+)\)/g;
  var last = 0;
  var m;
  while ((m = re.exec(s))) {
    if (m.index > last) out.push(document.createTextNode(s.slice(last, m.index)));
    if (m[1]) out.push(h('strong', null, [m[1]]));
    else if (m[2]) out.push(h('code', null, [m[2]]));
    else out.push(h('a', { href: m[4] }, [m[3]]));
    last = re.lastIndex;
  }
  if (last < s.length) out.push(document.createTextNode(s.slice(last)));
  return out;
}

// the same text without the marks, for search and the PDF
function plain(text, vars) {
  return fill(text, vars).replace(/\*\*([^*]+)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
}

function codeBlock(block, vars) {
  var text = fill(block.text, vars);
  var copy = h('button', { type: 'button', class: 'btn sm' }, ['Copy']);
  copy.addEventListener('click', function () { copyText(text, copy); });
  return h('figure', { class: 'code' }, [
    h('div', { class: 'code-bar' }, [h('span', { class: 'code-file' }, [block.file ? fill(block.file, vars) : (block.lang || 'text')]), copy]),
    h('pre', null, [h('code', null, [text])])
  ]);
}

// a screenshot with the parts the steps talk about outlined and numbered
function shot(block, shots) {
  var s = shots[block.id];
  if (!s) return h('p', { class: 'hint muted' }, ['(screenshot ' + block.id + ' is missing)']);
  var img = h('img', { src: 'docs/img/' + s.file, alt: s.alt || block.caption || '', width: String(s.w), height: String(s.h), loading: 'lazy' });
  var frame = h('div', { class: 'shot-frame' }, [img]);
  (s.marks || []).forEach(function (mark, n) {
    var box = h('span', { class: 'shot-mark', title: mark.label || '' }, [h('b', null, [String(n + 1)])]);
    box.style.left = (mark.x / s.w * 100) + '%';
    box.style.top = (mark.y / s.h * 100) + '%';
    box.style.width = (mark.w / s.w * 100) + '%';
    box.style.height = (mark.h / s.h * 100) + '%';
    frame.appendChild(box);
  });
  var legend = (s.marks || []).length
    ? h('ol', { class: 'shot-legend' }, s.marks.map(function (mark) { return h('li', null, [mark.label]); }))
    : null;
  return h('figure', { class: 'shot' }, [frame, block.caption ? h('figcaption', null, [block.caption]) : null, legend]);
}

var CALLOUT = { tip: ['check', 'Tip'], note: ['info', 'Good to know'], warn: ['alert', 'Be careful'] };

function block(b, ctx) {
  var vars = ctx.vars;
  switch (b.t) {
    case 'p':
      return h('p', null, inline(b.text, vars));
    case 'h':
      return h('h3', { id: b.anchor || null }, [fill(b.text, vars)]);
    case 'list':
      return h('ul', null, b.items.map(function (item) { return h('li', null, inline(item, vars)); }));
    case 'steps':
      return h('ol', { class: 'steps' }, b.items.map(function (item) { return h('li', null, inline(item, vars)); }));
    case 'code':
      return codeBlock(b, vars);
    case 'term':
      return ctx.terminals[b.id] ? terminal(ctx.terminals[b.id], vars) : h('p', { class: 'hint muted' }, ['(terminal ' + b.id + ' is missing)']);
    case 'shot':
      return shot(b, ctx.shots);
    case 'tip':
    case 'note':
    case 'warn':
      return h('div', { class: 'callout ' + b.t, role: 'note' }, [
        svgIcon(CALLOUT[b.t][0]),
        h('div', null, [h('strong', null, [CALLOUT[b.t][1] + '. ']), ...inline(b.text, vars)])
      ]);
    case 'table':
      return h('div', { class: 'table-scroll' }, [h('table', null, [
        h('thead', null, [h('tr', null, b.head.map(function (c) { return h('th', null, [fill(c, vars)]); }))]),
        h('tbody', null, b.rows.map(function (r) { return h('tr', null, r.map(function (c) { return h('td', null, inline(c, vars)); })); }))
      ])]);
    case 'diagram':
      return h('figure', { class: 'diagram' }, [diagram(b.id, vars), b.caption ? h('figcaption', null, [fill(b.caption, vars)]) : null]);
    case 'see':
      // only the topics this reader can open, and nothing at all when that is none of them
      var seen = b.ids.filter(function (id) { return ctx.byId[id]; });
      if (!seen.length) return null;
      return h('p', { class: 'see' }, ['See also: '].concat(seen.map(function (id, n) {
        return [n ? ', ' : '', h('a', { href: '#docs/' + id }, [fill(ctx.byId[id].title, vars)])];
      }).reduce(function (a, b2) { return a.concat(b2); }, [])));
    default:
      return null;
  }
}

// text of every block, for the search index
function textParts(topic, ctx) {
  var vars = ctx.vars;
  var parts = [
    { kind: 'title', text: fill(topic.title, vars) },
    { kind: 'summary', text: plain(topic.summary || '', vars) },
    { kind: 'keywords', text: (topic.keywords || []).join(' | ') }
  ];
  (topic.blocks || []).forEach(function (b) {
    if (b.t === 'h') parts.push({ kind: 'heading', text: fill(b.text, vars) });
    else if (b.t === 'p' || b.t === 'tip' || b.t === 'note' || b.t === 'warn') parts.push({ kind: 'body', text: plain(b.text, vars) });
    else if (b.t === 'list' || b.t === 'steps') b.items.forEach(function (i) { parts.push({ kind: 'body', text: plain(i, vars) }); });
    else if (b.t === 'code') parts.push({ kind: 'code', text: fill((b.file || '') + ' ' + b.text, vars) });
    else if (b.t === 'term' && ctx.terminals[b.id]) {
      ctx.terminals[b.id].steps.forEach(function (s) {
        parts.push({ kind: 'code', text: fill(s.cmd, vars) });
        parts.push({ kind: 'body', text: fill(s.out || '', vars) });
      });
    } else if (b.t === 'table') b.rows.forEach(function (r) { parts.push({ kind: 'body', text: r.map(function (c) { return plain(c, vars); }).join(' ') }); });
    else if (b.t === 'shot' && b.caption) parts.push({ kind: 'body', text: b.caption });
  });
  return parts;
}

export { block, inline, plain, textParts };
