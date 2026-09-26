// ForgeRepo portal: icons.
// Author: Tim Rice

import { state } from './state.js';
import { h, link } from './dom.js';

// has to be createElementNS, a createElement svg draws a whole lot of nothing.
// paths are constants, never server or user data

var SVGNS = 'http://www.w3.org/2000/svg';

var ICONS = {
  grid: 'M2 2h5v5H2V2zm7 0h5v3H9V2zM2 9h5v5H2V9zm7-2h5v7H9V7z',
  cube: 'M8 1.5 15 5v6l-7 3.5L1 11V5l7-3.5zm0 1.6L2.6 5.7 8 8.4l5.4-2.7L8 3.1z',
  box: 'M2 2.5h12v3H2v-3zm0 4.5h12v6.5a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5V7zm4 2v1.4h4V9H6z',
  funnel: 'M1.5 2.5h13v1.6l-5 4.4V14l-3-1.6V8.5l-5-4.4V2.5z',
  ticket: 'M3 1.5h10a1 1 0 0 1 1 1v11l-3-2-3 2-3-2-3 2v-11a1 1 0 0 1 1-1zm2 3v1.3h6V4.5H5zm0 3v1.3h6V7.5H5z',
  alert: 'M8 1.5 15 14H1L8 1.5zm0 4a.7.7 0 0 0-.7.8l.25 3.2a.45.45 0 0 0 .9 0l.25-3.2A.7.7 0 0 0 8 5.5zm0 5.4a.8.8 0 1 0 0 1.6.8.8 0 0 0 0-1.6z',
  search: 'M7 1.5a5.5 5.5 0 1 0 3.4 9.8l3.1 3.1 1-1-3.1-3.1A5.5 5.5 0 0 0 7 1.5zm0 1.4a4.1 4.1 0 1 1 0 8.2 4.1 4.1 0 0 1 0-8.2z',
  clock: 'M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm.7 3.5v4l3 1.8-.7 1.2L7.3 9.3V4.5h1.4z',
  bars: 'M1 9h2V7H1v2zm3.5 3h2V4h-2v8zM8 14h2V2H8v12zm3.5-3h2V5h-2v6z',
  lines: 'M2 2h12v2H2V2zm0 3.5h12v2H2v-2zM2 9h8v2H2V9zm0 3.5h8v2H2v-2z',
  shield: 'M8 1.5 14 4v4.2c0 3.1-2.5 5.6-6 6.3-3.5-.7-6-3.2-6-6.3V4l6-2.5z',
  key: 'M10.5 1.5a4 4 0 0 0-3.8 5.3L1.5 12v2.5H4v-1.5h1.5V12H7l1.2-1.2a4 4 0 1 0 2.3-9.3zm1.2 2.2a1.2 1.2 0 1 1 0 2.4 1.2 1.2 0 0 1 0-2.4z',
  user: 'M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 1.3c-2.7 0-5 1.4-5 3.1v1.1h10v-1.1c0-1.7-2.3-3.1-5-3.1z',
  globe: 'M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM6.7 3.1c-.6.9-1.1 2.3-1.2 4.2H3.1a5 5 0 0 1 3.6-4.2zm2.6 0a5 5 0 0 1 3.6 4.2h-2.4c-.1-1.9-.6-3.3-1.2-4.2zM8 3.3c.5.7 1.1 2 1.2 4H6.8c.1-2 .7-3.3 1.2-4zM3.1 8.7h2.4c.1 1.9.6 3.3 1.2 4.2a5 5 0 0 1-3.6-4.2zm3.7 0h2.4c-.1 2-.7 3.3-1.2 4-.5-.7-1.1-2-1.2-4zm3.7 0h2.4a5 5 0 0 1-3.6 4.2c.6-.9 1.1-2.3 1.2-4.2z',
  link: 'M6.3 9.7a3.5 3.5 0 0 1 0-4.9l2-2a3.5 3.5 0 0 1 5 4.9l-.9.9-1-1 .9-.9a2 2 0 1 0-2.9-2.8l-2 2a2 2 0 0 0 0 2.8zM9.7 6.3a3.5 3.5 0 0 1 0 4.9l-2 2a3.5 3.5 0 1 1-5-4.9l.9-.9 1 1-.9.9a2 2 0 1 0 2.9 2.8l2-2a2 2 0 0 0 0-2.8z',
  swap: 'M4.5 1.5 1.5 4.5l3 3V5.3H11V3.7H4.5V1.5zm7 7v2.2H5v1.6h6.5v2.2l3-3-3-3z',
  gear: 'M8 5.2a2.8 2.8 0 1 0 0 5.6 2.8 2.8 0 0 0 0-5.6zm6.2 3.6.02-.8-.02-.8 1.4-1.1-1.4-2.4-1.7.6a6 6 0 0 0-1.4-.8L10.8.8H8l-.3 1.8a6 6 0 0 0-1.4.8l-1.7-.6-1.4 2.4 1.4 1.1a6.6 6.6 0 0 0 0 1.6l-1.4 1.1 1.4 2.4 1.7-.6c.43.34.9.6 1.4.8l.3 1.8h2.8l.3-1.8c.5-.2.97-.46 1.4-.8l1.7.6 1.4-2.4-1.4-1.1z',
  chev: 'M4.8 6.1 8 9.3l3.2-3.2 1 1L8 11.3 3.8 7.1z',
  check: 'M6.3 11.6 2.7 8l1.1-1.1 2.5 2.5 5.9-5.9 1.1 1.1z',
  info: 'M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM7.25 7h1.5v4.5h-1.5V7zm0-2.5h1.5V6h-1.5V4.5z',
  anvil: 'M2.6 4.6h8.3c.35 1.35 1.35 2.05 2.5 2.1v1.35h-2.55c-.85 0-1.5.45-1.75 1.2l-.2.6 1.45.95v1.25H4.9V10.8l1.45-.95-.2-.6c-.25-.75-.9-1.2-1.75-1.2H2.6V4.6z',
  dot: 'M8 6a2 2 0 1 1 0 4 2 2 0 0 1 0-4z',
  // ecosystem marks, drawn here. not the projects' own logos
  npm: 'M8 1.2 14 4.6v6.8L8 14.8 2 11.4V4.6L8 1.2zm0 1.7L3.5 5.5v5L8 13.1l4.5-2.6v-5L8 2.9zM6 6h4v4H8.8V7.2H6V6z',
  pypi: 'M4 1.5h5A1.5 1.5 0 0 1 10.5 3v3H7A1.5 1.5 0 0 0 5.5 7.5v2H4A1.5 1.5 0 0 1 2.5 8V3A1.5 1.5 0 0 1 4 1.5zm1 1.3a.7.7 0 1 0 0 1.4.7.7 0 0 0 0-1.4zM7 6.5h5A1.5 1.5 0 0 1 13.5 8v5a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 13v-2H9a1.5 1.5 0 0 0 1.5-1.5v-3H7zm4 4.3a.7.7 0 1 0 0 1.4.7.7 0 0 0 0-1.4z'
};

function svgIcon(name, cls) {
  var svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('fill', 'currentColor');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  if (cls) svg.setAttribute('class', cls);
  var path = document.createElementNS(SVGNS, 'path');
  // evenodd, so a shape inside a shape is a hole no matter which way it was drawn
  path.setAttribute('fill-rule', 'evenodd');
  path.setAttribute('d', ICONS[name] || ICONS.dot);
  svg.appendChild(path);
  return svg;
}

// an admin's own icon if there is one, else the anvil
function brandMark() {
  if (state.brandIcon) return h('img', { src: '/_admin/brand/icon?v=' + encodeURIComponent(state.brandIcon), alt: '' });
  return anvilMark();
}

function setTitle() {
  document.title = state.registryName || 'ForgeRepo';
}

// the mark: an anvil. packages get hammered here
function anvilMark() {
  var svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  var tile = document.createElementNS(SVGNS, 'rect');
  tile.setAttribute('width', '16');
  tile.setAttribute('height', '16');
  tile.setAttribute('rx', '3');
  tile.setAttribute('fill', 'currentColor');
  tile.setAttribute('opacity', '0.18');
  var path = document.createElementNS(SVGNS, 'path');
  path.setAttribute('fill', 'currentColor');
  path.setAttribute('d', ICONS.anvil);
  svg.appendChild(tile);
  svg.appendChild(path);
  return svg;
}

function can(perm) {
  return state.perms.indexOf(perm) >= 0;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// All panels stay in the dom, tabs just hide them - a removed panel would save as empty on settings.
//caller owns `current` so a redraw keeps you on your tab. returns panels keyed by id for the caller
function tabs(body, current, items, onPick) {
  var chosen = items.some(function (i) { return i.id === current; }) ? current : items[0].id;
  var nav = h('div', { class: 'tabs' }, []);
  var panels = {};
  var buttons = {};

  items.forEach(function (item) {
    var panel = h('div', null, []);
    if (item.id !== chosen) panel.style.display = 'none';
    panels[item.id] = panel;
    buttons[item.id] = h('button', {
      type: 'button',
      class: item.id === chosen ? 'on' : null,
      onclick: function () {
        onPick(item.id);
        items.forEach(function (other) {
          panels[other.id].style.display = other.id === item.id ? '' : 'none';
          buttons[other.id].className = other.id === item.id ? 'on' : '';
        });
      }
    }, [item.label]);
    nav.appendChild(buttons[item.id]);
  });

  body.appendChild(nav);
  items.forEach(function (item) { body.appendChild(panels[item.id]); });
  return panels;
}

function when(value) {
  if (!value) return '';
  return String(value).replace('T', ' ').slice(0, 19);
}

function bytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}

function table(cols, rows) {
  if (!rows.length) return h('p', { class: 'empty' }, ['Nothing here yet.']);
  var head = h('tr', null, cols.map(function (c) {
    return h('th', { class: c.num ? 'num' : null }, [c.label !== undefined ? c.label : c]);
  }));
  var body = rows.map(function (cells) {
    return h('tr', null, cells.map(function (cell, i) {
      var col = cols[i] || {};
      return h('td', { class: col.num ? 'num' : null }, [cell]);
    }));
  });
  // wide tables scroll in their own box, not the whole page
  return h('div', { class: 'table-scroll' }, [
    h('table', null, [h('thead', null, [head]), h('tbody', null, body)])
  ]);
}

function pager(page, total, limit, go) {
  var pages = Math.max(1, Math.ceil(total / limit));
  if (pages <= 1) return h('div', { class: 'pager muted' }, [total + ' row' + (total === 1 ? '' : 's')]);
  var box = h('div', { class: 'pager' }, []);
  if (page > 1) box.appendChild(link('back', function () { go(page - 1); }));
  box.appendChild(h('span', { class: 'muted' }, ['page ' + page + ' of ' + pages + ', ' + total + ' rows']));
  if (page < pages) box.appendChild(h('span', null, [' ', link('next', function () { go(page + 1); })]));
  return box;
}

function notice(text, kind) {
  var icon = kind === 'err' ? 'alert' : kind === 'ok' ? 'check' : 'info';
  return h('div', { class: 'msg ' + (kind || ''), role: kind === 'err' ? 'alert' : 'status' }, [
    svgIcon(icon),
    h('div', null, [text])
  ]);
}

export {
  SVGNS, anvilMark, brandMark, bytes, can, clear, notice, pager, setTitle, svgIcon, table, tabs, when
};
