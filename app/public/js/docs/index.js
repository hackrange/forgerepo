// ForgeRepo portal: the documentation, written for whoever is signed in.
// Author: Tim Rice
//
// two guides. everyone gets the developer guide, cut down to what their role can do and the package types this
// registry has switched on. admins also get the administrator guide. every example uses the address the reader
// reached this page at. search looks through every topic the reader can see, and the PDF is made from the same topics

import { state } from '../state.js';
import { h } from '../dom.js';
import { clear, notice, svgIcon } from '../ui.js';
import { api } from '../api.js';
import { build as buildVars, fill } from './vars.js';
import { buildIndex, search, snippet } from './search.js';
import { block, textParts } from './render.js';
import { GUIDES } from './content/index.js';

var FOOTER = 'CONFIDENTIAL - For Internal Use Only';
var loaded = null;

function load() {
  if (loaded) return loaded;
  loaded = Promise.all([
    api('GET', '/docs/context'),
    fetch('docs/shots.json', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; }),
    fetch('docs/terminals.json', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; })
  ]).then(function (got) {
    return { context: got[0], shots: got[1], terminals: got[2] };
  }).catch(function (err) {
    loaded = null;
    throw err;
  });
  return loaded;
}

function hasAll(perms) {
  return (perms || []).every(function (p) { return state.perms.indexOf(p) >= 0; });
}

// a topic shows when the reader has every permission it needs and the package type it is about is switched on
function visible(topic, context) {
  if (!hasAll(topic.needs)) return false;
  if (topic.ecosystem && !(context.ecosystems || []).some(function (e) { return e.id === topic.ecosystem; })) return false;
  if (topic.when && !topic.when(context)) return false;
  return true;
}

function guidesFor(context) {
  return GUIDES.map(function (g) {
    if (!hasAll(g.needs)) return null;
    var groups = g.groups.map(function (group) {
      var topics = group.topics.filter(function (t) { return visible(t, context); });
      return topics.length ? { id: group.id, label: group.label, topics: topics } : null;
    }).filter(Boolean);
    return groups.length ? { id: g.id, title: g.title, intro: g.intro, groups: groups } : null;
  }).filter(Boolean);
}

function parseHash() {
  var raw = (window.location.hash || '').replace(/^#docs\/?/, '');
  var q = '';
  var qAt = raw.indexOf('?');
  if (qAt >= 0) {
    var params = new URLSearchParams(raw.slice(qAt + 1));
    q = params.get('q') || '';
    raw = raw.slice(0, qAt);
  }
  return { id: decodeURIComponent(raw), q: q };
}

function viewDocs(body) {
  clear(body);
  body.appendChild(h('p', { class: 'hint' }, ['Loading the documentation...']));
  return load().then(function (data) {
    clear(body);
    var context = data.context;
    var portalPath = window.location.pathname.replace(/\/+$/, '') || '/_admin';
    var vars = buildVars({
      origin: window.location.origin, publicUrl: context.publicUrl, registryName: state.registryName,
      username: state.me.username, portalPath: portalPath
    });
    vars.role = state.me.role;
    var guides = guidesFor(context);
    var all = [];
    var byId = {};
    guides.forEach(function (g) {
      g.groups.forEach(function (group) {
        group.topics.forEach(function (t) {
          byId[t.id] = t;
          all.push({ topic: t, guide: g, group: group });
        });
      });
    });
    var ctx = { vars: vars, shots: data.shots || {}, terminals: data.terminals || {}, byId: byId, context: context };
    var index = buildIndex(all.map(function (a) {
      return { id: a.topic.id, title: fill(a.topic.title, vars), group: a.guide.title + ' / ' + a.group.label, parts: textParts(a.topic, ctx) };
    }));

    var asked = parseHash();
    var current = byId[asked.id] ? all.filter(function (a) { return a.topic.id === asked.id; })[0] : null;

    // ---- the search box, always at the top ----
    var input = h('input', {
      type: 'search', class: 'docs-search-input', placeholder: 'Search, like "npm token" or "pull an image"',
      'aria-label': 'Search the documentation', value: asked.q, autocomplete: 'off'
    });
    var results = h('div', { class: 'docs-results', role: 'listbox', 'aria-label': 'Search results' }, []);
    var selected = -1;
    var shown = [];

    function renderResults() {
      clear(results);
      shown = [];
      selected = -1;
      var q = input.value.trim();
      if (!q) {
        results.classList.remove('open');
        return;
      }
      shown = search(index, q, 12);
      results.classList.add('open');
      if (!shown.length) {
        results.appendChild(h('p', { class: 'hint' }, ['Nothing matches "' + q + '". Try fewer words, or a word like npm, pip, docker or token.']));
        return;
      }
      shown.forEach(function (r, n) {
        var a = h('a', { href: '#docs/' + r.entry.id + '?q=' + encodeURIComponent(q), class: 'docs-result', role: 'option', id: 'docs-result-' + n }, [
          h('strong', null, [r.entry.title]),
          h('span', { class: 'faint' }, [r.entry.group]),
          h('span', { class: 'docs-snippet' }, [snippet(r.entry, q)])
        ]);
        results.appendChild(a);
      });
    }

    function move(delta) {
      if (!shown.length) return;
      selected = (selected + delta + shown.length) % shown.length;
      Array.prototype.forEach.call(results.querySelectorAll('.docs-result'), function (el, n) {
        el.classList.toggle('active', n === selected);
        if (n === selected) {
          el.scrollIntoView({ block: 'nearest' });
          input.setAttribute('aria-activedescendant', el.id);
        }
      });
    }

    input.addEventListener('input', renderResults);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        move(1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        move(-1);
      } else if (e.key === 'Enter') {
        var pick = shown[selected >= 0 ? selected : 0];
        if (pick) window.location.hash = '#docs/' + pick.entry.id + '?q=' + encodeURIComponent(input.value.trim());
      } else if (e.key === 'Escape') {
        input.value = '';
        renderResults();
      }
    });

    var pdfButtons = h('div', { class: 'docs-pdf' }, guides.map(function (g) {
      var btn = h('button', { type: 'button', class: 'btn' }, [svgIcon('lines'), ' Download the ' + g.title + ' (PDF)']);
      btn.addEventListener('click', function () {
        var was = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Making the PDF...';
        // an admin needs both, so their PDF is the admin guide followed by every developer topic they can see
        var dev = g.id === 'admin' ? guides.filter(function (x) { return x.id === 'developer'; })[0] : null;
        var whole = dev ? {
          id: g.id, title: g.title, intro: g.intro,
          groups: g.groups.concat(dev.groups.map(function (group) { return { id: 'dev-' + group.id, label: 'Developers: ' + group.label, topics: group.topics }; }))
        } : g;
        import('./pdf.js').then(function (pdf) {
          return pdf.build(whole, {
            vars: vars, shots: ctx.shots, terminals: ctx.terminals, imageBase: 'docs/img/',
            logo: state.brandIcon ? '/_admin/brand/icon?v=' + encodeURIComponent(state.brandIcon) : null
          });
        }).then(function (blob) {
          var url = URL.createObjectURL(blob);
          var a = h('a', { href: url, download: (vars.name + ' ' + g.title).replace(/[^A-Za-z0-9 -]+/g, '').replace(/\s+/g, '-') + '.pdf' });
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
        }).catch(function (err) {
          alert('The PDF could not be made: ' + err.message);
        }).then(function () {
          btn.disabled = false;
          btn.textContent = was;
        });
      });
      return btn;
    }));

    var header = h('div', { class: 'docs-head' }, [
      h('div', null, [
        h('h2', null, [vars.name + ' documentation']),
        h('p', { class: 'hint' }, ['Written for ' + vars.host + ' and for what your account (' + state.me.role + ') can do. Press / to search.'])
      ]),
      pdfButtons
    ]);
    body.appendChild(header);
    body.appendChild(h('div', { class: 'docs-search' }, [svgIcon('search'), input, results]));

    // ---- contents on the left, the topic on the right ----
    var narrow = window.matchMedia('(max-width: 900px)').matches;
    var toc = h('nav', { class: 'docs-toc', 'aria-label': 'Documentation contents' }, []);
    // on a phone the contents would push the topic off the screen, so there it folds away once you pick something
    var tocBox = h('details', { class: 'docs-toc-box' }, [h('summary', null, ['Contents']), toc]);
    if (!narrow || !current) tocBox.open = true;
    guides.forEach(function (g) {
      toc.appendChild(h('div', { class: 'docs-guide' }, [g.title]));
      g.groups.forEach(function (group) {
        toc.appendChild(h('div', { class: 'docs-group' }, [group.label]));
        group.topics.forEach(function (t) {
          toc.appendChild(h('a', { href: '#docs/' + t.id, class: current && current.topic.id === t.id ? 'active' : null }, [fill(t.title, vars)]));
        });
      });
    });

    var main = h('article', { class: 'docs-main' }, []);
    if (current) {
      var t = current.topic;
      main.appendChild(h('div', { class: 'docs-crumb faint' }, [current.guide.title + ' / ' + current.group.label]));
      main.appendChild(h('h1', null, [fill(t.title, vars)]));
      if (t.summary) main.appendChild(h('p', { class: 'docs-summary' }, [fill(t.summary, vars)]));
      (t.blocks || []).forEach(function (b) {
        var node = block(b, ctx);
        if (node) main.appendChild(node);
      });
      // a link to a topic this role cannot see stays as words, not a link to nowhere
      main.querySelectorAll('a[href^="#docs/"]').forEach(function (a) {
        if (!byId[decodeURIComponent(a.getAttribute('href').slice(6).split('?')[0])]) a.replaceWith(document.createTextNode(a.textContent));
      });
      // what comes next in the same group, so reading straight through works
      var siblings = current.group.topics;
      var at = siblings.indexOf(t);
      main.appendChild(h('div', { class: 'docs-next' }, [
        at > 0 ? h('a', { href: '#docs/' + siblings[at - 1].id }, ['Previous: ' + fill(siblings[at - 1].title, vars)]) : h('span'),
        at < siblings.length - 1 ? h('a', { href: '#docs/' + siblings[at + 1].id }, ['Next: ' + fill(siblings[at + 1].title, vars)]) : h('span')
      ]));
      if (asked.q) highlight(main, asked.q);
    } else {
      guides.forEach(function (g) {
        main.appendChild(h('h1', null, [g.title]));
        if (g.intro) main.appendChild(h('p', { class: 'docs-summary' }, [fill(g.intro, vars)]));
        main.appendChild(h('div', { class: 'docs-cards' }, g.groups.map(function (group) {
          return h('section', { class: 'docs-card' }, [
            h('h3', null, [group.label]),
            h('ul', null, group.topics.map(function (topic) {
              return h('li', null, [h('a', { href: '#docs/' + topic.id }, [fill(topic.title, vars)])]);
            }))
          ]);
        })));
      });
      if (!guides.length) main.appendChild(notice('There is no documentation for your role yet.', 'info'));
    }

    body.appendChild(h('div', { class: 'docs-layout' }, [tocBox, main]));
    body.appendChild(h('footer', { class: 'docs-footer' }, [FOOTER]));

    if (current) {
      // a phone has the contents above the topic, so land on the topic itself rather than the top of the page
      // once more after the pictures and diagrams have taken their space, or the topic drifts back down
      if (narrow) {
        main.scrollIntoView({ block: 'start' });
        setTimeout(function () { if (document.body.contains(main)) main.scrollIntoView({ block: 'start' }); }, 250);
      }
      else window.scrollTo(0, 0);
      // keep the topic you are on in view in the list, without moving the page
      var here = toc.querySelector('a.active');
      if (here && toc.scrollHeight > toc.clientHeight) toc.scrollTop = Math.max(0, here.offsetTop - toc.clientHeight / 2 + here.offsetHeight);
    }
    if (asked.q && !current) renderResults();

    // / focuses search from anywhere on the page, unless someone is typing in a box already
    var slash = function (e) {
      if (!document.body.contains(input)) {
        document.removeEventListener('keydown', slash);
        return;
      }
      var tag = (e.target && e.target.tagName) || '';
      if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
        e.preventDefault();
        input.focus();
      }
    };
    document.addEventListener('keydown', slash);
  }).catch(function (err) {
    clear(body);
    body.appendChild(notice('The documentation could not be loaded: ' + err.message, 'err'));
  });
}

// marks the searched words on the page that search led to, and scrolls to the first
function highlight(root, q) {
  var terms = q.toLowerCase().split(/\s+/).filter(function (w) { return w.length > 2; });
  if (!terms.length) return;
  var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  var nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  var first = null;
  nodes.forEach(function (node) {
    if (node.parentNode && /^(MARK|SCRIPT|STYLE)$/.test(node.parentNode.nodeName)) return;
    var text = node.nodeValue;
    var lower = text.toLowerCase();
    var hits = [];
    terms.forEach(function (term) {
      var at = lower.indexOf(term);
      while (at >= 0) {
        hits.push([at, at + term.length]);
        at = lower.indexOf(term, at + term.length);
      }
    });
    if (!hits.length) return;
    hits.sort(function (a, b) { return a[0] - b[0]; });
    var frag = document.createDocumentFragment();
    var last = 0;
    hits.forEach(function (hit) {
      if (hit[0] < last) return;
      frag.appendChild(document.createTextNode(text.slice(last, hit[0])));
      var mark = h('mark', null, [text.slice(hit[0], hit[1])]);
      if (!first) first = mark;
      frag.appendChild(mark);
      last = hit[1];
    });
    frag.appendChild(document.createTextNode(text.slice(last)));
    node.parentNode.replaceChild(frag, node);
  });
  if (first) setTimeout(function () { first.scrollIntoView({ block: 'center' }); }, 50);
}

export { viewDocs, guidesFor, visible };
