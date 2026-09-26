// ForgeRepo portal: documentation search.
// Author: Tim Rice
//
// everything is in the page already, so the index is built in the browser from the topics the reader may see.
// words match from their start (inst finds install), close misspellings still match on longer words, and a few
// words people use for the same thing are treated as one (a password and a token, a container and an image)

var SYNONYMS = [
  ['token', 'tokens', 'credential', 'credentials', 'password', 'apikey', 'secret'],
  ['login', 'signin', 'sign', 'logon', 'authenticate', 'auth'],
  ['image', 'images', 'container', 'containers', 'docker', 'podman', 'oci'],
  ['pypi', 'pip', 'python', 'wheel'],
  ['npm', 'npmrc', 'node', 'javascript'],
  ['block', 'blocked', 'deny', 'denied', 'refused', 'forbidden', '403'],
  ['allow', 'allowed', 'approve', 'approved', 'whitelist'],
  ['publish', 'push', 'upload', 'release'],
  ['pull', 'install', 'download', 'fetch'],
  ['vulnerability', 'vulnerabilities', 'cve', 'advisory', 'advisories'],
  ['pipeline', 'pipelines', 'ci', 'cd']
];
var STOP = ['the', 'a', 'an', 'and', 'or', 'to', 'of', 'in', 'on', 'for', 'is', 'it', 'you', 'your', 'with', 'this', 'that', 'be', 'are', 'as', 'at', 'by', 'from', 'can', 'how', 'do', 'i', 'my', 'what', 'when', 'if'];

var synonymOf = {};
SYNONYMS.forEach(function (group) {
  group.forEach(function (w) { synonymOf[w] = group; });
});

function words(text) {
  // npmAuthToken is npm auth token to someone searching
  return String(text || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().replace(/[^a-z0-9.\-_/@:]+/g, ' ').split(/[\s./:@_-]+/).filter(function (w) {
    return w && STOP.indexOf(w) < 0;
  });
}

// one letter off, added or dropped, for words long enough that it is still clearly the same word
function close(a, b) {
  if (Math.abs(a.length - b.length) > 1 || a.length < 5 || b.length < 5) return false;
  var i = 0;
  var j = 0;
  var edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i += 1;
      j += 1;
      continue;
    }
    edits += 1;
    if (edits > 1) return false;
    if (a.length > b.length) i += 1;
    else if (b.length > a.length) j += 1;
    else {
      i += 1;
      j += 1;
    }
  }
  return edits + (a.length - i) + (b.length - j) <= 1;
}

var WEIGHTS = { title: 10, keywords: 7, heading: 5, summary: 4, body: 1, code: 2 };

// entries: [{ id, title, group, summary, parts: [{ kind, text }] }]
function buildIndex(entries) {
  var terms = {};
  entries.forEach(function (e, n) {
    e.parts.forEach(function (part) {
      words(part.text).forEach(function (w) {
        if (!terms[w]) terms[w] = {};
        terms[w][n] = (terms[w][n] || 0) + (WEIGHTS[part.kind] || 1);
      });
    });
  });
  return { entries: entries, terms: terms, vocabulary: Object.keys(terms) };
}

function expand(index, q) {
  var hits = {};
  var direct = {};
  var add = function (term, factor) {
    var postings = index.terms[term];
    if (!postings) return;
    Object.keys(postings).forEach(function (n) {
      hits[n] = Math.max(hits[n] || 0, Math.min(postings[n], 24) * factor);
      if (factor >= 0.6) direct[n] = true;
    });
  };
  index.vocabulary.forEach(function (term) {
    if (term === q) add(term, 1);
    else if (term.indexOf(q) === 0 && q.length >= 2) add(term, 0.8);
    else if (close(term, q)) add(term, 0.6);
  });
  (synonymOf[q] || []).forEach(function (s) {
    if (s !== q) add(s, 0.4);
  });
  return { hits: hits, direct: Object.keys(direct).length };
}

// every word has to find something, and topics that match all of them rank by how strongly
function search(index, query, limit) {
  var qs = words(query);
  if (!qs.length) return [];
  var total = null;
  var size = index.entries.length;
  qs.forEach(function (q) {
    var expanded = expand(index, q);
    var hits = expanded.hits;
    // a word most topics mention says little about which one you want: "yarn token" is about yarn more than tokens.
    // rarity counts the topics that have the word itself, a synonym showing up everywhere should not water it down.
    // and a topic that says token forty times is not forty times more about tokens, expand caps each word
    var found = expanded.direct || Object.keys(hits).length;
    var rarity = found ? Math.log(1 + size / found) : 0;
    Object.keys(hits).forEach(function (n) { hits[n] = hits[n] * rarity; });
    if (total === null) {
      total = hits;
      return;
    }
    var next = {};
    Object.keys(total).forEach(function (n) {
      if (hits[n]) next[n] = total[n] + hits[n];
    });
    total = next;
  });
  var phrase = String(query).trim().toLowerCase();
  return Object.keys(total || {}).map(function (n) {
    var e = index.entries[n];
    var score = total[n];
    // the exact phrase in the title or anywhere is worth a lot more than the words scattered about
    if (phrase.length > 3 && e.title.toLowerCase().indexOf(phrase) >= 0) score += 40;
    else if (phrase.length > 3 && e.parts.some(function (p) { return p.kind === 'keywords' && p.text.toLowerCase().split(' | ').indexOf(phrase) >= 0; })) score += 30;
    else if (phrase.length > 3 && e.parts.some(function (p) { return p.text.toLowerCase().indexOf(phrase) >= 0; })) score += 12;
    return { entry: e, score: score };
  }).sort(function (a, b) { return b.score - a.score || a.entry.title.localeCompare(b.entry.title); }).slice(0, limit || 20);
}

// a short piece of text around the first word that matched, for the result list
function snippet(entry, query, size) {
  var qs = words(query);
  var width = size || 160;
  var text = entry.parts.filter(function (p) { return p.kind !== 'title'; }).map(function (p) { return p.text; }).join(' ').replace(/\s+/g, ' ');
  var lower = text.toLowerCase();
  var at = -1;
  qs.some(function (q) {
    at = lower.indexOf(q);
    return at >= 0;
  });
  if (at < 0) return text.slice(0, width) + (text.length > width ? '...' : '');
  var start = Math.max(0, at - Math.floor(width / 3));
  return (start ? '...' : '') + text.slice(start, start + width) + (start + width < text.length ? '...' : '');
}

export { buildIndex, search, snippet, words, close };
