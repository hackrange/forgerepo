// PyPI's simple repository API, read and written.
// Author: Tim Rice
//
// PEP 503 (links), 691 (JSON via Accept), 700 (sizes, versions), 658/714 (separate metadata files).
// Standards: they accrete. No network or db in here.

const pypiName = require('./name');
const pypiVersion = require('./version');

const CONTENT_TYPE = {
  json: 'application/vnd.pypi.simple.v1+json',
  html: 'application/vnd.pypi.simple.v1+html',
  text: 'text/html; charset=utf-8'
};

// Accept header or ?format= (PEP 691). null = 406.
// ties go json > versioned html > text/html, like PyPI. no Accept or */* gets text/html for old clients
const OFFERS = {
  'application/vnd.pypi.simple.v1+json': 'json',
  'application/vnd.pypi.simple.latest+json': 'json',
  'application/vnd.pypi.simple.v1+html': 'html',
  'application/vnd.pypi.simple.latest+html': 'html',
  'text/html': 'text'
};
const PREFERENCE = { json: 3, html: 2, text: 1 };

function negotiate(accept, format) {
  if (format !== undefined && format !== null && format !== '') {
    // + in a query string arrives as a space. put it back
    return OFFERS[String(format).trim().toLowerCase().replace(/ /g, '+')] || null;
  }
  if (!accept || !String(accept).trim()) return 'text';

  let best = null;
  for (const part of String(accept).split(',')) {
    const [rawType, ...params] = part.split(';');
    const type = rawType.trim().toLowerCase();
    let q = 1;
    for (const param of params) {
      const m = /^\s*q\s*=\s*([0-9.]+)\s*$/i.exec(param);
      if (m) q = Number(m[1]);
    }
    if (!(q > 0)) continue;

    let kinds = [];
    if (OFFERS[type]) kinds = [OFFERS[type]];
    else if (type === '*/*') kinds = ['text'];
    else if (type === 'text/*') kinds = ['text'];
    else if (type === 'application/*') kinds = ['json', 'html'];

    for (const kind of kinds) {
      if (!best || q > best.q || (q === best.q && PREFERENCE[kind] > PREFERENCE[best.kind])) best = { kind, q };
    }
  }
  return best ? best.kind : null;
}

// hashlib name + hex. anything else is a hash nobody can check, so drop it
function cleanHashes(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [alg, value] of Object.entries(raw)) {
    if (/^[a-z0-9_]{2,32}$/.test(alg) && typeof value === 'string' && /^[0-9a-fA-F]{8,512}$/.test(value)) {
      out[alg] = value.toLowerCase();
    }
  }
  return out;
}

//PEP 691: false, true, or a non-empty string saying why.
function yankedValue(raw) {
  if (raw === true) return true;
  if (typeof raw === 'string') return raw.length ? raw : true;
  return false;
}

// PEP 658 and 714: false, true, or the hashes of the metadata file.
function metadataValue(raw) {
  if (raw === true) return true;
  if (raw && typeof raw === 'object') {
    const hashes = cleanHashes(raw);
    return Object.keys(hashes).length ? hashes : true;
  }
  return false;
}

// http(s) only. fragment comes off, in HTML it's the hash, not part of the address
function absolute(href, base) {
  let url;
  try {
    url = new URL(href, base);
  } catch (err) {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  const fragment = url.hash.slice(1);
  url.hash = '';
  return { href: url.href, fragment };
}

function fromJson(doc, pageUrl) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.files)) {
    throw new Error('the registry answered with JSON that is not a PyPI project page');
  }
  const files = [];
  for (const f of doc.files) {
    if (!f || typeof f.filename !== 'string' || typeof f.url !== 'string') continue;
    const url = absolute(f.url, pageUrl);
    if (!url) continue;
    files.push({
      filename: f.filename,
      url: url.href,
      hashes: cleanHashes(f.hashes),
      requiresPython: typeof f['requires-python'] === 'string' && f['requires-python'] ? f['requires-python'] : null,
      yanked: yankedValue(f.yanked),
      coreMetadata: metadataValue(f['core-metadata'] !== undefined ? f['core-metadata'] : f['dist-info-metadata']),
      size: Number.isSafeInteger(f.size) && f.size >= 0 ? f.size : null,
      uploadTime: typeof f['upload-time'] === 'string' ? f['upload-time'] : null,
      provenance: typeof f.provenance === 'string' && absolute(f.provenance, pageUrl) ? absolute(f.provenance, pageUrl).href : null
    });
  }
  const versions = Array.isArray(doc.versions) ? doc.versions.filter((v) => typeof v === 'string') : null;
  return { name: typeof doc.name === 'string' ? doc.name : null, files, versions };
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decodeEntities(text) {
  return String(text).replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (whole, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isInteger(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[body.toLowerCase()] !== undefined ? ENTITIES[body.toLowerCase()] : whole;
  });
}

function parseAttrs(text) {
  const attrs = {};
  const re = /([^\s"'=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = re.exec(text))) {
    const name = m[1].toLowerCase();
    if (attrs[name] !== undefined) continue;
    const raw = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
    attrs[name] = decodeEntities(raw);
  }
  return attrs;
}

// data-core-metadata holds either "true" or "<hashname>=<hex>", nothing fancier
function metadataAttr(raw) {
  if (raw === undefined) return false;
  if (raw.trim().toLowerCase() === 'true') return true;
  const m = /^\s*([a-z0-9_]+)=([0-9a-fA-F]+)\s*$/.exec(raw);
  return m ? { [m[1]]: m[2].toLowerCase() } : false;
}

// the page comes from an upstream index, so it is read by walking forward. the regexes these replace rescanned to the
// end of the page from every tag that never closed, and a page of nothing but those took minutes

// the attributes of the first <base ...>, or null. same as /<base\b([^>]*)>/i
function baseTagAttrs(src) {
  const open = /<base/gi;
  let m;
  while ((m = open.exec(src))) {
    const after = src.charAt(m.index + 5);
    if (/[A-Za-z0-9_]/.test(after)) continue;
    const end = src.indexOf('>', m.index + 5);
    // no > after this one means none after any later one either
    return end < 0 ? null : src.slice(m.index + 5, end);
  }
  return null;
}

// [attributes, inner text] of each <a ...>...</a>. same as /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi
function anchorsIn(src) {
  const out = [];
  const open = /<a\b/gi;
  const close = /<\/a\s*>/gi;
  let m;
  while ((m = open.exec(src))) {
    const gt = src.indexOf('>', m.index + 2);
    if (gt < 0) break;
    close.lastIndex = gt + 1;
    const c = close.exec(src);
    // nothing closes after this opening, so nothing closes after a later one
    if (!c) break;
    out.push([src.slice(m.index + 2, gt), src.slice(gt + 1, c.index)]);
    open.lastIndex = c.index + c[0].length;
  }
  return out;
}

// text with its tags taken out. same as .replace(/<[^>]*>/g, ''), an unclosed < and everything after it stays
function withoutTags(text) {
  let out = '';
  let at = 0;
  for (;;) {
    const lt = text.indexOf('<', at);
    if (lt < 0) return out + text.slice(at);
    const gt = text.indexOf('>', lt + 1);
    if (gt < 0) return out + text.slice(at);
    out += text.slice(at, lt);
    at = gt + 1;
  }
}

function fromHtml(text, pageUrl) {
  const src = String(text);
  let base = pageUrl;
  const baseTag = baseTagAttrs(src);
  if (baseTag !== null) {
    const href = parseAttrs(baseTag).href;
    if (href) {
      try {
        base = new URL(href, pageUrl).href;
      } catch (err) {
        base = pageUrl;
      }
    }
  }

  const files = [];
  for (const [rawAttrs, inner] of anchorsIn(src)) {
    const attrs = parseAttrs(rawAttrs);
    if (attrs.href === undefined) continue;
    const url = absolute(attrs.href, base);
    if (!url) continue;

    const hashes = {};
    const hm = /^([a-z0-9_]+)=([0-9a-fA-F]+)$/.exec(url.fragment);
    if (hm) hashes[hm[1]] = hm[2].toLowerCase();

    let filename = decodeEntities(withoutTags(inner)).trim();
    if (!filename) {
      try {
        filename = decodeURIComponent(new URL(url.href).pathname.split('/').pop() || '');
      } catch (err) {
        filename = '';
      }
    }
    if (!filename) continue;

    files.push({
      filename,
      url: url.href,
      hashes,
      requiresPython: attrs['data-requires-python'] ? attrs['data-requires-python'] : null,
      yanked: attrs['data-yanked'] === undefined ? false : (attrs['data-yanked'] ? attrs['data-yanked'] : true),
      coreMetadata: metadataAttr(attrs['data-core-metadata'] !== undefined ? attrs['data-core-metadata'] : attrs['data-dist-info-metadata']),
      size: null,
      uploadTime: null,
      provenance: attrs['data-provenance'] && absolute(attrs['data-provenance'], base) ? absolute(attrs['data-provenance'], base).href : null
    });
  }
  return { name: null, files, versions: null };
}

// letters, digits, a bit of punctuation. anything more creative stays off disk
const FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+!~-]{0,254}$/;

function validFilename(filename) {
  return typeof filename === 'string' && FILENAME_RE.test(filename) && !filename.includes('..');
}

const ARCHIVES = ['.tar.gz', '.tar.bz2', '.tar.xz', '.tar.z', '.tar', '.tgz', '.tbz', '.zip'];

// which release a file is, or null. no readable version = no rule applies = out.
// wheels escape dashes so field 2 is the version; sdists don't, so split at each dash till it fits. Fun.
function releaseOf(filename, project) {
  if (!validFilename(filename)) return null;
  const want = pypiName.normalize(project);
  const lower = filename.toLowerCase();

  if (lower.endsWith('.whl') || lower.endsWith('.egg')) {
    const parts = filename.slice(0, -4).split('-');
    if (parts.length < 2) return null;
    if (lower.endsWith('.whl') && parts.length !== 5 && parts.length !== 6) return null;
    return pypiName.normalize(parts[0]) === want && pypiVersion.valid(parts[1]) ? parts[1] : null;
  }

  const ext = ARCHIVES.find((e) => lower.endsWith(e));
  if (!ext) return null;
  const stem = filename.slice(0, -ext.length);
  for (let at = stem.indexOf('-'); at > 0; at = stem.indexOf('-', at + 1)) {
    const left = stem.slice(0, at);
    const right = stem.slice(at + 1);
    if (pypiName.normalize(left) === want && pypiVersion.valid(right)) return right;
  }
  return null;
}

function esc(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function preferredHash(hashes) {
  if (!hashes) return null;
  if (hashes.sha256) return 'sha256';
  return Object.keys(hashes)[0] || null;
}

function sortVersions(list) {
  return [...new Set(list)].filter((v) => pypiVersion.valid(v)).sort((a, b) => pypiVersion.compare(a, b));
}

// urlFor always points back at this box.
// PEP 700's 1.1 promises sizes; HTML-only upstreams have none and we don't invent them, so 1.0
function renderProject(page, kind, urlFor) {
  if (kind === 'json') {
    const sized = page.files.every((f) => Number.isSafeInteger(f.size));
    const out = {
      meta: { 'api-version': sized ? '1.1' : '1.0' },
      name: page.name,
      files: page.files.map((f) => {
        const entry = { filename: f.filename, url: urlFor(f), hashes: f.hashes || {} };
        if (f.requiresPython) entry['requires-python'] = f.requiresPython;
        if (f.yanked) entry.yanked = f.yanked;
        // PEP 714: new name only. pip 23.0 chokes on the hash dict under the old key, PyPI dropped it too
        if (f.coreMetadata) entry['core-metadata'] = f.coreMetadata;
        if (Number.isSafeInteger(f.size)) entry.size = f.size;
        if (f.uploadTime) entry['upload-time'] = f.uploadTime;
        return entry;
      })
    };
    if (sized) out.versions = sortVersions(page.versions || page.files.map((f) => f.version));
    return JSON.stringify(out);
  }

  const lines = [
    '<!DOCTYPE html>',
    '<html>',
    '  <head>',
    '    <meta name="pypi:repository-version" content="1.0">',
    `    <title>Links for ${esc(page.name)}</title>`,
    '  </head>',
    '  <body>',
    `    <h1>Links for ${esc(page.name)}</h1>`
  ];
  for (const f of page.files) {
    const alg = preferredHash(f.hashes);
    const attrs = [`href="${esc(urlFor(f) + (alg ? `#${alg}=${f.hashes[alg]}` : ''))}"`];
    if (f.requiresPython) attrs.push(`data-requires-python="${esc(f.requiresPython)}"`);
    if (f.yanked) attrs.push(`data-yanked="${f.yanked === true ? '' : esc(f.yanked)}"`);
    if (f.coreMetadata) {
      const metaAlg = f.coreMetadata === true ? null : preferredHash(f.coreMetadata);
      const value = metaAlg ? `${metaAlg}=${f.coreMetadata[metaAlg]}` : 'true';
      //old data-dist-info-metadata name left out on purpose, see the pip 23.0 saga above
      attrs.push(`data-core-metadata="${esc(value)}"`);
    }
    lines.push(`    <a ${attrs.join(' ')}>${esc(f.filename)}</a><br />`);
  }
  lines.push('  </body>', '</html>', '');
  return lines.join('\n');
}

// the list of projects. Links are relative, like PEP 503 says
function renderIndex(names, kind) {
  if (kind === 'json') {
    return JSON.stringify({ meta: { 'api-version': '1.0' }, projects: names.map((name) => ({ name })) });
  }
  const lines = [
    '<!DOCTYPE html>',
    '<html>',
    '  <head>',
    '    <meta name="pypi:repository-version" content="1.0">',
    '    <title>Simple index</title>',
    '  </head>',
    '  <body>'
  ];
  for (const name of names) lines.push(`    <a href="${esc(name)}/">${esc(name)}</a><br />`);
  lines.push('  </body>', '</html>', '');
  return lines.join('\n');
}

module.exports = {
  CONTENT_TYPE,
  negotiate,
  fromJson,
  fromHtml,
  releaseOf,
  validFilename,
  renderProject,
  renderIndex,
  baseTagAttrs,
  anchorsIn,
  withoutTags
};
