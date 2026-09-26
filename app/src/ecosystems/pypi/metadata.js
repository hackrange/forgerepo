// A Python release's core metadata, from METADATA (PEP 658) or PyPI's JSON info.
// Author: Tim Rice
//
// email-style headers (it's Python packaging, don't ask). Both end up the same shape.
// only headers are read, the description can be megabytes of README

const MULTIPLE = new Set([
  'classifier', 'requires-dist', 'provides-extra', 'project-url', 'license-file',
  'dynamic', 'platform', 'supported-platform', 'requires-external', 'provides-dist', 'obsoletes-dist'
]);

const MAX_HEADER_BYTES = 1024 * 1024;
const MAX_LICENSE_TEXT = 200;

// License is sometimes a name, sometimes all eleven pages. text gets trimmed + flagged
// so policy never mistakes it for an identifier
function licenseField(raw) {
  const value = String(raw || '').trim();
  if (!value || value.toUpperCase() === 'UNKNOWN') return null;
  const text = value.length > 100 || value.includes('\n');
  return { value: text ? `${value.slice(0, MAX_LICENSE_TEXT)}${value.length > MAX_LICENSE_TEXT ? '...' : ''}` : value, isText: text };
}

function projectUrl(entry) {
  const text = String(entry || '');
  const at = text.indexOf(',');
  if (at < 0) return { label: '', url: text.trim() };
  return { label: text.slice(0, at).trim(), url: text.slice(at + 1).trim() };
}

// only keep addresses a browser can open safely. javascript: urls need not apply
function safeUrl(url) {
  return /^https?:\/\/[^\s]+$/i.test(String(url || '')) ? String(url) : null;
}

function strings(list) {
  return Array.isArray(list) ? list.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim()) : [];
}

function shape(fields) {
  const classifiers = strings(fields.classifiers);
  const urls = [];
  for (const { label, url } of fields.projectUrls || []) {
    const safe = safeUrl(url);
    if (safe) urls.push({ label: label || 'URL', url: safe });
  }
  return {
    name: fields.name || null,
    version: fields.version || null,
    metadataVersion: fields.metadataVersion || null,
    summary: fields.summary ? String(fields.summary).slice(0, 512) : null,
    requiresPython: fields.requiresPython || null,
    requiresDist: strings(fields.requiresDist),
    providesExtra: strings(fields.providesExtra),
    licenseExpression: fields.licenseExpression ? String(fields.licenseExpression).trim() : null,
    license: licenseField(fields.license),
    licenseClassifiers: classifiers.filter((c) => c.startsWith('License ::')),
    projectUrls: urls,
    classifiers
  };
}

function parse(text) {
  let src = String(text || '').replace(/\r\n?/g, '\n');
  if (src.length > MAX_HEADER_BYTES) src = src.slice(0, MAX_HEADER_BYTES);
  const end = src.indexOf('\n\n');
  const head = end >= 0 ? src.slice(0, end) : src;

  const fields = {};
  let last = null;
  for (const line of head.split('\n')) {
    //line starting with whitespace is a continuation of the header above it
    if (/^[ \t]/.test(line) && last) {
      const more = line.replace(/^ {7}\|/, '').trim();
      if (Array.isArray(fields[last])) fields[last][fields[last].length - 1] += `\n${more}`;
      else fields[last] = `${fields[last]}\n${more}`;
      continue;
    }
    const m = /^([A-Za-z0-9-]+):[ \t]?(.*)$/.exec(line);
    if (!m) {
      last = null;
      continue;
    }
    const key = m[1].toLowerCase();
    last = key;
    if (MULTIPLE.has(key)) (fields[key] = fields[key] || []).push(m[2].trim());
    else if (fields[key] === undefined) fields[key] = m[2].trim();
  }

  const projectUrls = (fields['project-url'] || []).map(projectUrl);
  if (fields['home-page']) projectUrls.unshift({ label: 'Homepage', url: fields['home-page'] });
  if (fields['download-url']) projectUrls.push({ label: 'Download', url: fields['download-url'] });

  return shape({
    name: fields.name,
    version: fields.version,
    metadataVersion: fields['metadata-version'],
    summary: fields.summary,
    requiresPython: fields['requires-python'],
    requiresDist: fields['requires-dist'],
    providesExtra: fields['provides-extra'],
    licenseExpression: fields['license-expression'],
    license: fields.license,
    projectUrls,
    classifiers: fields.classifier
  });
}

// PyPI's JSON API info block. Same fields, different names, because of course.
function fromJsonInfo(info) {
  const i = info && typeof info === 'object' ? info : {};
  const projectUrls = [];
  if (i.home_page) projectUrls.push({ label: 'Homepage', url: i.home_page });
  for (const [label, url] of Object.entries(i.project_urls && typeof i.project_urls === 'object' ? i.project_urls : {})) {
    projectUrls.push({ label, url });
  }
  return shape({
    name: i.name,
    version: i.version,
    summary: i.summary,
    requiresPython: i.requires_python,
    requiresDist: i.requires_dist,
    providesExtra: i.provides_extra,
    licenseExpression: i.license_expression,
    license: i.license,
    projectUrls,
    classifiers: i.classifiers
  });
}

module.exports = { parse, fromJsonInfo };
