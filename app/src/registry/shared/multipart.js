// multipart/form-data, the way twine uploads a release and dotnet pushes a package. read from a buffer already capped by the body reader.
// Author: Tim Rice
// strict on purpose: one boundary, headers we understand, a closing marker, and file names that are only a name

const { httpError } = require('../../lib/errors');

const LIMITS = { parts: 200, fieldBytes: 1024 * 1024, headerBytes: 8192 };

function boundaryOf(contentType) {
  const type = String(contentType || '');
  if (!/^multipart\/form-data\s*;/i.test(type)) return null;
  // the value has to end where the parameter does, or a 71 character boundary would be read as its first 70
  const m = /;\s*boundary=(?:"([^"]{1,70})"|([^\s;"]{1,70}))(?=\s*(?:;|$))/i.exec(type);
  const b = m ? (m[1] || m[2]) : null;
  // RFC 2046 characters only
  return b && /^[0-9A-Za-z'()+_,\-./:=? ]+$/.test(b) && !b.endsWith(' ') ? b : null;
}

// Content-Disposition: form-data; name="content"; filename="x.whl"
function disposition(value) {
  const text = String(value || '');
  if (!/^form-data\b/i.test(text)) return null;
  const params = {};
  const re = /;\s*([A-Za-z*]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/g;
  let m;
  while ((m = re.exec(text))) {
    const key = m[1].toLowerCase();
    if (key in params) return null;
    // only \" is unescaped. a raw backslash stays, so a Windows style path is refused rather than quietly made a name
    params[key] = m[2] !== undefined ? m[2].replace(/\\"/g, '"') : m[3];
  }
  return params.name === undefined ? null : params;
}

function parse(buffer, contentType, limits = {}) {
  const lim = { ...LIMITS, ...limits };
  const boundary = boundaryOf(contentType);
  if (!boundary) throw httpError(400, 'that upload is not multipart/form-data with a boundary');
  const delimiter = Buffer.from(`--${boundary}`);
  const fields = Object.create(null);
  const files = [];

  let at = buffer.indexOf(delimiter);
  if (at !== 0 && !(at > 0 && buffer.slice(0, at).toString('latin1').trim() === '')) {
    throw httpError(400, 'that upload does not start with its boundary');
  }
  let parts = 0;
  for (;;) {
    at += delimiter.length;
    // --boundary-- closes it
    if (buffer[at] === 0x2d && buffer[at + 1] === 0x2d) return { fields, files };
    if (buffer[at] !== 0x0d || buffer[at + 1] !== 0x0a) throw httpError(400, 'that upload has a broken boundary line');
    at += 2;
    parts += 1;
    if (parts > lim.parts) throw httpError(400, `that upload has more than ${lim.parts} parts`);

    const headEnd = buffer.indexOf('\r\n\r\n', at);
    if (headEnd < 0 || headEnd - at > lim.headerBytes) throw httpError(400, 'that upload has a part with no end to its headers');
    const headers = Object.create(null);
    for (const line of buffer.slice(at, headEnd).toString('utf8').split('\r\n')) {
      const colon = line.indexOf(':');
      if (colon <= 0) throw httpError(400, 'that upload has a header line that is not a header');
      headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
    }
    const next = buffer.indexOf(Buffer.concat([Buffer.from('\r\n'), delimiter]), headEnd + 4);
    if (next < 0) throw httpError(400, 'that upload stops before its closing boundary');
    const body = buffer.slice(headEnd + 4, next);

    const disp = disposition(headers['content-disposition']);
    if (!disp) throw httpError(400, 'that upload has a part without a form-data name');
    if (disp.filename !== undefined) {
      const name = disp.filename;
      // eslint-disable-next-line no-control-regex -- a file name with control characters in it is refused
      if (!name || name.length > 255 || /[/\\"\u0000-\u001f\u007f]/.test(name) || name === '.' || name === '..') {
        throw httpError(400, 'an uploaded file name has to be a plain file name');
      }
      if (lim.fileBytes && body.length > lim.fileBytes) throw httpError(413, `${name} is over the size limit`);
      files.push({ field: disp.name, filename: name, contentType: headers['content-type'] || 'application/octet-stream', data: body });
    } else {
      if (body.length > lim.fieldBytes) throw httpError(400, `the ${disp.name} field is too long`);
      (fields[disp.name] = fields[disp.name] || []).push(body.toString('utf8'));
    }
    at = next + 2;
  }
}

module.exports = { LIMITS, boundaryOf, disposition, parse };
