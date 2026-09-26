// Portal API, CSV cells and streaming rows out.
// Author: Tim Rice

const { eachRow } = require('../../db/repositories/rows');

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  // leading quote stops a spreadsheet running it as a formula (CSV injection)
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

// wait for drain or a big export ends up buffered in memory anyway
async function writeChunk(res, text) {
  if (!res.write(text)) await new Promise((resolve) => res.once('drain', resolve));
}

module.exports = { csvEscape, writeChunk, eachRow };
