// The project page of a PyPI project published here: the files uploaded for it, kept like a fetched page but marked as ours.
// Author: Tim Rice

const zlib = require('zlib');
const { promisify } = require('util');
const pypiDocs = require('../../db/repositories/pypi-documents');
const published = require('../shared/published');
const log = require('../../logger');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

// null when nothing was ever uploaded, or the stored page was fetched from outside before the name was reserved
async function read(project) {
  const row = await pypiDocs.get(project, 'simple', '');
  if (!row || row.source !== published.SOURCE) return null;
  try {
    return JSON.parse((await gunzip(row.body)).toString('utf8'));
  } catch (err) {
    log.warn(`the published page for ${project} could not be read`, err.message);
    return null;
  }
}

async function write(project, doc) {
  const body = await gzip(Buffer.from(JSON.stringify(doc), 'utf8'));
  await pypiDocs.put(project, 'simple', '', body, published.SOURCE, null);
}

module.exports = { read, write };
