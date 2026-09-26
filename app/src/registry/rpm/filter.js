// The filtered index of a mirror: primary.xml with only the packages the rules and the kill switch let through, and a
// repomd.xml that points at it. only for mirrors set to filter, see mirror-options.js
// Author: Tim Rice
//
// the filtered primary is named after its own checksum and kept on disk, so the same answer is built once and a
// change of rules gives a new file. repomd.xml keeps every other file as the distro made it (filelists, other,
// updateinfo, comps), but drops the sqlite and zchunk copies of the index, which can not be filtered and would let dnf
// read the whole list after all. what a hold, an advisory or cooling off would refuse is still refused on download

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const config = require('../../config');
const policy = require('../../policy');
const killswitch = require('../../policy/killswitch');
const ecosystems = require('../../ecosystems');
const upstream = require('./upstream');

const dir = () => path.join(config.cacheDir, 'rpm', 'filtered');
const adapter = () => ecosystems.adapter('rpm');

// which packages of the index this caller may see, as a set of hrefs
async function allowedHrefs(idx, scope) {
  const out = new Set();
  for (const [name, list] of idx.byName) {
    if (!(await policy.checkPackage(name, adapter(), scope)).allowed) continue;
    const killed = await killswitch.killedVersions('rpm', name, list.map((p) => p.version));
    for (const p of list) {
      if (killed.has(p.version)) continue;
      if ((await policy.checkVersion(name, p.version, adapter(), scope)).allowed) out.add(p.href);
    }
  }
  return out;
}

// the filtered primary.xml.gz for this set, built once. { file, checksum, openChecksum, size, openSize }
const building = new Map();
async function filteredPrimary(up, idx, allowed) {
  const stamp = crypto.createHash('sha256').update(`${idx.primary.checksum}\n${[...allowed].sort().join('\n')}`).digest('hex');
  const meta = path.join(dir(), `${stamp}.json`);
  const known = await fsp.readFile(meta, 'utf8').then(JSON.parse, () => null);
  if (known && await fsp.stat(path.join(dir(), `${known.checksum}.xml.gz`)).then(() => true, () => false)) return known;
  if (building.has(stamp)) return building.get(stamp);
  const job = (async () => {
    await fsp.mkdir(dir(), { recursive: true });
    const source = await upstream.metaFile(up, idx.primary);
    const tmp = path.join(dir(), `${stamp}.${process.pid}.tmp`);
    const gz = zlib.createGzip({ level: 6 });
    const out = fs.createWriteStream(tmp, { mode: 0o640 });
    const packed = crypto.createHash('sha256');
    const plain = crypto.createHash('sha256');
    let size = 0;
    let openSize = 0;
    gz.on('data', (c) => {
      packed.update(c);
      size += c.length;
    });
    gz.pipe(out);
    const write = (text) => {
      const b = Buffer.from(text, 'utf8');
      plain.update(b);
      openSize += b.length;
      return gz.write(b) ? null : new Promise((resolve) => gz.once('drain', resolve));
    };
    await upstream.eachPackage(source, idx.primary.href,
      (header) => write(header.replace(/(<metadata\b[^>]*\spackages=")\d+(")/, `$1${allowed.size}$2`)),
      (block) => {
        const p = upstream.readBlock(block);
        return p && allowed.has(p.href) ? write(`${block}\n`) : null;
      });
    await write('</metadata>\n');
    await new Promise((resolve, reject) => {
      out.on('finish', resolve);
      out.on('error', reject);
      gz.end();
    });
    const checksum = packed.digest('hex');
    await fsp.rename(tmp, path.join(dir(), `${checksum}.xml.gz`));
    const got = { checksum, openChecksum: plain.digest('hex'), size, openSize };
    await fsp.writeFile(meta, JSON.stringify(got), { mode: 0o640 });
    return got;
  })().finally(() => building.delete(stamp));
  building.set(stamp, job);
  return job;
}

// repomd.xml pointing at the filtered primary, without the copies of the index that can not be filtered
function rewrite(xml, entries, got) {
  let out = xml;
  for (const e of entries) {
    if (/_db$|_zck$/.test(e.type)) out = out.replace(e.block, '');
  }
  const primary = entries.find((e) => e.type === 'primary');
  const block = primary.block
    .replace(/<checksum\s+type="[a-z0-9]+"\s*>[0-9a-f]+<\/checksum>/, `<checksum type="sha256">${got.checksum}</checksum>`)
    .replace(/<open-checksum\s+type="[a-z0-9]+"\s*>[0-9a-f]+<\/open-checksum>/, `<open-checksum type="sha256">${got.openChecksum}</open-checksum>`)
    .replace(/<location\s[^>]*href="[^"]+"\s*\/>/, `<location href="repodata/${got.checksum}-primary.xml.gz"/>`)
    .replace(/<size>\d+<\/size>/, `<size>${got.size}</size>`)
    .replace(/<open-size>\d+<\/open-size>/, `<open-size>${got.openSize}</open-size>`);
  return out.replace(primary.block, block).replace(/\n\s*\n/g, '\n');
}

// a filtered primary asked for by name, or null when this box never built one called that
async function fileFor(checksum) {
  if (!/^[0-9a-f]{64}$/.test(checksum)) return null;
  const file = path.join(dir(), `${checksum}.xml.gz`);
  return (await fsp.stat(file).then(() => true, () => false)) ? file : null;
}

module.exports = { allowedHrefs, filteredPrimary, rewrite, fileFor };
