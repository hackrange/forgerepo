// What is inside a .gem: a tar holding metadata.gz, data.tar.gz and checksums.yaml.gz. only the metadata is read,
// and only the handful of fields the compact index needs.
// Author: Tim Rice
//
// the metadata is Psych's YAML of a Gem::Specification, which is regular enough to read field by field. nothing here
// evaluates it, and anything it does not know is left out rather than guessed at

const zlib = require('zlib');

const MAX_METADATA = 4 * 1024 * 1024;
const MAX_DEPS = 200;

// the entries of a plain tar, names and bytes
function entries(buf) {
  const out = new Map();
  let at = 0;
  while (at + 512 <= buf.length) {
    const h = buf.subarray(at, at + 512);
    if (h.every((b) => b === 0)) break;
    const size = parseInt(h.toString('utf8', 124, 136).replace(/\0.*$/s, '').trim() || '0', 8);
    if (!Number.isFinite(size) || size < 0 || at + 512 + size > buf.length) throw new Error('the .gem is damaged');
    const name = h.toString('utf8', 0, 100).replace(/\0.*$/s, '');
    const type = String.fromCharCode(h[156] || 48);
    if (type === '0' || type === '\0') out.set(name, buf.subarray(at + 512, at + 512 + size));
    at += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

const scalar = (text, key) => {
  const m = new RegExp(`^${key}: +(.+)$`, 'm').exec(text);
  return m ? m[1].trim().replace(/^["']|["']$/g, '') : '';
};

// version: !ruby/object:Gem::Version, then its own version line under it
function versionOf(text) {
  const m = /^version: !ruby\/object:Gem::Version\n\s+version: +(.+)$/m.exec(text);
  return m ? m[1].trim().replace(/^["']|["']$/g, '') : scalar(text, 'version');
}

// each dependency is its own object with a name, a type and the requirements it asks for
function dependencies(text) {
  const out = [];
  const parts = text.split('- !ruby/object:Gem::Dependency').slice(1);
  for (const part of parts.slice(0, MAX_DEPS)) {
    const name = scalar(part, '  name');
    if (!name) continue;
    const runtime = !/type: :development/.test(part);
    const block = (/requirement: [\s\S]*?requirements:\n([\s\S]*?)(?:\n {2}[a-z_]+:|$)/.exec(part) || [])[1] || '';
    const wants = [];
    for (const r of block.matchAll(/- - +"?([^"\n]+)"?\n\s+- !ruby\/object:Gem::Version\n\s+version: +(.+)/g)) {
      wants.push(`${r[1].trim()} ${r[2].trim().replace(/^["']|["']$/g, '')}`.replace(/\s+/g, ' '));
    }
    out.push({ name, runtime, requirement: wants.join(', ') });
  }
  return out;
}

/** reads a .gem. throws when it is not one */
function read(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 512) throw new Error('that is not a .gem');
  const parts = entries(buf);
  const meta = parts.get('metadata.gz');
  if (!meta) throw new Error('the .gem has no metadata.gz in it');
  const text = zlib.gunzipSync(meta, { maxOutputLength: MAX_METADATA }).toString('utf8');
  if (!/^--- !ruby\/object:Gem::Specification/m.test(text)) throw new Error('the metadata in the .gem is not a gem specification');
  const name = scalar(text, 'name');
  const version = versionOf(text);
  const platform = scalar(text, 'platform') || 'ruby';
  const licenses = ((/^licenses:\n((?:- .+\n)+)/m.exec(text) || [])[1] || '')
    .split('\n').map((l) => l.replace(/^- /, '').trim().replace(/^["']|["']$/g, '')).filter(Boolean);
  const rubyLine = (/^required_ruby_version: [\s\S]*?requirements:\n\s+- - +"?([^"\n]+)"?\n\s+- !ruby\/object:Gem::Version\n\s+version: +(.+)/m.exec(text) || []);
  return {
    name,
    version,
    platform: platform === 'ruby' ? '' : platform,
    licenses: licenses.slice(0, 10),
    summary: scalar(text, 'summary').slice(0, 1000),
    ruby: rubyLine.length ? `${rubyLine[1].trim()} ${rubyLine[2].trim().replace(/^["']|["']$/g, '')}` : '',
    dependencies: dependencies(text),
    hasData: parts.has('data.tar.gz')
  };
}

// the line the compact index wants: "1.2.3[-platform] dep:req,dep:req|checksum:...,ruby:>= 3.0"
function infoLine(spec, sha256) {
  const deps = spec.dependencies.filter((d) => d.runtime).map((d) => `${d.name}:${d.requirement}`).join(',');
  const tail = [`checksum:${sha256}`, spec.ruby ? `ruby:${spec.ruby}` : ''].filter(Boolean).join(',');
  return `${spec.version}${spec.platform ? `-${spec.platform}` : ''} ${deps}|${tail}`;
}

module.exports = { read, infoLine, entries };
