// The .gemspec.rz a pushed gem needs: `gem install` asks for one before it downloads the .gem, and a gem pushed here
// has none, so it is written from the metadata inside the .gem.
// Author: Tim Rice
//
// it is Ruby's Marshal 4.8 of what Gem::Specification#_dump writes: an array of nineteen fields, with Gem::Version and
// Gem::Requirement dumped the way they ask to be, and the whole thing deflated. only the types that array needs are
// written here, nothing reads a Marshal stream back

const zlib = require('zlib');

const RUBYGEMS_VERSION = '3.5.22';
const SPEC_VERSION = 4;

function writer() {
  const parts = [];
  const symbols = new Map();
  const put = (b) => parts.push(Buffer.isBuffer(b) ? b : Buffer.from(b));

  // 0, then 1..122 as n+5, then a length and the bytes of it, little end first
  function int(n) {
    if (n === 0) return put(Buffer.from([0]));
    if (n > 0 && n < 123) return put(Buffer.from([n + 5]));
    if (n < 0 && n > -124) return put(Buffer.from([(n - 5) & 0xff]));
    const bytes = [];
    let v = n;
    while (v !== 0 && v !== -1 && bytes.length < 4) {
      bytes.push(v & 0xff);
      v >>= 8;
    }
    return put(Buffer.from([n < 0 ? (256 - bytes.length) & 0xff : bytes.length, ...bytes]));
  }

  function symbol(name) {
    if (symbols.has(name)) {
      put(';');
      return int(symbols.get(name));
    }
    symbols.set(name, symbols.size);
    put(':');
    int(Buffer.byteLength(name));
    return put(name);
  }

  // a string carries its encoding, the way Ruby writes one
  function string(s) {
    const b = Buffer.from(String(s), 'utf8');
    put('I"');
    int(b.length);
    put(b);
    int(1);
    symbol('E');
    put('T');
  }

  function value(v) {
    if (v === null || v === undefined) return put('0');
    if (v === true) return put('T');
    if (v === false) return put('F');
    if (typeof v === 'number') {
      put('i');
      return int(v);
    }
    if (typeof v === 'string') return string(v);
    if (Array.isArray(v)) {
      put('[');
      int(v.length);
      return v.forEach(value);
    }
    if (v && v.marshal === 'user') {
      // Gem::Version and Gem::Requirement: the class, then what marshal_dump gives
      put('U');
      symbol(v.klass);
      return value(v.data);
    }
    if (v && v.marshal === 'object') {
      put('o');
      symbol(v.klass);
      int(Object.keys(v.ivars).length);
      for (const [k, x] of Object.entries(v.ivars)) {
        symbol(k);
        value(x);
      }
      return undefined;
    }
    if (v && v.marshal === 'symbol') return symbol(v.name);
    if (v && typeof v === 'object') {
      const keys = Object.keys(v);
      put('{');
      int(keys.length);
      for (const k of keys) {
        string(k);
        value(v[k]);
      }
      return undefined;
    }
    return put('0');
  }

  return { value, done: () => Buffer.concat([Buffer.from([4, 8]), ...parts]) };
}

const dump = (v) => {
  const w = writer();
  w.value(v);
  return w.done();
};

const version = (v) => ({ marshal: 'user', klass: 'Gem::Version', data: [String(v)] });
const requirement = (pairs) => ({ marshal: 'user', klass: 'Gem::Requirement', data: [pairs.map(([op, v]) => [op, version(v)])] });

// ">= 3.0", or "~> 3.1, < 4" as the pairs a Gem::Requirement holds
function parseRequirement(text) {
  const out = [];
  for (const part of String(text || '').split(',')) {
    const m = /^\s*(>=|<=|~>|!=|>|<|=)?\s*([0-9][0-9A-Za-z.\-+]*)\s*$/.exec(part);
    if (m) out.push([m[1] || '=', m[2]]);
  }
  return out.length ? out : [['>=', '0']];
}

function dependency(d) {
  return {
    marshal: 'object',
    klass: 'Gem::Dependency',
    ivars: {
      '@name': d.name,
      '@requirement': requirement(parseRequirement(d.requirement)),
      '@type': { marshal: 'symbol', name: d.runtime ? 'runtime' : 'development' },
      '@prerelease': false,
      '@version_requirements': requirement(parseRequirement(d.requirement))
    }
  };
}

// Gem::Specification writes itself with _dump, so the stream is the class and then the bytes of its own dump
function wrapped(klass, inner) {
  const w = writer();
  w.value({ marshal: 'raw' });
  const head = Buffer.from([4, 8]);
  const sym = Buffer.concat([Buffer.from(':'), Buffer.from([klass.length + 5]), Buffer.from(klass)]);
  const len = inner.length;
  const size = len < 123 ? Buffer.from([len + 5]) : Buffer.from([2, len & 0xff, (len >> 8) & 0xff]);
  return Buffer.concat([head, Buffer.from('u'), sym, size, inner]);
}

/** the Marshal of a Gem::Specification, as `gem install` reads it */
function gemspec(spec) {
  const platform = spec.platform || 'ruby';
  return wrapped('Gem::Specification', dump([
    RUBYGEMS_VERSION,
    SPEC_VERSION,
    spec.name,
    version(spec.version),
    null, // the date, which the reader fills in
    spec.summary || '',
    requirement(spec.ruby ? parseRequirement(spec.ruby) : [['>=', '0']]),
    requirement([['>=', '0']]),
    platform,
    (spec.dependencies || []).map(dependency),
    '', // where rubyforge used to be
    null,
    spec.authors && spec.authors.length ? spec.authors : ['unknown'],
    spec.summary || '',
    null,
    true,
    platform,
    (spec.licenses || [])[0] || null,
    {}
  ]));
}

const rz = (spec) => zlib.deflateSync(gemspec(spec));

module.exports = { gemspec, rz, dump, parseRequirement, _internal: { version, requirement, dependency } };
