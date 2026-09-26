// Sigstore bundle verification with nothing but node's crypto.
// Author: Tim Rice
// the trust comes from a pinned trusted root in src/trust, never from the registry handing us a bundle.
// a bundle only counts when all of it holds: the Fulcio chain, the signing time inside the certificate's
// ten minutes, the DSSE signature, Rekor's signed promise, the log entry naming this exact signature and
// payload, and the statement's subject being the bytes we actually have

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';
const OIDS = {
  issuer: '1.3.6.1.4.1.57264.1.8',
  runnerEnvironment: '1.3.6.1.4.1.57264.1.11',
  sourceRepository: '1.3.6.1.4.1.57264.1.12',
  sourceDigest: '1.3.6.1.4.1.57264.1.13',
  sourceRef: '1.3.6.1.4.1.57264.1.14',
  buildConfig: '1.3.6.1.4.1.57264.1.18',
  buildTrigger: '1.3.6.1.4.1.57264.1.20',
  runInvocation: '1.3.6.1.4.1.57264.1.21'
};
const IN_TOTO = 'application/vnd.in-toto+json';

const b64 = (s) => Buffer.from(String(s || ''), 'base64');

// ---------------------------------------------------------------- the pinned root

let trust = null;
function loadTrust(rootJson) {
  const root = rootJson || JSON.parse(fs.readFileSync(path.join(__dirname, 'trust', 'sigstore-trusted-root.json'), 'utf8'));
  const window = (v) => ({ start: v && v.start ? Date.parse(v.start) : 0, end: v && v.end ? Date.parse(v.end) : Infinity });
  return {
    cas: (root.certificateAuthorities || []).map((ca) => ({
      certs: ca.certChain.certificates.map((c) => new crypto.X509Certificate(b64(c.rawBytes))),
      valid: window(ca.validFor)
    })),
    logs: new Map((root.tlogs || []).map((t) => [t.logId.keyId, {
      key: crypto.createPublicKey({ key: b64(t.publicKey.rawBytes), format: 'der', type: 'spki' }),
      valid: window(t.publicKey.validFor)
    }]))
  };
}
function trusted() {
  if (!trust) trust = loadTrust();
  return trust;
}
function useTrustForTests(rootJson) {
  if (process.env.NODE_ENV === 'production') throw new Error('the Sigstore trust root cannot be swapped in production');
  trust = rootJson ? loadTrust(rootJson) : null;
}

// ---------------------------------------------------------------- just enough DER

function der(buf, start = 0, end = buf.length) {
  const items = [];
  let off = start;
  while (off < end) {
    if (off + 2 > end) throw new Error('truncated DER');
    const tag = buf[off];
    let len = buf[off + 1];
    let hdr = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n < 1 || n > 4 || off + 2 + n > end) throw new Error('bad DER length');
      len = 0;
      for (let i = 0; i < n; i += 1) len = (len * 256) + buf[off + 2 + i];
      hdr = 2 + n;
    }
    const item = { tag, start: off + hdr, end: off + hdr + len };
    if (item.end > end) throw new Error('DER runs past its container');
    if (tag & 0x20) item.children = der(buf, item.start, item.end);
    items.push(item);
    off = item.end;
  }
  return items;
}

function oidText(buf) {
  const parts = [Math.floor(buf[0] / 40), buf[0] % 40];
  let v = 0;
  for (let i = 1; i < buf.length; i += 1) {
    v = (v * 128) + (buf[i] & 0x7f);
    if (!(buf[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

// Fulcio's own extensions, the identity the certificate was issued to
function extensions(raw) {
  const out = {};
  const tbs = der(raw)[0].children[0];
  const wrap = tbs.children.find((c) => c.tag === 0xa3);
  if (!wrap) return out;
  for (const ext of wrap.children[0].children) {
    const id = oidText(raw.subarray(ext.children[0].start, ext.children[0].end));
    const octet = ext.children[ext.children.length - 1];
    out[id] = raw.subarray(octet.start, octet.end);
  }
  return out;
}

function extText(value) {
  if (!value || !value.length) return null;
  try {
    const inner = der(value)[0];
    if (inner && (inner.tag === 0x0c || inner.tag === 0x16 || inner.tag === 0x13)) return value.subarray(inner.start, inner.end).toString('utf8');
  } catch (err) {
    // the v1 extensions are raw strings, not DER
  }
  return value.toString('utf8');
}

function identity(cert, raw) {
  const ext = extensions(raw);
  const id = {};
  for (const [k, oid] of Object.entries(OIDS)) id[k] = extText(ext[oid]);
  if (!id.issuer && ext[ISSUER_V1]) id.issuer = ext[ISSUER_V1].toString('utf8');
  const san = String(cert.subjectAltName || '').split(', ').map((s) => s.replace(/^(URI|email):/, ''));
  id.subject = san[0] || null;
  return id;
}

// ---------------------------------------------------------------- the checks

function fail(reason) {
  const e = new Error(reason);
  e.invalid = true;
  throw e;
}

function pae(type, payload) {
  return Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]);
}

function chainOk(cert, at) {
  for (const ca of trusted().cas) {
    if (at < ca.valid.start || at > ca.valid.end) continue;
    const [inter, ...rest] = ca.certs;
    if (!inter || !cert.checkIssued(inter) || !cert.verify(inter.publicKey)) continue;
    let prev = inter;
    let ok = true;
    for (const next of rest) {
      if (!prev.checkIssued(next) || !prev.verify(next.publicKey)) {
        ok = false;
        break;
      }
      prev = next;
    }
    if (ok) return true;
  }
  return false;
}

function canonical(o) {
  return JSON.stringify(Object.keys(o).sort().reduce((a, k) => {
    a[k] = o[k];
    return a;
  }, {}));
}

// Rekor signed "this is in the log at this time". integratedTime is only trusted because of it
function promiseOk(entry) {
  const log = trusted().logs.get(entry.logId && entry.logId.keyId);
  if (!log) fail('the transparency log that recorded it is not one this box trusts');
  const at = Number(entry.integratedTime) * 1000;
  if (!Number.isFinite(at) || at < log.valid.start || at > log.valid.end) fail('the transparency log entry is outside that log\'s trusted period');
  const set = entry.inclusionPromise && entry.inclusionPromise.signedEntryTimestamp;
  if (!set) fail('the transparency log entry has no signed promise');
  const message = canonical({
    body: entry.canonicalizedBody,
    integratedTime: Number(entry.integratedTime),
    logID: b64(entry.logId.keyId).toString('hex'),
    logIndex: Number(entry.logIndex)
  });
  if (!crypto.verify('sha256', Buffer.from(message), log.key, b64(set))) fail('the transparency log\'s signed promise does not verify');
  return at;
}

const pemBody = (text) => String(text).replace(/-----(BEGIN|END) CERTIFICATE-----|\s+/g, '');

// the log entry has to be about this signature, this certificate and this payload, not some other one
function entryMatches(entry, cert, payload, sig) {
  let body;
  try {
    body = JSON.parse(b64(entry.canonicalizedBody).toString('utf8'));
  } catch (err) {
    fail('the transparency log entry cannot be read');
  }
  const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
  const certDer = cert.raw.toString('base64');
  const spec = body && body.spec;
  let signatures;
  let hash;
  if (body.kind === 'dsse' && spec) {
    signatures = (spec.signatures || []).map((s) => ({ sig: s.signature, cert: b64(s.verifier).toString('utf8') }));
    hash = spec.payloadHash;
  } else if (body.kind === 'intoto' && spec && spec.content) {
    signatures = ((spec.content.envelope || {}).signatures || []).map((s) => ({ sig: b64(s.sig).toString('utf8'), cert: b64(s.publicKey).toString('utf8') }));
    hash = spec.content.payloadHash;
  } else {
    fail('the transparency log entry is not a kind this box understands');
  }
  if (!hash || hash.algorithm !== 'sha256' || hash.value !== payloadHash) fail('the transparency log entry is for a different statement');
  const wanted = sig.toString('base64');
  const match = signatures.some((s) => {
    const logged = /^[A-Za-z0-9+/=]+$/.test(s.sig) ? s.sig : Buffer.from(s.sig).toString('base64');
    return (logged === wanted || b64(logged).equals(sig)) && pemBody(s.cert) === certDer;
  });
  if (!match) fail('the transparency log entry is for a different signature or certificate');
}

// { certificate (DER), payloadType, payload, signature, entry } -> { statement, identity, integratedTime } or throws { invalid }
function verifyDsse({ certificate, payloadType, payload, signature, entry }) {
  if (payloadType !== IN_TOTO) fail('the attestation is not an in-toto statement');
  let cert;
  try {
    cert = new crypto.X509Certificate(certificate);
  } catch (err) {
    fail('the signing certificate cannot be read');
  }
  if (!entry) fail('there is no transparency log entry, so the signing time cannot be trusted');
  const at = promiseOk(entry);
  if (!chainOk(cert, at)) fail('the signing certificate was not issued by a trusted Sigstore authority');
  if (at < Date.parse(cert.validFrom) || at > Date.parse(cert.validTo)) fail('it was signed outside the certificate\'s valid time');
  if (!crypto.verify('sha256', pae(payloadType, payload), cert.publicKey, signature)) fail('the attestation signature does not verify');
  entryMatches(entry, cert, payload, signature);
  let statement;
  try {
    statement = JSON.parse(payload.toString('utf8'));
  } catch (err) {
    fail('the attestation statement cannot be read');
  }
  if (!statement || !Array.isArray(statement.subject)) fail('the attestation names no subject');
  return { statement, identity: identity(cert, certificate), integratedTime: new Date(at).toISOString() };
}

function subjectMatches(statement, digests) {
  return statement.subject.some((s) => s && s.digest && Object.entries(digests).some(([alg, v]) => v && String(s.digest[alg] || '').toLowerCase() === String(v).toLowerCase()));
}

// ---------------------------------------------------------------- npm registry signatures

let npmKeys = null;
function registryKeys() {
  if (!npmKeys) npmKeys = JSON.parse(fs.readFileSync(path.join(__dirname, 'trust', 'npm-registry-keys.json'), 'utf8')).keys;
  return npmKeys;
}

// npm signs name@version:integrity. a key that has expired still vouches for what it signed before then
function verifyRegistrySignature(name, version, dist, publishedAt) {
  const sigs = Array.isArray(dist && dist.signatures) ? dist.signatures : [];
  if (!sigs.length || !dist.integrity) return { status: 'MISSING' };
  const message = Buffer.from(`${name}@${version}:${dist.integrity}`);
  // the list is registry data, so anything that isn't a signature is skipped rather than tripped over
  const real = sigs.filter((s) => s && typeof s === 'object' && typeof s.keyid === 'string' && typeof s.sig === 'string');
  for (const s of real) {
    const key = registryKeys().find((k) => k.keyid === s.keyid);
    if (!key) continue;
    if (key.expires && publishedAt && Date.parse(publishedAt) > Date.parse(key.expires)) continue;
    const pub = crypto.createPublicKey({ key: b64(key.key), format: 'der', type: 'spki' });
    let good = false;
    try {
      good = crypto.verify('sha256', message, pub, b64(s.sig));
    } catch (err) {
      // a signature that isn't even shaped like one doesn't verify
    }
    if (good) return { status: 'VERIFIED', keyid: s.keyid };
  }
  return { status: real.some((s) => registryKeys().some((k) => k.keyid === s.keyid)) ? 'INVALID' : 'PRESENT_UNVERIFIED' };
}

module.exports = { verifyDsse, subjectMatches, verifyRegistrySignature, identity, der, oidText, useTrustForTests, IN_TOTO };
