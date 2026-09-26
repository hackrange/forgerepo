// Checking a cosign signature on an image, keyed or keyless. no network in here: the signature manifest, its payloads and
// the trust root are handed in, and the answer is who signed which digest, or why nobody provably did.
// Author: Tim Rice
//
// keyless is the Sigstore public good way: a short lived Fulcio certificate that names the signer (a GitHub workflow,
// an email), and a Rekor entry proving the signature was logged while that certificate was valid. the chain the
// signer attaches is never trusted, only the roots in the trust root. SCTs are not checked, the Rekor entry is

const crypto = require('crypto');
const { X509Certificate } = crypto;

const SIGNATURE = 'dev.cosignproject.cosign/signature';
const CERTIFICATE = 'dev.sigstore.cosign/certificate';
const BUNDLE = 'dev.sigstore.cosign/bundle';
const SIMPLE_SIGNING = 'application/vnd.dev.cosign.simplesigning.v1+json';
const MAX_LAYERS = 20;

// Fulcio's own extensions: who issued the login token the certificate was made from
const OID_ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';
const OID_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';
const OID_SAN = '2.5.29.17';

// ---------------------------------------------------------------- just enough DER for certificate extensions

function readTlv(buf, at) {
  if (at + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[at];
  let len = buf[at + 1];
  let head = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || at + 2 + n > buf.length) throw new Error('bad DER length');
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + buf[at + 2 + i];
    head += n;
  }
  const start = at + head;
  if (start + len > buf.length) throw new Error('truncated DER');
  return { tag, start, end: start + len };
}

function children(buf, tlv) {
  const out = [];
  for (let at = tlv.start; at < tlv.end;) {
    const c = readTlv(buf, at);
    out.push(c);
    at = c.end;
  }
  return out;
}

function oidOf(buf, tlv) {
  const b = buf.subarray(tlv.start, tlv.end);
  if (!b.length) return '';
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i += 1) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

// oid -> the extension's value bytes
function extensions(der) {
  const cert = readTlv(der, 0);
  const tbs = children(der, cert)[0];
  const out = new Map();
  for (const field of children(der, tbs)) {
    if (field.tag !== 0xa3) continue;
    const seq = children(der, field)[0];
    for (const ext of children(der, seq)) {
      const parts = children(der, ext);
      const oid = oidOf(der, parts[0]);
      const value = parts[parts.length - 1];
      out.set(oid, der.subarray(value.start, value.end));
    }
  }
  return out;
}

// the names in a subjectAltName: email (rfc822Name) and URI are what Fulcio writes
function altNames(value) {
  const seq = readTlv(value, 0);
  return children(value, seq)
    .filter((n) => n.tag === 0x81 || n.tag === 0x86)
    .map((n) => value.subarray(n.start, n.end).toString('utf8'));
}

function issuerOf(ext) {
  const v2 = ext.get(OID_ISSUER_V2);
  if (v2) {
    const s = readTlv(v2, 0);
    return v2.subarray(s.start, s.end).toString('utf8');
  }
  const v1 = ext.get(OID_ISSUER_V1);
  return v1 ? v1.toString('utf8') : null;
}

// ---------------------------------------------------------------- the trust root

const ROOT = require('./sigstore-trusted-root.json');

const within = (validFor, t) => {
  const from = validFor && validFor.start ? Date.parse(validFor.start) : -Infinity;
  const to = validFor && validFor.end ? Date.parse(validFor.end) : Infinity;
  return t >= from && t <= to;
};

function trustRoot(raw) {
  const doc = raw || ROOT;
  const cas = (doc.certificateAuthorities || []).map((ca) => ({
    validFor: ca.validFor,
    certs: ((ca.certChain && ca.certChain.certificates) || []).map((c) => new X509Certificate(Buffer.from(c.rawBytes, 'base64')))
  }));
  const tlogs = (doc.tlogs || []).map((t) => ({
    id: Buffer.from(t.logId.keyId, 'base64').toString('hex'),
    validFor: t.publicKey.validFor,
    key: crypto.createPublicKey({ key: Buffer.from(t.publicKey.rawBytes, 'base64'), format: 'der', type: 'spki' })
  }));
  return { cas, tlogs };
}

// the leaf chains to a root in the trust root, every link valid when it was used
function chains(leaf, root, t) {
  for (const ca of root.cas) {
    if (!within(ca.validFor, t)) continue;
    let cur = leaf;
    for (let hops = 0; hops <= ca.certs.length; hops += 1) {
      const up = ca.certs.find((c) => cur.checkIssued(c) && cur.verify(c.publicKey));
      if (!up) break;
      if (t < Date.parse(up.validFrom) || t > Date.parse(up.validTo)) break;
      if (up.checkIssued(up) && up.verify(up.publicKey)) return true;
      cur = up;
    }
  }
  return false;
}

// ---------------------------------------------------------------- Rekor

// the signed entry timestamp is over the entry in canonical json: sorted keys, no spaces
function checkSet(bundle, root) {
  const p = bundle && bundle.Payload;
  if (!p || typeof p.body !== 'string' || !Number.isSafeInteger(p.integratedTime) || !Number.isSafeInteger(p.logIndex) || typeof p.logID !== 'string') {
    throw new Error('the Rekor entry is incomplete');
  }
  const log = root.tlogs.find((l) => l.id === p.logID.toLowerCase());
  if (!log) throw new Error('the Rekor entry is from a log the trust root does not know');
  const t = p.integratedTime * 1000;
  if (!within(log.validFor, t)) throw new Error('the Rekor entry is from outside its log\'s validity');
  const canonical = `{"body":${JSON.stringify(p.body)},"integratedTime":${p.integratedTime},"logID":${JSON.stringify(p.logID)},"logIndex":${p.logIndex}}`;
  const set = Buffer.from(String(bundle.SignedEntryTimestamp || ''), 'base64');
  if (!set.length || !crypto.verify('sha256', Buffer.from(canonical), log.key, set)) throw new Error('the Rekor signed entry timestamp does not verify');
  let body;
  try {
    body = JSON.parse(Buffer.from(p.body, 'base64').toString('utf8'));
  } catch (err) {
    throw new Error('the Rekor entry body is not json');
  }
  return { t, body };
}

// the logged entry is this signature, over this payload, by this certificate or key
function entryMatches(body, payload, signature, keyPem) {
  if (!body || body.kind !== 'hashedrekord' || !body.spec) throw new Error(`the Rekor entry is a ${String(body && body.kind).slice(0, 40)}, not a hashedrekord`);
  const hash = body.spec.data && body.spec.data.hash;
  if (!hash || hash.algorithm !== 'sha256' || hash.value !== crypto.createHash('sha256').update(payload).digest('hex')) {
    throw new Error('the Rekor entry is for a different payload');
  }
  const sig = body.spec.signature || {};
  if (!Buffer.from(String(sig.content || ''), 'base64').equals(signature)) throw new Error('the Rekor entry holds a different signature');
  const logged = Buffer.from(String((sig.publicKey && sig.publicKey.content) || ''), 'base64').toString('utf8');
  if (keyPem && der(logged) && !der(logged).equals(der(keyPem))) throw new Error('the Rekor entry names a different signer');
}

function der(pem) {
  const m = /-----BEGIN [A-Z ]+-----([\s\S]+?)-----END [A-Z ]+-----/.exec(String(pem || ''));
  return m ? Buffer.from(m[1].replace(/\s+/g, ''), 'base64') : null;
}

// ---------------------------------------------------------------- identities

// exact, or * for any run of characters. a glob, not a regex, so a policy can't be a ReDoS
function globMatch(pattern, value) {
  const p = String(pattern || '');
  if (!p.includes('*')) return p === value;
  const re = new RegExp(`^${p.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
  return re.test(value);
}

// ---------------------------------------------------------------- one signature

function payloadDigest(payload) {
  let doc;
  try {
    doc = JSON.parse(payload.toString('utf8'));
  } catch (err) {
    throw new Error('the signed payload is not json');
  }
  const c = doc && doc.critical;
  if (!c || c.type !== 'cosign container image signature') throw new Error('the signed payload is not a cosign image signature');
  return c.image && c.image['docker-manifest-digest'];
}

/**
 * checks one signature layer against a trust policy.
 * trust = { keys: [pem], identities: [{ issuer, subject }], requireLog: bool }
 * @returns {{ signer: string, how: 'key'|'keyless', logged: boolean }}
 */
function checkLayer(layer, payload, digest, trust, root) {
  const ann = layer.annotations || {};
  const signature = Buffer.from(String(ann[SIGNATURE] || ''), 'base64');
  if (!signature.length) throw new Error('no signature on the layer');
  if (payloadDigest(payload) !== digest) throw new Error('the signature is for a different image');
  const bundle = ann[BUNDLE] ? JSON.parse(ann[BUNDLE]) : null;

  if (ann[CERTIFICATE]) {
    if (!(trust.identities || []).length) throw new Error('a keyless signature, and no signer identities are trusted here');
    const leaf = new X509Certificate(ann[CERTIFICATE]);
    // keyless without the log is only a certificate that expired ten minutes after it was made
    if (!bundle) throw new Error('a keyless signature with no Rekor entry');
    const { t, body } = checkSet(bundle, root);
    entryMatches(body, payload, signature, ann[CERTIFICATE]);
    if (t < Date.parse(leaf.validFrom) || t > Date.parse(leaf.validTo)) throw new Error('logged when its certificate was not valid');
    if (!chains(leaf, root, t)) throw new Error('the certificate does not chain to a trusted Fulcio root');
    if (!crypto.verify('sha256', payload, leaf.publicKey, signature)) throw new Error('the signature does not verify');
    const ext = extensions(leaf.raw);
    const issuer = issuerOf(ext);
    const names = ext.get(OID_SAN) ? altNames(ext.get(OID_SAN)) : [];
    const who = trust.identities.find((i) => issuer && i.issuer === issuer && names.some((n) => globMatch(i.subject, n)));
    if (!who) throw new Error(`signed by ${names[0] || 'nobody named'} (${issuer || 'no issuer'}), not a trusted identity`);
    return { signer: `${names.find((n) => globMatch(who.subject, n))} via ${issuer}`, how: 'keyless', logged: true };
  }

  for (const k of trust.keys || []) {
    let key;
    try {
      key = crypto.createPublicKey(k.pem || k);
    } catch (err) {
      continue;
    }
    // ed25519 signs the message itself, everything else a sha256 of it
    const algo = key.asymmetricKeyType === 'ed25519' ? null : 'sha256';
    if (!crypto.verify(algo, payload, key, signature)) continue;
    let logged = false;
    if (bundle) {
      const { body } = checkSet(bundle, root);
      entryMatches(body, payload, signature, null);
      logged = true;
    }
    if (trust.requireLog && !logged) throw new Error('signed with a trusted key, but not in the transparency log');
    return { signer: `key ${k.name || fingerprint(key)}`, how: 'key', logged };
  }
  throw new Error((trust.keys || []).length ? 'not signed by any trusted key' : 'a keyed signature, and no keys are trusted here');
}

function fingerprint(key) {
  return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16);
}

/**
 * every signature on an image. sig = the .sig manifest, payloads = digest -> bytes (already checked against the digest)
 * @returns {{ ok: boolean, signer?: string, how?: string, reasons: string[] }}
 */
function verify({ digest, sig, payloads, trust, root }) {
  const r = root || trustRoot();
  const layers = (sig && Array.isArray(sig.layers) ? sig.layers : []).filter((l) => l && l.mediaType === SIMPLE_SIGNING).slice(0, MAX_LAYERS);
  if (!layers.length) return { ok: false, reasons: ['no cosign signatures'] };
  const reasons = [];
  for (const layer of layers) {
    const payload = payloads.get(layer.digest);
    if (!payload) {
      reasons.push('a signature payload could not be fetched');
      continue;
    }
    try {
      return { ok: true, ...checkLayer(layer, payload, digest, trust, r), reasons };
    } catch (err) {
      reasons.push(err.message);
    }
  }
  return { ok: false, reasons };
}

// ---------------------------------------------------------------- the newer layout: a Sigstore bundle

const BUNDLE_TYPE = /^application\/vnd\.dev\.sigstore\.bundle\.v\d+\.\d+\+json$/;
const IN_TOTO = 'application/vnd.in-toto+json';

// DSSE signs this, not the payload: the type and the payload with their lengths in front
function pae(payloadType, payload) {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `),
    payload
  ]);
}

// the Rekor entry of a bundle, in the shape the older check reads
function bundleLog(entry, payload, signature, root) {
  const set = {
    SignedEntryTimestamp: (entry.inclusionPromise || {}).signedEntryTimestamp,
    Payload: {
      body: entry.canonicalizedBody,
      integratedTime: Number(entry.integratedTime),
      logID: Buffer.from(String((entry.logId || {}).keyId || ''), 'base64').toString('hex'),
      logIndex: Number(entry.logIndex)
    }
  };
  const { t, body } = checkSet(set, root);
  if (body && body.kind === 'dsse') {
    const spec = body.spec || {};
    const hash = (spec.payloadHash || {}).value;
    if (hash && hash !== crypto.createHash('sha256').update(payload).digest('hex')) throw new Error('the Rekor entry is for a different payload');
    const sigs = (spec.signatures || []).map((s) => s && s.signature);
    if (sigs.length && !sigs.some((s) => Buffer.from(String(s), 'base64').equals(signature))) throw new Error('the Rekor entry holds a different signature');
  }
  return t;
}

// what the signed statement says it is about: pkg:oci style subjects are not used, cosign names the digest
function statementDigest(payload) {
  let doc;
  try {
    doc = JSON.parse(payload.toString('utf8'));
  } catch (err) {
    throw new Error('the signed statement is not json');
  }
  const subject = (doc && Array.isArray(doc.subject) ? doc.subject : [])[0] || {};
  const sha = (subject.digest || {})['sha256'];
  return sha ? `sha256:${sha}` : null;
}

/** one Sigstore bundle against the trust policy. same answer shape as checkLayer */
function checkBundle(bundle, digest, trust, root) {
  const env = bundle && bundle.dsseEnvelope;
  if (!env) throw new Error(bundle && bundle.messageSignature ? 'a bundle that signs bytes rather than the image, which is not what an image signature looks like' : 'the bundle carries no DSSE envelope');
  if (env.payloadType !== IN_TOTO) throw new Error(`the bundle signs a ${String(env.payloadType).slice(0, 60)}, not an in-toto statement`);
  const payload = Buffer.from(String(env.payload || ''), 'base64');
  const signature = Buffer.from(String(((env.signatures || [])[0] || {}).sig || ''), 'base64');
  if (!payload.length || !signature.length) throw new Error('the bundle has no payload or no signature');
  if (statementDigest(payload) !== digest) throw new Error('the signature is for a different image');
  const signed = pae(env.payloadType, payload);
  const material = bundle.verificationMaterial || {};
  const entry = (material.tlogEntries || [])[0];

  if (material.certificate && material.certificate.rawBytes) {
    if (!(trust.identities || []).length) throw new Error('a keyless signature, and no signer identities are trusted here');
    if (!entry) throw new Error('a keyless signature with no Rekor entry');
    const leaf = new X509Certificate(Buffer.from(material.certificate.rawBytes, 'base64'));
    const t = bundleLog(entry, payload, signature, root);
    if (t < Date.parse(leaf.validFrom) || t > Date.parse(leaf.validTo)) throw new Error('logged when its certificate was not valid');
    if (!chains(leaf, root, t)) throw new Error('the certificate does not chain to a trusted Fulcio root');
    if (!crypto.verify('sha256', signed, leaf.publicKey, signature)) throw new Error('the signature does not verify');
    const ext = extensions(leaf.raw);
    const issuer = issuerOf(ext);
    const names = ext.get(OID_SAN) ? altNames(ext.get(OID_SAN)) : [];
    const who = (trust.identities || []).find((i) => issuer && i.issuer === issuer && names.some((n) => globMatch(i.subject, n)));
    if (!who) throw new Error(`signed by ${names[0] || 'nobody named'} (${issuer || 'no issuer'}), not a trusted identity`);
    return { signer: `${names.find((n) => globMatch(who.subject, n))} via ${issuer}`, how: 'keyless', logged: true };
  }

  for (const k of trust.keys || []) {
    let key;
    try {
      key = crypto.createPublicKey(k.pem || k);
    } catch (err) {
      continue;
    }
    const algo = key.asymmetricKeyType === 'ed25519' ? null : 'sha256';
    if (!crypto.verify(algo, signed, key, signature)) continue;
    let logged = false;
    if (entry) {
      bundleLog(entry, payload, signature, root);
      logged = true;
    }
    if (trust.requireLog && !logged) throw new Error('signed with a trusted key, but not in the transparency log');
    return { signer: `key ${k.name || fingerprint(key)}`, how: 'key', logged };
  }
  throw new Error((trust.keys || []).length ? 'not signed by any trusted key' : 'a keyed signature, and no keys are trusted here');
}

/**
 * the bundles hanging off an image. manifests = the referrer manifests, blobs = digest -> bundle bytes
 * @returns {{ ok: boolean, signer?: string, how?: string, reasons: string[] }}
 */
function verifyBundles({ digest, manifests, blobs, trust, root }) {
  const r = root || trustRoot();
  const reasons = [];
  for (const doc of (manifests || []).slice(0, MAX_LAYERS)) {
    for (const layer of (doc && Array.isArray(doc.layers) ? doc.layers : []).filter((l) => l && BUNDLE_TYPE.test(String(l.mediaType)))) {
      const bytes = blobs.get(layer.digest);
      if (!bytes) {
        reasons.push('a bundle could not be fetched');
        continue;
      }
      try {
        return { ok: true, ...checkBundle(JSON.parse(bytes.toString('utf8')), digest, trust, r), reasons };
      } catch (err) {
        reasons.push(err.message);
      }
    }
  }
  return { ok: false, reasons };
}

// the tag cosign keeps an image's signatures under: the older .sig, and the referrers fallback the newer one uses
const sigTag = (digest) => `${digest.replace(':', '-')}.sig`;
const bundleTag = (digest) => digest.replace(':', '-');

module.exports = {
  verify, verifyBundles, sigTag, bundleTag, trustRoot, globMatch, SIMPLE_SIGNING, BUNDLE_TYPE,
  _internal: { extensions, altNames, issuerOf, checkSet, chains, payloadDigest, pae, checkBundle, statementDigest }
};
