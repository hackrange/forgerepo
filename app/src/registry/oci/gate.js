// Deciding a pull of an image: a tag, the digest a tag points at, or a digest asked for on its own (a platform image,
// a config blob, a layer). one place, so the registry and the Check page give the same answer.
// Author: Tim Rice
//
// rules name tags, pulls name digests. a digest is judged by, in order: a deny, kill or blocked stage naming it, or an
// allow whose range names it; a tag that points or pointed at it here (an allow lets it through, a deny, kill or blocked
// stage refuses it, so a denied tag cannot be had by asking for its digest); the images or lists that name it, when it
// is a layer or a platform image; and last a rule with no range, or whatever the mode says. a rule with no range comes
// last because it says nothing about tags: allow nginx next to deny nginx 1.19.* must not let 1.19.0 in by digest.
// a layer only an unknown manifest names is judged by the mode alone. a digest this box never saw a tag resolve to has
// no tags to go on, so a tag refused before it was ever pulled here is only kept out by a rule on the digest itself

const ecosystems = require('../../ecosystems');
const ociName = require('../../ecosystems/oci/name');
const policy = require('../../policy');
const killswitch = require('../../policy/killswitch');
const lifecycle = require('../../policy/lifecycle');
const refs = require('../../db/repositories/oci-refs');

const MAX_HOPS = 2;
const adapter = () => ecosystems.adapter('oci');
const refused = (reason, extra) => ({ allowed: false, rule: null, reason, ...(extra || {}) });
const firm = (v) => !v.allowed && (v.killed || v.lifecycle || (v.rule && v.rule.kind === 'deny'));

// a kill or a blocked stage on this exact reference, tag or digest
async function stopped(repository, reference) {
  const dead = await killswitch.check('oci', repository, reference);
  if (dead) return refused(dead.reason, { killed: true });
  if (ociName.isDigest(reference)) {
    const hash = await killswitch.checkHash(reference.slice(7));
    if (hash) return refused(hash.reason, { killed: true });
  }
  const stage = await lifecycle.blocked('oci', repository, reference);
  return stage ? refused(stage, { lifecycle: true }) : null;
}

// what the tags of a digest say: the first tag it would be served under (an allow rule, or blacklist mode letting the tag
// through with its stage satisfied), or else the first tag that refuses it outright. each tag is asked about under every
// name the image goes by, the same as pulling the tag would, since the tag history is kept under one name only
async function byTags(repository, digest, scope, names = [repository]) {
  let no = null;
  for (const t of await refs.tagsFor(repository, digest)) {
    const verdicts = [];
    for (const name of names) verdicts.push(await tag(name, t, scope));
    const v = verdicts.find(firm) || verdicts.find((x) => x.allowed) || verdicts[0];
    if (v.allowed) return { yes: { ...v, reason: `${v.reason}, tag ${t}` } };
    if (firm(v)) no = no || { ...v, reason: `${v.reason}, tag ${t}` };
  }
  return { no };
}

/** a digest asked for by itself */
async function digest(repository, ref, scope, hops = 0, names = [repository]) {
  const stop = await stopped(repository, ref);
  if (stop) return stop;
  const direct = await policy.checkVersion(repository, ref, adapter(), scope);
  if (!direct.allowed && direct.rule && direct.rule.kind === 'deny') return direct;
  // a digest only ever matches a range by being written in it, so this allow names this exact image
  if (direct.allowed && direct.rule && direct.rule.kind === 'allow' && direct.rule.version_range) return direct;

  const tags = await byTags(repository, ref, scope, names);
  if (tags.yes) return tags.yes;
  if (tags.no) return tags.no;

  if (hops < MAX_HOPS) {
    const parents = await refs.parentsOf(repository, ref);
    let firstNo = null;
    for (const parent of parents) {
      const up = await digest(repository, parent, scope, hops + 1, names);
      if (up.allowed) return up;
      firstNo = firstNo || up;
    }
    // every image that names it is refused, so it is too
    if (parents.length && firstNo) return firstNo;
  }
  return direct;
}

/** the digest a tag that was just let through resolved to. only what names the digest itself can take it away */
async function pointedAt(repository, ref, scope) {
  const stop = await stopped(repository, ref);
  if (stop) return stop;
  const direct = await policy.checkVersion(repository, ref, adapter(), scope);
  if (!direct.allowed && direct.rule && direct.rule.kind === 'deny') return direct;
  return { allowed: true, rule: null, reason: 'the tag is allowed' };
}

/** a tag, or no reference at all for the repository */
async function tag(repository, ref, scope) {
  if (!ref) return policy.checkPackage(repository, adapter(), scope);
  const stop = await stopped(repository, ref);
  if (stop) return stop;
  return policy.checkVersion(repository, ref, adapter(), scope);
}

function decideOne(repository, reference, scope, options) {
  if (!reference || !ociName.isDigest(reference)) return tag(repository, reference, scope);
  return options.pointedAt ? pointedAt(repository, reference, scope) : digest(repository, reference, scope, 0, namesOf(repository, options));
}

const namesOf = (repository, options) => (options.aliases && options.aliases.length ? options.aliases : [repository]);

/**
 * options.aliases: every name the same image goes by (nginx and library/nginx on Docker Hub). a deny, kill or blocked
 * stage on any of them refuses, otherwise an allow on any of them lets it through
 */
async function decide(repository, reference, scope, options = {}) {
  const verdicts = [];
  for (const name of namesOf(repository, options)) verdicts.push(await decideOne(name, reference, scope, options));
  return verdicts.find(firm) || verdicts.find((v) => v.allowed) || verdicts[0];
}

module.exports = { decide, digest, pointedAt, tag };
