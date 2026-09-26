// Promoting and demoting package versions through their lifecycle, every move kept.
// Author: Tim Rice

const lifecycle = require('../policy/lifecycle');
const repo = require('../db/repositories/lifecycle');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

const MAX_REASON = 500;

const label = (t) => `${t.ecosystem}:${t.name}@${t.version}`;

async function get(target) {
  const now = await repo.current(target.ecosystem, target.name, target.version);
  return {
    target,
    stage: now ? now.stage : null,
    reason: now ? now.reason : null,
    setBy: now ? now.set_by : null,
    setAt: now ? now.set_at : null,
    history: await repo.history(target.ecosystem, target.name, target.version, 100),
    enforcing: lifecycle.enforcing()
  };
}

// from: the stage the person was looking at, so two people moving it at once don't silently overwrite each other
async function move(actor, target, { stage, from, reason }) {
  if (!lifecycle.STAGES.includes(stage)) fail(400, `the stage is one of ${lifecycle.STAGES.join(', ')}`);
  // eslint-disable-next-line no-control-regex -- one line of plain text
  const why = String(reason === undefined || reason === null ? '' : reason).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, MAX_REASON);
  if (!why) fail(400, 'say why, every move is kept with its reason');
  const now = await repo.current(target.ecosystem, target.name, target.version);
  const was = now ? now.stage : null;
  const expected = from === undefined ? was : (from === '' || from === null ? null : String(from));
  if (expected !== was) fail(409, `${label(target)} moved to ${was || 'no stage'} while you were looking, have another look`);
  if (was === stage) fail(409, `${label(target)} is already at ${stage}`);
  if (!(await repo.move({ ...target, from: was, to: stage, reason: why, user: actor.name }))) {
    fail(409, `${label(target)} was moved by someone else a moment ago, have another look`);
  }
  lifecycle.invalidate();
  await audit(actor, 'lifecycle.move', label(target), why, { before: { stage: was }, after: { stage } });
  return get(target);
}

async function counts() {
  return Object.fromEntries((await repo.counts()).map((r) => [r.stage, Number(r.n)]));
}

module.exports = { MAX_REASON, get, move, counts };
