// The hourly digest. one mail an hour tops, only with news in it.
// Author: Tim Rice
// each address has a mark per kind, a run mails what happened since, and the mark
// only moves once the mail actually went out. new addresses start at now, no backlog

const db = require('../../db');
const auth = require('../../security/auth');
const mail = require('./index');
const log = require('../../logger');
const digestState = require('../../db/repositories/digest-state');
const requests = require('../../db/repositories/requests');
const tokens = require('../../db/repositories/tokens');
const users = require('../../db/repositories/users');
const waivers = require('../../db/repositories/waivers');
const integrity = require('../../db/repositories/integrity');

const DECIDED = 'decided';
const PENDING = 'pending';
const INTEGRITY = 'integrity';

function integrityBody(rows) {
  const lines = [
    'A registry changed a release this box had already seen. Nothing was swapped on its own,',
    'someone has to accept or dismiss each one.',
    ''
  ];
  for (const r of rows.slice(0, 25)) {
    lines.push(`- ${r.ecosystem} ${r.package_name} ${r.version} (${r.filename}): `
      + `${r.kind === 'content' ? 'the downloaded bytes' : 'the published digest'} changed`);
  }
  if (rows.length > 25) lines.push(`...and ${rows.length - 25} more`);
  lines.push('');
  const url = portalUrl();
  if (url) lines.push(`Review them at ${url}#integrity`);
  return lines.join('\n');
}

// a nudge, not the whole list
const MAX_LINES = 25;

// db lock so nodes sharing a database don't each send the same digest
const LOCK = 'npmrepo_digest';

let running = false;

function portalUrl() {
  const base = db.settings.get('public_url');
  return base ? `${String(base).replace(/\/+$/, '')}/_admin` : null;
}

// lodash@^4.17.0 for npm, python ranges bring their own operator
function describe(row) {
  if (row.ecosystem && row.ecosystem !== 'npm') {
    return `${row.package_name}${row.version_range ? ` ${row.version_range}` : ''} (${row.ecosystem === 'oci' ? 'image' : 'PyPI'})`;
  }
  return row.version_range ? `${row.package_name}@${row.version_range}` : row.package_name;
}

function tail(total, shown) {
  const more = total - shown;
  return more > 0 ? [`  ...and ${more} more, which are on the portal`] : [];
}

// ---------------------------------------------------------------- the marks

// null = never seen before, clock starts now
async function mark(userId, kind, recipient, now) {
  const row = await digestState.markFor(userId, kind, recipient);
  if (row) return row.mark;
  await digestState.startMark(userId, kind, recipient, now);
  return null;
}

async function moveMark(userId, kind, recipient, now) {
  await digestState.moveMark(userId, kind, recipient, now);
}

// ---------------------------------------------------------------- what happened to the thing you asked for

const OUTCOME = {
  approved: 'approved',
  rejected: 'turned down',
  blocked: 'blocked'
};

function decidedBody(rows, toToken) {
  const one = rows.length === 1;
  const lines = [
    `${one ? 'One package request' : `${rows.length} package requests`} ${one ? 'has' : 'have'} been decided since the last of these.`,
    ''
  ];

  const shown = rows.slice(0, MAX_LINES);
  for (const row of shown) {
    const what = OUTCOME[row.status] || row.status;
    const who = row.decided_by ? ` by ${row.decided_by}` : '';
    lines.push(`  ${describe(row)} - ${what}${who}`);
    if (row.decision_note) lines.push(`      "${String(row.decision_note).slice(0, 300)}"`);
    if (row.token_name) lines.push(`      asked for by an install using the ${row.token_name} token`);
  }
  lines.push(...tail(rows.length, shown.length));

  lines.push('');
  if (rows.some((r) => r.status === 'approved')) {
    lines.push('Anything approved can be installed now. No change to your .npmrc or pip settings, they were always pointed here.');
  }
  const url = portalUrl();
  if (url) lines.push(`The requests page is at ${url}#requests`);
  if (toToken) {
    lines.push('');
    lines.push('This went to the address on the token rather than to an account, because that is the contact the token names.');
  }
  return lines.join('\n');
}

async function decidedFor(userId, since) {
  return requests.decidedSince(userId, since);
}

// token address wins if it has one, so a shared build token can point at its team
function byRecipient(rows, tokenEmails, fallback) {
  const groups = new Map();
  for (const row of rows) {
    const address = (row.token_name && tokenEmails.get(row.token_name)) || fallback;
    if (!address) continue;
    if (!groups.has(address)) groups.set(address, []);
    groups.get(address).push(row);
  }
  return groups;
}

// ---------------------------------------------------------------- what's waiting on you

// only new ones spelled out, old ones are just a count
function pendingBody(fresh, olderCount, oldest) {
  const one = fresh.length === 1;
  const lines = [
    one
      ? 'One new package request is waiting to be decided.'
      : `${fresh.length} new package requests are waiting to be decided.`,
    ''
  ];

  const shown = fresh.slice(0, MAX_LINES);
  for (const row of shown) {
    const who = row.requested_by_user || row.requested_by ||
      (row.token_name ? `the ${row.token_name} token` : 'a blocked install');
    const asked = row.hits > 1 ? `, asked ${row.hits} times` : '';
    lines.push(`  ${describe(row)} - ${who}${asked}`);
    if (row.reason) lines.push(`      "${String(row.reason).slice(0, 200)}"`);
  }
  lines.push(...tail(fresh.length, shown.length));

  if (olderCount) {
    lines.push('');
    lines.push(`${olderCount} other${olderCount === 1 ? ' request was' : ' requests were'} already on the list before this` +
      `${oldest ? `, the oldest since ${String(oldest).slice(0, 16)}` : ''}, ` +
      'so they are not listed again here.');
  }

  lines.push('');
  const url = portalUrl();
  if (url) lines.push(`Decide them at ${url}#requests`);
  return lines.join('\n');
}

// ---------------------------------------------------------------- the run itself

async function forUser(user, now, name) {
  let sent = 0;

  try {
    const own = await tokens.emailsFor(user.id);
    const emails = new Map(own.filter((t) => mail.validAddress(t.email)).map((t) => [t.name, t.email]));

    const addresses = new Set([user.email, ...emails.values()]);
    const since = new Map();
    for (const address of addresses) since.set(address, await mark(user.id, DECIDED, address, now));

    //one query from the earliest mark, then filter per address
    const live = [...since.values()].filter(Boolean);
    if (live.length) {
      const earliest = live.sort()[0];
      const rows = await decidedFor(user.id, earliest);
      const groups = byRecipient(rows, emails, user.email);

      for (const [address, group] of groups) {
        const from = since.get(address);
        if (!from) continue;
        const mine = group.filter((r) => String(r.resolved_at) > String(from));
        if (!mine.length) continue;
        try {
          await mail.send({
            to: address,
            subject: `[${name}] ${mine.length} package request${mine.length === 1 ? '' : 's'} decided`,
            text: decidedBody(mine, address !== user.email),
            kind: DECIDED
          });
          sent += 1;
          await moveMark(user.id, DECIDED, address, now);
        } catch (err) {
          // it'll receive it next hour
          log.error(`could not send the decided digest to ${address}`, err.message);
        }
      }
      // quiet addresses move too, or a quiet week becomes one giant mail
      for (const address of addresses) {
        if (since.get(address) && !groups.has(address)) await moveMark(user.id, DECIDED, address, now);
      }
    }
  } catch (err) {
    log.error(`the decided digest for ${user.username} failed`, err.message);
  }

  // malware still flagged, once a day, for whoever can release or reject it. quiet days send nothing
  if (auth.can({ role: user.role }, 'cache:purge') && db.settings.getBool('email_malware_daily')) {
    try {
      const since = await mark(user.id, 'malware-daily', user.email, now);
      if (since && new Date(now) - new Date(since) >= 23.5 * 3600000) {
        const malwaremail = require('./malware-alerts');
        const { rows, total } = await malwaremail.outstanding();
        if (total) {
          await mail.send({
            to: user.email,
            subject: `[${name}] ${total} file${total === 1 ? '' : 's'} still flagged by a malware scan`,
            text: malwaremail.dailyBody(rows, total),
            kind: 'malware-daily'
          });
          sent += 1;
        }
        await moveMark(user.id, 'malware-daily', user.email, now);
      }
    } catch (err) {
      log.error(`the malware digest for ${user.username} failed`, err.message);
    }
  }

  // waivers waiting for a decision, and ones running out within a week. once a day, quiet days send nothing
  if (auth.can({ role: user.role }, 'rules:write') && auth.can({ role: user.role }, 'requests:decide')) {
    try {
      const since = await mark(user.id, 'waivers-daily', user.email, now);
      if (since && new Date(now) - new Date(since) >= 23.5 * 3600000) {
        const pending = await waivers.waitingForDecision(50);
        const ending = await waivers.endingWithinAWeek(50);
        if (pending.length || ending.length) {
          const line = (w) => `- ${w.kind}: ${w.ecosystem === 'pypi' ? 'PyPI ' : w.ecosystem === 'oci' ? 'image ' : ''}${w.package_name}${w.version_range ? ` ${w.version_range}` : ''}${w.subject ? ` [${w.subject}]` : ''}${w.reference ? ` (ticket ${w.reference})` : ''}`;
          const text = [
            pending.length ? `${pending.length} waiver request(s) waiting for a decision:` : null,
            ...pending.map((w) => `${line(w)}, asked by ${w.requested_by || 'someone'}: ${String(w.reason).slice(0, 200)}`),
            pending.length && ending.length ? '' : null,
            ending.length ? `${ending.length} waiver(s) running out within a week, after which the finding applies again:` : null,
            ...ending.map((w) => `${line(w)}, until ${String(w.expires_at).slice(0, 16)}`),
            '',
            `${portalUrl()}#waivers`
          ].filter((x) => x !== null).join('\n');
          await mail.send({ to: user.email, subject: `[${name}] Waivers: ${pending.length} waiting, ${ending.length} ending soon`, text, kind: 'waivers-daily' });
          sent += 1;
        }
        await moveMark(user.id, 'waivers-daily', user.email, now);
      }
    } catch (err) {
      log.error(`the waiver digest for ${user.username} failed`, err.message);
    }
  }

  // integrity alerts, for whoever can resolve them. before the requests part, which returns early
  if (auth.can({ role: user.role }, 'cache:purge')) {
    try {
      const since = await mark(user.id, INTEGRITY, user.email, now);
      if (since) {
        const fresh = await integrity.openSince(since, 200);
        if (fresh.length) {
          await mail.send({
            to: user.email,
            subject: `[${name}] ${fresh.length} release integrity alert${fresh.length === 1 ? '' : 's'}`,
            text: integrityBody(fresh),
            kind: INTEGRITY
          });
          sent += 1;
        }
        await moveMark(user.id, INTEGRITY, user.email, now);
      }
    } catch (err) {
      log.error(`the integrity digest for ${user.username} failed`, err.message);
    }
  }

  if (!auth.can({ role: user.role }, 'requests:decide')) return sent;
  try {
    const since = await mark(user.id, PENDING, user.email, now);
    if (!since) return sent;

    const fresh = await requests.pendingSince(since);
    // nothing new, not news
    if (!fresh.length) return sent;

    const older = await requests.pendingBefore(since);

    await mail.send({
      to: user.email,
      subject: `[${name}] ${fresh.length} new package request${fresh.length === 1 ? '' : 's'} to decide`,
      text: pendingBody(fresh, Number(older.n) || 0, older.oldest),
      kind: PENDING
    });
    sent += 1;
    await moveMark(user.id, PENDING, user.email, now);
  } catch (err) {
    log.error(`the pending digest for ${user.username} failed`, err.message);
  }

  return sent;
}

async function runOnce() {
  if (!db.settings.getBool('email_enabled')) return { sent: 0, skipped: 'email is off' };
  const problem = mail.unusable();
  if (problem) return { sent: 0, skipped: problem };

  const now = await digestState.now();
  const name = db.settings.get('registry_name') || 'ForgeRepo';

  const people = await users.withEmail();

  let sent = 0;
  for (const user of people) {
    if (!mail.validAddress(user.email)) continue;
    sent += await forUser(user, now, name);
  }
  return { sent };
}

// zero timeout, so a losing node gives up instead of queueing and definitely
// sending it all twice
async function withLock(work) {
  const held = await digestState.withLock(LOCK, work);
  return held ? held.result : { sent: 0, skipped: 'another node is running the digest' };
}

async function run() {
  if (running) return { sent: 0, skipped: 'a digest run is already going' };
  running = true;
  try {
    const result = await withLock(runOnce);
    if (result.sent) log.info(`the digest went out to ${result.sent} address(es)`);
    return result;
  } catch (err) {
    log.error('the digest run failed', err.message);
    return { sent: 0, error: err.message };
  } finally {
    running = false;
  }
}

module.exports = { run, runOnce };
