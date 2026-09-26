// Email from the portal: a test message, the digest on demand, and the send log.
// Author: Tim Rice

const db = require('../db');
const mail = require('../integrations/mail');
const digest = require('../integrations/mail/digest');
const repo = require('../db/repositories/email-log');
const { audit } = require('../lib/actor');
const { fail } = require('../lib/errors');

// works with the switch off on purpose, test BEFORE turning it on. to is already a checked address
async function sendTest(actor, to) {
  const name = db.settings.get('registry_name') || 'ForgeRepo';
  const url = db.settings.get('public_url');
  try {
    await mail.send({
      to,
      subject: `[${name}] test message`,
      text: [
        `This is a test from ${name}, sent by ${actor.name}.`,
        '',
        'If you are reading it, the mail settings on the box are right and the',
        'hourly digest will go out the same way.',
        url ? `\nThe portal is at ${url}/_admin` : ''
      ].join('\n'),
      kind: 'test',
      force: true
    });
  } catch (err) {
    await audit(actor, 'email.test', to, `failed: ${err.message}`);
    fail(400, err.message);
  }
  await audit(actor, 'email.test', to, 'sent');
}

// same marks as the hourly run, so button mashing won't double send
async function runDigest(actor) {
  const result = await digest.run();
  await audit(actor, 'email.digest.run', null, result.skipped || `${result.sent} sent`);
  return result;
}

function log(paging) {
  return repo.page(paging);
}

module.exports = { sendTest, runDigest, log };
