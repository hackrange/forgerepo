// Sending mail. smtp, or the Microsoft 365 Graph api if that's your life.
// Author: Tim Rice
// settings, whether mail can go out at all, and the one send() everything calls. the wire work is next door

const db = require('../../db');
const log = require('../../logger');
const emailLog = require('../../db/repositories/email-log');
const { oneLine, addressOnly, validAddress, buildMessage } = require('./message');
const { sendSmtp } = require('./smtp');
const { sendGraph } = require('./graph');

function config() {
  return {
    enabled: db.settings.getBool('email_enabled'),
    transport: db.settings.get('email_transport') === 'graph' ? 'graph' : 'smtp',
    email_from: db.settings.get('email_from') || '',
    email_from_name: db.settings.get('email_from_name') || db.settings.get('registry_name') || '',
    smtp_host: db.settings.get('smtp_host') || '',
    smtp_port: db.settings.get('smtp_port') || '587',
    smtp_security: db.settings.get('smtp_security') || 'starttls',
    smtp_user: db.settings.get('smtp_user') || '',
    smtp_password: db.settings.get('smtp_password') || '',
    // verify ON by default. self signed relays have to opt out on purpose
    smtp_verify: !db.settings.getBool('smtp_allow_self_signed'),
    graph_tenant: db.settings.get('graph_tenant') || '',
    graph_client_id: db.settings.get('graph_client_id') || '',
    graph_client_secret: db.settings.get('graph_client_secret') || '',
    graph_sender: db.settings.get('graph_sender') || ''
  };
}

// why mail can't go out, or null
function unusable(settings = config()) {
  if (!settings.email_from) return 'no address to send from is set';
  if (!validAddress(settings.email_from)) return 'the address to send from is not an email address';
  if (settings.transport === 'smtp') {
    if (!settings.smtp_host) return 'no smtp server is set';
    if (settings.smtp_user && !settings.smtp_password) return 'there is an smtp username with no password';
  } else {
    if (!settings.graph_tenant) return 'no microsoft tenant is set';
    if (!settings.graph_client_id) return 'no microsoft application id is set';
    if (!settings.graph_client_secret) return 'no microsoft client secret is set';
    if (!settings.graph_sender && !settings.email_from) return 'no mailbox to send from is set';
  }
  return null;
}

// force = test button, works while the toggle is off. chicken, meet egg
async function send({ to, subject, text, kind = 'notice', force = false }) {
  const settings = config();
  if (!settings.enabled && !force) throw new Error('email is switched off');
  const problem = unusable(settings);
  if (problem) throw new Error(problem);
  if (!validAddress(to)) throw new Error(`${to || 'that'} is not an email address`);

  let error = null;
  try {
    if (settings.transport === 'graph') {
      await sendGraph(to, subject, text, settings);
    } else {
      const message = buildMessage({
        from: settings.email_from,
        fromName: settings.email_from_name,
        to,
        subject,
        text
      });
      await sendSmtp(message, to, settings);
    }
  } catch (err) {
    error = err.message;
  }

  await emailLog.insert({
    kind, to: addressOnly(to).slice(0, 254), subject: oneLine(subject).slice(0, 255), transport: settings.transport,
    ok: error ? 0 : 1, error: error ? String(error).slice(0, 255) : null
  }).catch((err) => log.error('could not write the email log', err.message));

  if (error) throw new Error(error);
}

module.exports = { send, config, unusable, validAddress, addressOnly, buildMessage, sendSmtp };
