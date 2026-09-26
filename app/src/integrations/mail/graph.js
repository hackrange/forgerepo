// Sending through the Microsoft 365 Graph api, with an app token cached till nearly expired.
// Author: Tim Rice

const https = require('https');
const { oneLine, addressOnly } = require('./message');

const GRAPH_TIMEOUT_MS = 30000;

let graphToken = null;

function postJson(url, body, headers, timeout) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request(
      {
        // separate hostname/port, or node resolves "thing:443" as a name
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        method: 'POST',
        headers: { 'content-length': Buffer.byteLength(payload), ...headers }
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          if (text.length < 64000) text += c;
        });
        res.on('end', () => resolve({ status: res.statusCode, text }));
      }
    );
    req.on('error', (err) => reject(new Error(err.message)));
    req.setTimeout(timeout, () => req.destroy(new Error('microsoft did not answer in time')));
    req.end(payload);
  });
}

// app token, cached till nearly expired
async function graphAccessToken(settings) {
  const key = `${settings.graph_tenant}|${settings.graph_client_id}`;
  if (graphToken && graphToken.key === key && graphToken.expires > Date.now() + 60000) {
    return graphToken.value;
  }
  const form = new URLSearchParams({
    client_id: settings.graph_client_id,
    client_secret: settings.graph_client_secret,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials'
  }).toString();

  const res = await postJson(
    `https://login.microsoftonline.com/${encodeURIComponent(settings.graph_tenant)}/oauth2/v2.0/token`,
    form,
    { 'content-type': 'application/x-www-form-urlencoded' },
    GRAPH_TIMEOUT_MS
  );
  let parsed;
  try {
    parsed = JSON.parse(res.text);
  } catch (err) {
    throw new Error('microsoft answered with something that is not json');
  }
  if (res.status !== 200 || !parsed.access_token) {
    throw new Error(`microsoft would not issue a token: ${parsed.error_description || parsed.error || res.status}`);
  }
  graphToken = {
    key,
    value: parsed.access_token,
    expires: Date.now() + (Number(parsed.expires_in) || 3600) * 1000
  };
  return graphToken.value;
}

async function sendGraph(to, subject, text, settings) {
  if (!settings.graph_tenant || !settings.graph_client_id || !settings.graph_client_secret) {
    throw new Error('the microsoft 365 details are not filled in');
  }
  const mailbox = addressOnly(settings.graph_sender || settings.email_from);
  if (!mailbox) throw new Error('no mailbox is set to send from');

  const token = await graphAccessToken(settings);
  const res = await postJson(
    `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(mailbox)}/sendMail`,
    {
      message: {
        subject: oneLine(subject),
        body: { contentType: 'Text', content: String(text) },
        toRecipients: [{ emailAddress: { address: addressOnly(to) } }]
      },
      saveToSentItems: false
    },
    { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    GRAPH_TIMEOUT_MS
  );

  if (res.status === 202) return;
  // stale token, drop it
  if (res.status === 401) graphToken = null;
  let detail = res.text;
  try {
    const parsed = JSON.parse(res.text);
    detail = (parsed.error && (parsed.error.message || parsed.error.code)) || detail;
  } catch (err) {
    // not json, raw body it is
  }
  throw new Error(`microsoft would not send it (${res.status}): ${String(detail).slice(0, 200)}`);
}

module.exports = { sendGraph };
