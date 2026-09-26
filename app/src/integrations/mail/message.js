// A mail message: addresses, headers that can't be injected into, and a body that can't end DATA early.
// Author: Tim Rice

const crypto = require('crypto');
const os = require('os');

// non-ascii headers get base64'd, no fussing
function encodeHeader(text) {
  const s = String(text || '');
  if (/^[\x20-\x7E]*$/.test(s)) return s;
  return `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}

// newline in a header = header injection. flatten to a space, a weird subject
// beats a digest that stops sending
function oneLine(text) {
  return String(text || '').replace(/[\r\n]+/g, ' ').trim();
}

function addressOnly(value) {
  const s = oneLine(value);
  const match = s.match(/<([^>]+)>/);
  return (match ? match[1] : s).trim();
}

//loose on purpose, catches typos. not trying to be RFC 5322
function validAddress(value) {
  const s = addressOnly(value);
  return /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(s) && s.length <= 254;
}

function wrap76(text) {
  return text.replace(/(.{1,76})/g, '$1\r\n');
}

// base64 body so a leading "." can't end DATA early. no dot stuffing
function buildMessage({ from, fromName, to, subject, text }) {
  const address = addressOnly(from);
  const sender = fromName ? `${encodeHeader(oneLine(fromName))} <${address}>` : address;
  const id = `${crypto.randomBytes(16).toString('hex')}@${address.split('@')[1] || os.hostname()}`;
  const headers = [
    `From: ${sender}`,
    `To: ${addressOnly(to)}`,
    `Subject: ${encodeHeader(oneLine(subject))}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${id}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    'Auto-Submitted: auto-generated'
  ];
  const body = wrap76(Buffer.from(String(text), 'utf8').toString('base64'));
  return `${headers.join('\r\n')}\r\n\r\n${body}`;
}

module.exports = { oneLine, addressOnly, validAddress, buildMessage };
