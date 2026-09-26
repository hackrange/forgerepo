// How an event is written for each receiver: CEF, RFC 5424 syslog, Splunk HEC, and the webhook signature.
// Author: Tim Rice

const crypto = require('crypto');
const os = require('os');

// how loud each event is: syslog severity (0 worst) and CEF severity (10 worst)
const LEVEL = {
  'malware.detected': [2, 10], 'artifact.integrity_changed': [2, 9], 'vulnerability.discovered': [4, 7],
  'package.quarantined': [4, 6], 'policy.violation': [4, 6], 'package.blocked': [4, 5], 'waiver.expired': [5, 4],
  'waiver.created': [5, 4], 'package.released': [5, 4], 'package.approved': [5, 3], 'package.requested': [6, 2],
  'vulnerability.remediated': [6, 2], 'package.cached': [6, 1], 'integration.test': [6, 1]
};

function cefHeader(v) {
  return String(v === null || v === undefined ? '' : v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}

function cefValue(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n|\r/g, '\\n');
}

function toCef(e, version) {
  const level = (LEVEL[e.event_type] || [6, 3])[1];
  const ext = [
    ['rt', Date.parse(e.timestamp)], ['externalId', e.id], ['act', e.action], ['reason', e.reason], ['msg', e.reason],
    ['suser', e.user], ['src', e.source_ip], ['fname', e.filename || e.package], ['fileHash', e.artifact_hash],
    ['cs1Label', 'ecosystem'], ['cs1', e.ecosystem], ['cs2Label', 'package'], ['cs2', e.package],
    ['cs3Label', 'version'], ['cs3', e.version], ['cs4Label', 'application'], ['cs4', e.application],
    ['cs5Label', 'environment'], ['cs5', e.environment], ['cs6Label', 'cve'], ['cs6', e.cve],
    ['flexString1Label', 'token'], ['flexString1', e.token], ['flexString2Label', 'policy'], ['flexString2', e.policy]
  ].filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${cefValue(v)}`).join(' ');
  return `CEF:0|ForgeRepo|ForgeRepo|${cefHeader(version)}|${cefHeader(e.event_type)}|${cefHeader(e.event_type.replace(/[._]/g, ' '))}|${level}|${ext}`;
}

// RFC 5424, facility local0
function toSyslog(e, format, version) {
  const pri = 16 * 8 + (LEVEL[e.event_type] || [6])[0];
  const host = String(os.hostname() || '-').replace(/[^\x21-\x7e]/g, '').slice(0, 255) || '-';
  const msgid = e.event_type.replace(/[^\x21-\x7e]/g, '').slice(0, 32);
  const msg = format === 'cef' ? toCef(e, version) : JSON.stringify(e);
  return `<${pri}>1 ${e.timestamp} ${host} forgerepo - ${msgid} - ${msg}`;
}

function toHec(e) {
  return JSON.stringify({
    time: Date.parse(e.timestamp) / 1000, host: os.hostname(), source: 'forgerepo', sourcetype: 'forgerepo:event', event: e
  });
}

// the receiver can check it came from here and wasn't replayed: HMAC over "timestamp.body"
function signature(secret, timestamp, body) {
  return `sha256=${crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

module.exports = { LEVEL, toCef, toSyslog, toHec, signature };
