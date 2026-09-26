// How bad an OS advisory is, from what the distribution says first and the CVSS vector second.
// Author: Tim Rice
//
// distributions rate their own builds. Debian calls plenty of scary CVSS scores unimportant because the code path is
// not built in, and an image blocked for those would block every Debian image there is. so the distro's word wins
// when it gave one, and the vector only fills in when it did not

const ORDER = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'];

function worst(list) {
  return list.filter((s) => ORDER.includes(s)).sort((a, b) => ORDER.indexOf(b) - ORDER.indexOf(a))[0] || null;
}

// CVSS 3.x base score, from the spec's own formulas
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: [0.85, 0.85], L: [0.62, 0.68], H: [0.27, 0.5] },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 }
};

function roundUp(x) {
  const n = Math.round(x * 100000);
  return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
}

function cvss3Score(vector) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vector || '').trim());
  if (!m) return null;
  const v = {};
  for (const part of m[1].split('/')) {
    const [k, val] = part.split(':');
    if (k && val !== undefined && !(k in v)) v[k] = val;
  }
  const changed = v.S === 'C';
  if (v.S !== 'U' && v.S !== 'C') return null;
  const av = W.AV[v.AV];
  const ac = W.AC[v.AC];
  const pr = W.PR[v.PR] && W.PR[v.PR][changed ? 1 : 0];
  const ui = W.UI[v.UI];
  const c = W.CIA[v.C];
  const i = W.CIA[v.I];
  const a = W.CIA[v.A];
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploit = 8.22 * av * ac * pr * ui;
  return roundUp(Math.min(changed ? 1.08 * (impact + exploit) : impact + exploit, 10));
}

function rating(score) {
  if (score === null || score === undefined || !(score > 0)) return null;
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MODERATE';
  return 'LOW';
}

const DEBIAN = { unimportant: 'LOW', low: 'LOW', medium: 'MODERATE', high: 'HIGH' };
const UBUNTU = { negligible: 'LOW', low: 'LOW', medium: 'MODERATE', high: 'HIGH', critical: 'CRITICAL' };
// Red Hat style titles: "Important: openssl security update"
const REDHAT = { low: 'LOW', moderate: 'MODERATE', important: 'HIGH', critical: 'CRITICAL' };

/** @returns {string} CRITICAL, HIGH, MODERATE, LOW or unrated */
function ofRecord(record) {
  if (!record || typeof record !== 'object') return 'unrated';
  const dbs = record.database_specific && typeof record.database_specific === 'object' ? record.database_specific : {};
  const said = String(dbs.severity || '').toUpperCase();
  if (ORDER.includes(said)) return said;

  const vendor = [];
  for (const affected of Array.isArray(record.affected) ? record.affected : []) {
    const eco = String((affected && affected.package && affected.package.ecosystem) || '');
    const spec = (affected && affected.ecosystem_specific) || {};
    if (/^Debian/.test(eco) && DEBIAN[String(spec.urgency || '').toLowerCase()]) vendor.push(DEBIAN[String(spec.urgency).toLowerCase()]);
  }
  const severities = Array.isArray(record.severity) ? record.severity : [];
  for (const s of severities) {
    if (s && s.type === 'Ubuntu' && UBUNTU[String(s.score || '').toLowerCase()]) vendor.push(UBUNTU[String(s.score).toLowerCase()]);
  }
  const title = /^(Low|Moderate|Important|Critical):/.exec(String(record.summary || ''));
  if (title && /^(RLSA|ALSA|RHSA)-/.test(String(record.id || ''))) vendor.push(REDHAT[title[1].toLowerCase()]);
  const fromVendor = worst(vendor);
  if (fromVendor) return fromVendor;

  const scores = severities.filter((s) => s && s.type === 'CVSS_V3').map((s) => rating(cvss3Score(s.score)));
  return worst(scores) || 'unrated';
}

module.exports = { ofRecord, cvss3Score, rating, worst, ORDER };
