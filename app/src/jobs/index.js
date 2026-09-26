// Every background job and when it runs. one place to see what the box does on its own.
// Author: Tim Rice
// the timings are the ones the jobs always had. unref = the timer doesn't hold the process open on shutdown

const db = require('../db');
const log = require('../logger');
const auth = require('../security/auth');
const ipacl = require('../security/network/ipacl');
const sso = require('../security/sso');
const ghmeta = require('../security/network/github-ranges');
const digest = require('../integrations/mail/digest');
const cvescan = require('../cvescan');
const intel = require('../integrations/intel');
const events = require('../integrations/events');
const utilization = require('../utilization');
const licenses = require('../policy/licenses');
const waivers = require('../policy/waivers');
const provenance = require('../policy/provenance');
const malware = require('../malware');
const { createScheduler } = require('./scheduler');
const { cleanup } = require('./retention');

const MINUTE = 60000;
const HOUR = 60 * MINUTE;

// with a bucket in use: send new files up, then keep the local copies inside their limit. nothing on local disk
const inBucketMode = () => ['s3', 'azure'].includes(db.settings.get('storage_backend'));
async function bucketUpload() {
  if (inBucketMode()) await require('../storage/bucket').uploadWaiting();
}
async function storageCache() {
  if (inBucketMode()) await require('../storage/bucket').evict(db.settings.getInt('storage_cache_mb', 20480) * 1048576);
}

async function sweepSessions() {
  await auth.sweepSessions();
  await ipacl.sweepGrants();
  await auth.sweepRateLimits();
  await sso.sweepStates();
}

function definitions() {
  return [
    // a change another node made is picked up in about as long as a kill takes, the full reload is the safety net
    { name: 'settings poll', every: 5000, unref: true, run: () => db.settings.poll(), onError: { level: 'silent' } },
    { name: 'settings reload', every: 30000, run: () => db.settings.load(true), onError: { level: 'silent' } },

    // cpu, memory, disk and network every few seconds, for the Utilization page
    { name: 'utilization sample', every: utilization.PERIOD_MS, runNow: true, unref: true, run: utilization.sample, onError: { level: 'warn', message: 'utilization sample failed' } },
    { name: 'utilization breakdown', every: 5 * MINUTE, runNow: true, unref: true, run: utilization.refreshBreakdown },
    { name: 'utilization rollup', every: 10 * MINUTE, firstDelay: MINUTE, unref: true, run: utilization.rollup },

    // a first boot can have hours of licenses to read, that is not stuck
    { name: 'license backfill', every: 10 * MINUTE, firstDelay: MINUTE, unref: true, stuckAfter: 12 * HOUR, run: licenses.backfill, onError: { level: 'silent' } },
    { name: 'waiver sweep', every: MINUTE, unref: true, run: waivers.sweep, onError: { message: 'waiver sweep failed' } },
    { name: 'event delivery', every: events.TICK_MS, unref: true, run: events.tick, onError: { message: 'event worker failed' } },
    { name: 'event outbox cleanup', every: HOUR, unref: true, run: events.sweep, onError: { message: 'event outbox cleanup failed' } },
    // files held while a malware scanner was down get scanned as soon as it answers again
    { name: 'malware catch up', every: 30000, firstDelay: MINUTE, unref: true, run: malware.recover, onError: { level: 'silent' } },
    { name: 'provenance backfill', every: 2 * MINUTE, firstDelay: MINUTE, unref: true, stuckAfter: HOUR, run: provenance.backfill, onError: { message: 'provenance backfill failed' } },

    { name: 'session sweep', every: 10 * MINUTE, run: sweepSessions, onError: { message: 'session sweep failed' } },
    { name: 'log cleanup', every: HOUR, run: cleanup, onError: { message: 'log cleanup failed' } },
    // not on boot, a restart loop shouldn't re-mail everyone
    { name: 'digest', every: HOUR, firstDelay: 10 * MINUTE, run: digest.run, onError: { message: 'the digest failed' } },
    // not on boot either, a restart loop would hammer the feed
    { name: 'vulnerability scan check', every: HOUR, firstDelay: 5 * MINUTE, run: cvescan.maybeRun, onError: { message: 'scan check failed' } },
    // images a node died scanning, or that failed a while ago. the pull already queued the rest
    { name: 'image scans', every: 10 * MINUTE, firstDelay: 3 * MINUTE, unref: true, run: () => require('../images/scanner').resume(), onError: { level: 'warn', message: 'resuming image scans failed' } },
    // CISA KEV and FIRST EPSS, daily by default. a failed fetch is noted on the feed and tried again next hour
    { name: 'vulnerability intel', every: HOUR, firstDelay: 7 * MINUTE, unref: true, stuckAfter: 2 * HOUR, run: intel.maybeSync, onError: { level: 'warn', message: 'the vulnerability intel refresh failed' } },
    // github ranges DO run soon after boot, an empty feed blocks the builds it should allow
    { name: 'github ranges', every: HOUR, firstDelay: 20000, run: ghmeta.maybeSync, onError: { message: 'the github fetch failed' } },
    // a first upload of a big cache takes hours, that is not stuck
    { name: 'bucket upload', every: MINUTE, firstDelay: MINUTE, unref: true, stuckAfter: 12 * HOUR, run: bucketUpload, onError: { message: 'bucket upload failed' } },
    { name: 'storage cache', every: 10 * MINUTE, firstDelay: 2 * MINUTE, unref: true, run: storageCache, onError: { message: 'storage cache eviction failed' } },
    // any-version allow rules that still have nothing cached, loaded late so a box without an upstream never touches it
    // auto approve picks up requests that were waiting on a scan, cooling off or an outage
    { name: 'auto approve', every: 5 * MINUTE, firstDelay: 2 * MINUTE, unref: true, stuckAfter: 2 * HOUR, run: () => require('../services/auto-approve').sweep(), onError: { level: 'warn', message: 'auto approve failed' } },
    { name: 'current versions', every: HOUR, firstDelay: 9 * MINUTE, unref: true, run: () => require('../warm-latest').sweep(), onError: { level: 'warn', message: 'caching current versions for any-version rules failed' } }
  ];
}

let scheduler = null;

function start() {
  if (scheduler) return scheduler;
  scheduler = createScheduler({ log });
  for (const job of definitions()) scheduler.register(job);
  scheduler.start();
  return scheduler;
}

function stop() {
  if (scheduler) scheduler.stop();
  scheduler = null;
}

function status() {
  return scheduler ? scheduler.status() : [];
}

module.exports = { definitions, start, stop, status };
