// @ts-check
// Runs the background jobs on their timers, one run of each at a time.
// Author: Tim Rice
// a tick that lands while the last run is still going is skipped, never queued. the skip is counted every time
// and warned about once per run, and a run still going past its job's limit gets one error. nothing is ever killed

const STUCK_FLOOR_MS = 15 * 60000;

/**
 * @typedef {object} JobSpec
 * @property {string} name
 * @property {number} every ms between runs
 * @property {() => unknown} run
 * @property {number} [firstDelay] ms before an extra first run, off the regular timer
 * @property {boolean} [runNow] run once straight away
 * @property {boolean} [unref] the regular timer doesn't keep the process alive
 * @property {number} [stuckAfter] ms a run may take before it is reported as stuck
 * @property {{ level?: 'error' | 'warn' | 'silent', message?: string }} [onError]
 */

/** @param {number} ms */
const ago = (ms) => (ms < 60000 ? `${Math.round(ms / 1000)}s` : `${Math.round(ms / 60000)}m`);

/**
 * @param {{ log: any, timers?: { setTimeout: Function, setInterval: Function, clearTimeout: Function, clearInterval: Function }, now?: () => number }} options
 */
function createScheduler({ log, timers = { setTimeout, setInterval, clearTimeout, clearInterval }, now = Date.now }) {
  /** @type {Map<string, any>} */
  const jobs = new Map();
  /** @type {Array<[string, any]>} */
  let handles = [];
  let started = false;

  /** @param {JobSpec} spec */
  function register(spec) {
    if (!spec || !spec.name || typeof spec.run !== 'function') throw new Error('a job needs a name and something to run');
    if (!(Number(spec.every) > 0)) throw new Error(`the ${spec.name} job needs a positive interval`);
    if (jobs.has(spec.name)) throw new Error(`there is already a job called ${spec.name}`);
    jobs.set(spec.name, {
      ...spec,
      stuckAfter: spec.stuckAfter || Math.max(3 * spec.every, STUCK_FLOOR_MS),
      onError: { level: 'error', message: `${spec.name} failed`, ...(spec.onError || {}) },
      running: false, startedAt: null, finishedAt: null, runs: 0, skipped: 0, failures: 0, lastError: null,
      skipWarned: false, stuckWarned: false
    });
  }

  /** @param {any} job */
  function fire(job) {
    if (job.running) {
      job.skipped += 1;
      const took = now() - job.startedAt;
      if (!job.skipWarned) {
        job.skipWarned = true;
        log.warn(`${job.name}: skipped a run, the previous one is still going after ${ago(took)}`);
      }
      if (!job.stuckWarned && took >= job.stuckAfter) {
        job.stuckWarned = true;
        log.error(`${job.name}: still running after ${ago(took)}, it may be stuck`);
      }
      return null;
    }
    job.running = true;
    job.startedAt = now();
    job.runs += 1;
    /** @param {any} err */
    const finished = (err) => {
      if (err) {
        job.failures += 1;
        job.lastError = err && err.message ? err.message : String(err);
        if (job.onError.level !== 'silent') log[job.onError.level](job.onError.message, job.lastError);
      } else {
        job.lastError = null;
      }
      job.running = false;
      job.finishedAt = now();
      job.skipWarned = false;
      job.stuckWarned = false;
    };
    let result;
    try {
      result = job.run();
    } catch (err) {
      finished(err);
      return null;
    }
    return Promise.resolve(result).then(() => finished(null), (err) => finished(err || new Error('the job failed')));
  }

  function start() {
    if (started) return;
    started = true;
    for (const job of jobs.values()) {
      if (job.runNow) fire(job);
      if (job.firstDelay !== undefined && job.firstDelay !== null) {
        const first = timers.setTimeout(() => fire(job), job.firstDelay);
        if (first && first.unref) first.unref();
        handles.push(['timeout', first]);
      }
      const every = timers.setInterval(() => fire(job), job.every);
      if (job.unref && every && every.unref) every.unref();
      handles.push(['interval', every]);
    }
  }

  function stop() {
    for (const [kind, handle] of handles) {
      if (kind === 'timeout') timers.clearTimeout(handle);
      else timers.clearInterval(handle);
    }
    handles = [];
    started = false;
  }

  /**
   * one run now, same guard as a tick. for tests and anything that wants a job done early
   * @param {string} name
   */
  function trigger(name) {
    const job = jobs.get(name);
    if (!job) throw new Error(`there is no job called ${name}`);
    return fire(job);
  }

  function status() {
    return [...jobs.values()].map((j) => ({
      name: j.name, every: j.every, running: j.running, runs: j.runs, skipped: j.skipped, failures: j.failures,
      lastError: j.lastError, startedAt: j.startedAt, finishedAt: j.finishedAt
    }));
  }

  const specs = () => [...jobs.values()].map((j) => ({
    name: j.name, every: j.every, firstDelay: j.firstDelay === undefined ? null : j.firstDelay, runNow: !!j.runNow, unref: !!j.unref,
    stuckAfter: j.stuckAfter, onError: j.onError
  }));

  return { register, start, stop, trigger, status, specs };
}

module.exports = { createScheduler, STUCK_FLOOR_MS };
