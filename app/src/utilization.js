// Utilization: CPU, memory, disk and network, live and over time.
// Author: Tim Rice
// sampled every 5s. the last hour stays in memory for the gauges, a row a minute goes to the db
// (kept 2 days, the today view), averaged into 2 minutes (kept a month) and 10 minutes (kept a year). host numbers come from /proc,
// ForgeRepo's own from its cgroup, so no docker socket is ever needed (that would be a gaping hole)

const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const config = require('./config');
const db = require('./db');
const log = require('./logger');

const PERIOD_MS = 5000;
const LIVE_POINTS = 720;
const DAY = 86400000;
// where each resolution lives and for how long. anything past a year is purged
const TIERS = [
  { table: 'utilization_minute', seconds: 60, keepDays: 2 },
  { table: 'utilization_2min', seconds: 120, keepDays: 31 },
  { table: 'utilization_10min', seconds: 600, keepDays: 365 }
];
// a day at one minute is 1440 points, so that's the most any chart asks for
const MAX_POINTS = 1440;
const MAX_SPAN_MS = 366 * DAY;

const NODE = String(process.env.NODE_NAME || os.hostname()).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64) || 'node';

// ---------------------------------------------------------------- readers, each one small and testable

// first line of /proc/stat: cpu user nice system idle iowait irq softirq steal ...
function parseProcStat(text) {
  const line = String(text).split('\n').find((l) => l.startsWith('cpu '));
  if (!line) return null;
  const n = line.trim().split(/\s+/).slice(1, 9).map(Number);
  if (n.length < 4 || n.some((v) => !Number.isFinite(v))) return null;
  const idle = n[3] + (n[4] || 0);
  return { total: n.reduce((a, b) => a + b, 0), idle };
}

function cpuPercent(prev, cur) {
  if (!prev || !cur) return null;
  const total = cur.total - prev.total;
  if (total <= 0) return null;
  return Math.max(0, Math.min(100, (100 * (total - (cur.idle - prev.idle))) / total));
}

function parseMeminfo(text) {
  const get = (key) => {
    const m = new RegExp(`^${key}:\\s+(\\d+)\\s*kB`, 'm').exec(String(text));
    return m ? Number(m[1]) * 1024 : null;
  };
  const total = get('MemTotal');
  const available = get('MemAvailable');
  if (total === null || available === null) return null;
  return { total, used: Math.max(0, total - available) };
}

// sums every interface but loopback: the container's own traffic
function parseNetDev(text) {
  let rx = 0;
  let tx = 0;
  for (const line of String(text).split('\n').slice(2)) {
    const [name, rest] = line.split(':');
    if (!rest || name.trim() === 'lo') continue;
    const f = rest.trim().split(/\s+/).map(Number);
    if (f.length < 9) continue;
    rx += f[0];
    tx += f[8];
  }
  return { rx, tx };
}

// like docker stats: current minus inactive file cache, which the kernel would hand back anyway
function containerMemory(current, stat) {
  // a missing file is "don't know", not zero, so the caller falls back to the next reader
  const raw = String(current === null || current === undefined ? '' : current).trim();
  if (!/^\d+$/.test(raw)) return null;
  const cur = Number(raw);
  const m = /^inactive_file\s+(\d+)/m.exec(String(stat || ''));
  return Math.max(0, cur - (m ? Number(m[1]) : 0));
}

function readText(path) {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch (err) {
    return null;
  }
}

function appCpuMicros() {
  const v2 = readText('/sys/fs/cgroup/cpu.stat');
  const m = v2 && /^usage_usec\s+(\d+)/m.exec(v2);
  if (m) return Number(m[1]);
  const v1 = readText('/sys/fs/cgroup/cpuacct/cpuacct.usage');
  if (v1 && /^\d+/.test(v1.trim())) return Number(v1.trim()) / 1000;
  const u = process.cpuUsage();
  return u.user + u.system;
}

function appMemory() {
  const v2 = containerMemory(readText('/sys/fs/cgroup/memory.current'), readText('/sys/fs/cgroup/memory.stat'));
  if (v2 !== null) return v2;
  const v1 = containerMemory(readText('/sys/fs/cgroup/memory/memory.usage_in_bytes'), readText('/sys/fs/cgroup/memory/memory.stat'));
  return v1 !== null ? v1 : process.memoryUsage().rss;
}

async function disk() {
  try {
    const s = await fsp.statfs(config.cacheDir);
    return { total: s.blocks * s.bsize, used: (s.blocks - s.bfree) * s.bsize };
  } catch (err) {
    return { total: 0, used: 0 };
  }
}

// ---------------------------------------------------------------- the sampler

const live = [];
let minutePoints = [];
let prev = null;
let breakdown = { cache: null, database: null, at: 0 };

async function refreshBreakdown() {
  try {
    const cache = await db.one('SELECT COALESCE(SUM(size), 0) AS n FROM blobs');
    const dbSize = await db.one(
      'SELECT COALESCE(SUM(data_length + index_length), 0) AS n FROM information_schema.tables WHERE table_schema = DATABASE()'
    );
    breakdown = { cache: Number(cache.n), database: Number(dbSize.n), at: Date.now() };
  } catch (err) {
    // not worth shouting about, the gauge still works
  }
}

async function sample() {
  const t = Date.now();
  const cpu = parseProcStat(readText('/proc/stat') || '');
  const appMicros = appCpuMicros();
  const net = parseNetDev(readText('/proc/net/dev') || '');
  const mem = parseMeminfo(readText('/proc/meminfo') || '') || { total: os.totalmem(), used: os.totalmem() - os.freemem() };
  const d = await disk();
  const cpus = os.cpus().length || 1;

  if (prev) {
    const secs = (t - prev.t) / 1000;
    if (secs > 0) {
      const appCores = Math.max(0, (appMicros - prev.appMicros) / 1e6 / secs);
      const point = {
        t,
        hostCpu: round(cpuPercent(prev.cpu, cpu)),
        appCpu: round(Math.min(100, (100 * appCores) / cpus)),
        appCores: round(appCores),
        hostMemUsed: mem.used,
        hostMemTotal: mem.total,
        appMem: appMemory(),
        diskUsed: d.used,
        diskTotal: d.total,
        rxBps: Math.max(0, Math.round((net.rx - prev.net.rx) / secs)),
        txBps: Math.max(0, Math.round((net.tx - prev.net.tx) / secs))
      };
      live.push(point);
      if (live.length > LIVE_POINTS) live.splice(0, live.length - LIVE_POINTS);
      const minute = Math.floor(t / 60000);
      if (minutePoints.length && Math.floor(minutePoints[0].t / 60000) !== minute) {
        const done = minutePoints;
        minutePoints = [];
        await flushMinute(done);
      }
      minutePoints.push(point);
    }
  }
  prev = { t, cpu, appMicros, net };
}

const round = (v) => (v === null || v === undefined ? null : Math.round(v * 100) / 100);
const avg = (list, key) => {
  const vals = list.map((p) => p[key]).filter((v) => v !== null && Number.isFinite(v));
  return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : 0;
};
const peak = (list, key) => Math.max(0, ...list.map((p) => p[key]).filter((v) => Number.isFinite(v)));

async function flushMinute(points) {
  if (!points.length) return;
  const ts = Math.floor(points[0].t / 60000) * 60;
  try {
    await db.query(
      `INSERT INTO utilization_minute
         (node, ts, host_cpu, host_cpu_max, app_cpu, host_mem_used, host_mem_total, app_mem,
          disk_used, disk_total, net_rx_bps, net_tx_bps, net_rx_max, net_tx_max)
       VALUES (?, FROM_UNIXTIME(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE host_cpu = VALUES(host_cpu), host_cpu_max = VALUES(host_cpu_max), app_cpu = VALUES(app_cpu),
         host_mem_used = VALUES(host_mem_used), host_mem_total = VALUES(host_mem_total), app_mem = VALUES(app_mem),
         disk_used = VALUES(disk_used), disk_total = VALUES(disk_total), net_rx_bps = VALUES(net_rx_bps),
         net_tx_bps = VALUES(net_tx_bps), net_rx_max = VALUES(net_rx_max), net_tx_max = VALUES(net_tx_max)`,
      [
        NODE, ts, round(avg(points, 'hostCpu')), round(peak(points, 'hostCpu')), round(avg(points, 'appCpu')),
        Math.round(avg(points, 'hostMemUsed')), Math.round(peak(points, 'hostMemTotal')), Math.round(avg(points, 'appMem')),
        Math.round(avg(points, 'diskUsed')), Math.round(peak(points, 'diskTotal')),
        Math.round(avg(points, 'rxBps')), Math.round(avg(points, 'txBps')),
        Math.round(peak(points, 'rxBps')), Math.round(peak(points, 'txBps'))
      ]
    );
  } catch (err) {
    log.warn('could not save a utilization sample', err.message);
  }
}

const COLS = 'host_cpu, host_cpu_max, app_cpu, host_mem_used, host_mem_total, app_mem, disk_used, disk_total, net_rx_bps, net_tx_bps, net_rx_max, net_tx_max';

// the last few hours of minutes averaged into the 2 and 10 minute tables, then everything past keeping goes.
// reruns over the same window just rewrite the same rows, so a missed run catches up
async function rollup() {
  try {
    for (const tier of TIERS.slice(1)) {
      await db.query(
        `INSERT INTO ${tier.table} (node, ts, ${COLS})
         SELECT node, FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(ts) / ${tier.seconds}) * ${tier.seconds}) AS slot,
                AVG(host_cpu), MAX(host_cpu_max), AVG(app_cpu), AVG(host_mem_used), MAX(host_mem_total), AVG(app_mem),
                AVG(disk_used), MAX(disk_total), AVG(net_rx_bps), AVG(net_tx_bps), MAX(net_rx_max), MAX(net_tx_max)
           FROM utilization_minute WHERE ts >= DATE_SUB(NOW(), INTERVAL 3 HOUR)
          GROUP BY node, slot
         ON DUPLICATE KEY UPDATE host_cpu = VALUES(host_cpu), host_cpu_max = VALUES(host_cpu_max), app_cpu = VALUES(app_cpu),
           host_mem_used = VALUES(host_mem_used), host_mem_total = VALUES(host_mem_total), app_mem = VALUES(app_mem),
           disk_used = VALUES(disk_used), disk_total = VALUES(disk_total), net_rx_bps = VALUES(net_rx_bps),
           net_tx_bps = VALUES(net_tx_bps), net_rx_max = VALUES(net_rx_max), net_tx_max = VALUES(net_tx_max)`
      );
    }
    for (const tier of TIERS) {
      await db.query(`DELETE FROM ${tier.table} WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)`, [tier.keepDays]);
    }
  } catch (err) {
    log.warn('utilization rollup failed', err.message);
  }
}

// ---------------------------------------------------------------- what the api hands out

function limits() {
  const max = (readText('/sys/fs/cgroup/cpu.max') || '').trim().split(/\s+/);
  const quota = max[0] && max[0] !== 'max' ? Number(max[0]) / Number(max[1] || 100000) : null;
  const memMax = (readText('/sys/fs/cgroup/memory.max') || '').trim();
  return {
    hostCpus: os.cpus().length,
    cpuLimitCores: Number.isFinite(quota) ? quota : null,
    memLimit: /^\d+$/.test(memMax) ? Number(memMax) : null
  };
}

function current(since) {
  const after = Number(since) || 0;
  return {
    node: NODE,
    periodMs: PERIOD_MS,
    now: live.length ? live[live.length - 1] : null,
    points: live.filter((p) => p.t > after),
    breakdown,
    limits: limits()
  };
}

// finest table that still covers the start of the range: today at 1 minute, up to a month at 2,
// beyond that at 10. only widened further if a range would draw more than MAX_POINTS
function plan(fromMs, toMs, now = Date.now()) {
  const span = toMs - fromMs;
  const age = now - fromMs;
  const tier = TIERS.find((t) => span <= t.keepDays * DAY && age <= t.keepDays * DAY + DAY) || TIERS[TIERS.length - 1];
  const base = tier.seconds;
  const bucket = Math.max(base, Math.ceil(span / 1000 / MAX_POINTS / base) * base);
  return { source: tier.table.replace('utilization_', ''), table: tier.table, bucket };
}

async function history(fromMs, toMs) {
  const { source, table, bucket } = plan(fromMs, toMs);
  const rows = await db.query(
    `SELECT FLOOR(UNIX_TIMESTAMP(ts) / ?) * ? AS b,
            AVG(host_cpu) AS host_cpu, MAX(host_cpu_max) AS host_cpu_max, AVG(app_cpu) AS app_cpu,
            AVG(host_mem_used) AS host_mem_used, MAX(host_mem_total) AS host_mem_total, AVG(app_mem) AS app_mem,
            AVG(disk_used) AS disk_used, MAX(disk_total) AS disk_total,
            AVG(net_rx_bps) AS net_rx_bps, AVG(net_tx_bps) AS net_tx_bps, MAX(net_rx_max) AS net_rx_max, MAX(net_tx_max) AS net_tx_max
       FROM ${table}
      WHERE node = ? AND ts >= FROM_UNIXTIME(?) AND ts < FROM_UNIXTIME(?)
      GROUP BY b ORDER BY b`,
    [bucket, bucket, NODE, Math.floor(fromMs / 1000), Math.ceil(toMs / 1000)]
  );
  const num = (v) => (v === null ? null : Math.round(Number(v) * 100) / 100);
  return {
    node: NODE,
    source,
    bucketSeconds: bucket,
    from: fromMs,
    to: toMs,
    points: rows.map((r) => ({
      t: Number(r.b) * 1000,
      hostCpu: num(r.host_cpu), hostCpuMax: num(r.host_cpu_max), appCpu: num(r.app_cpu),
      hostMemUsed: num(r.host_mem_used), hostMemTotal: num(r.host_mem_total), appMem: num(r.app_mem),
      diskUsed: num(r.disk_used), diskTotal: num(r.disk_total),
      rxBps: num(r.net_rx_bps), txBps: num(r.net_tx_bps), rxMax: num(r.net_rx_max), txMax: num(r.net_tx_max)
    }))
  };
}

module.exports = {
  NODE, PERIOD_MS, MAX_SPAN_MS, TIERS, sample, refreshBreakdown, rollup, current, history, plan,
  parseProcStat, cpuPercent, parseMeminfo, parseNetDev, containerMemory
};
