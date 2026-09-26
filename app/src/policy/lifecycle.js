// Lifecycle: quarantine, development, test, approved, production, blocked. a stage is metadata on one exact version,
// the bytes never move or get copied. with enforcement on, blocked is refused to everyone and a token in a production
// environment only gets versions promoted to production. off, the stages are only ever information
// Author: Tim Rice

const db = require('../db');
const repo = require('../db/repositories/lifecycle');

const STAGES = ['quarantine', 'development', 'test', 'approved', 'production', 'blocked'];
const CACHE_MS = 5000;

let cache = null;
let cachedAt = 0;

function invalidate() {
  cache = null;
}

function enforcing() {
  return db.settings.getBool('lifecycle_enforce');
}

const key = (eco, name, version) => `${eco}\n${name}\n${version}`;

async function loaded() {
  if (cache && Date.now() - cachedAt < CACHE_MS) return cache;
  const [rows, envs] = await Promise.all([repo.enforced(), require('../db/repositories/labels').names('environments')]);
  cache = {
    stages: new Map(rows.map((r) => [key(r.ecosystem, r.package_name, r.version), r.stage])),
    production: new Set(envs.filter((e) => Number(e.production)).map((e) => Number(e.id)))
  };
  cachedAt = Date.now();
  return cache;
}

// null = the stage has nothing against it. only ever asked with enforcement on
async function refusal(ecosystem, name, version, scope) {
  if (!version) return null;
  const { stages, production } = await loaded();
  const stage = stages.get(key(ecosystem, name, version)) || null;
  if (stage === 'blocked') return `${name} ${version} is at the blocked stage of its lifecycle`;
  const env = scope ? Number(scope.env) || 0 : 0;
  if (env && production.has(env) && stage !== 'production') {
    return `${name} ${version} is ${stage ? `at the ${stage} stage` : 'not promoted'}, and a production environment only gets versions promoted to production`;
  }
  return null;
}

// only the blocked stage, for a digest reached through a tag that already answered everything else
async function blocked(ecosystem, name, version) {
  if (!version || !enforcing()) return null;
  const { stages } = await loaded();
  return stages.get(key(ecosystem, name, version)) === 'blocked' ? `${name} ${version} is at the blocked stage of its lifecycle` : null;
}

module.exports = { STAGES, enforcing, refusal, blocked, invalidate };
