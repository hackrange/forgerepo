// Reads the environment once and hands back plain boring values.
// Author: Tim Rice

const fs = require('fs');
const path = require('path');

const dataDir = process.env.DATA_DIR || '/data';

function readCreds() {
  const file = path.join(dataDir, '.dbcreds.json');
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return null;
  }
}

// DB_HOST set = external db. the local creds file is ignored then, or a stale one
// fills in a wrong password and the error mentions neither. hours of fun
const externalDb = !!(process.env.DB_HOST || '').trim();
const creds = externalDb ? {} : (readCreds() || {});

// DB_SSL=rds uses mysql2's bundled amazon CA. off by default, local is a unix socket
function dbSsl() {
  const raw = String(process.env.DB_SSL || '').trim().toLowerCase();
  if (!raw || raw === '0' || raw === 'false' || raw === 'off' || raw === 'no') return null;
  if (raw === 'rds' || raw === 'amazon rds') return 'Amazon RDS';
  if (process.env.DB_SSL_CA) {
    return { ca: fs.readFileSync(process.env.DB_SSL_CA, 'utf8'), rejectUnauthorized: true };
  }
  // no CA named, still verified against the system store
  return { rejectUnauthorized: !['0', 'false', 'off', 'no'].includes(String(process.env.DB_SSL_VERIFY || '').toLowerCase()) };
}

function trustProxyValue() {
  const raw = (process.env.TRUST_PROXY || '1').trim();
  if (/^\d+$/.test(raw)) return parseInt(raw, 10);
  if (raw.toLowerCase() === 'false') return false;
  if (raw.toLowerCase() === 'true') return true;
  return raw;
}

function bool(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

module.exports = {
  port: parseInt(process.env.PORT || '4444', 10),
  bindAddress: process.env.BIND_ADDRESS || '0.0.0.0',
  dataDir,
  cacheDir: process.env.CACHE_DIR || path.join(dataDir, 'cache'),
  backupDir: process.env.BACKUP_DIR || path.join(dataDir, 'backups'),

  db: {
    socketPath: process.env.DB_SOCKET || creds.socketPath || '/run/mysqld/mysqld.sock',
    host: process.env.DB_HOST || '',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER || creds.user || 'npmrepo',
    password: process.env.DB_PASSWORD || creds.password || '',
    database: process.env.DB_NAME || creds.database || 'npmrepo',
    connectionLimit: parseInt(process.env.DB_POOL || '10', 10),
    ssl: dbSsl(),
    external: externalDb
  },

  // first admin account, only created when the users table is empty. blank means
  // a random one-time password is made and written to the log
  adminUser: process.env.ADMIN_USER || 'admin',
  adminPassword: process.env.ADMIN_PASSWORD || '',

  publicUrl: (process.env.PUBLIC_URL || '').replace(/\/+$/, ''),

  // must be a real number, a string "1" means "trust the host called 1"
  trustProxy: trustProxyValue(),
  secureCookies: bool(process.env.SECURE_COOKIES, false),
  sessionHours: parseInt(process.env.SESSION_HOURS || '12', 10),

  // upstream default. the portal can override it, and the portal wins
  upstreamRegistry: (process.env.UPSTREAM_REGISTRY || 'https://registry.npmjs.org').replace(/\/+$/, ''),
  upstreamToken: process.env.UPSTREAM_TOKEN || '',

  // bucket credentials. set here they win over the portal settings and never go near the database
  storage: {
    s3AccessKeyId: process.env.S3_ACCESS_KEY_ID || '',
    s3SecretAccessKey: process.env.S3_SECRET_ACCESS_KEY || '',
    azureAccountKey: process.env.AZURE_STORAGE_KEY || ''
  },

  // import body size. the portal gives it only to the routes that take a file (api/shared/json-body). ~300k rules at the default
  maxImportBytes: Math.max(1, parseInt(process.env.MAX_IMPORT_MB || '64', 10)) * 1024 * 1024,

  version: require('../package.json').version
};
