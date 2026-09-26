// Typosquatting. names that imitate a package everyone uses, lodahs for lodash, reqeusts for requests.
// Author: Tim Rice
// a name that is itself well known, pinned by an allow rule, or dismissed by a person is never flagged.
// what this registry serves a lot is something worth imitating, but being served a lot never makes a name legit

const db = require('../db');
const auth = require('../security/auth');
const log = require('../logger');
const rulesRepo = require('../db/repositories/rules');
const findings = require('../db/repositories/typosquats');
const packagesRepo = require('../db/repositories/packages');
const pypiFiles = require('../db/repositories/pypi-files');

const MODES = ['off', 'warn', 'block'];
const CACHE_MS = 60000;
const MEMO_MAX = 5000;
const LOCAL_TOP = 500;
const LOCAL_MIN_HITS = 20;

// the names people actually reach for, and so the names worth imitating
const BUILTIN = {
  npm: [
    'react', 'react-dom', 'react-native', 'react-router', 'react-router-dom', 'react-redux', 'preact', 'lodash', 'lodash.merge',
    'lodash.get', 'underscore', 'express', 'koa', '@koa/router', 'fastify', 'hapi', '@hapi/hapi', 'restify', 'connect', 'axios',
    'node-fetch', 'cross-fetch', 'isomorphic-fetch', 'got', 'superagent', 'request', 'request-promise', 'chalk', 'colors',
    'commander', 'yargs', 'minimist', 'debug', 'moment', 'dayjs', 'date-fns', 'luxon', 'uuid', 'nanoid', 'shortid', 'async',
    'bluebird', 'rxjs', 'jquery', 'vue', 'nuxt', 'svelte', 'angular', '@angular/core', 'next', 'gatsby', 'lit', 'redux',
    '@reduxjs/toolkit', 'mobx', 'zustand', 'immer', 'classnames', 'prop-types', 'styled-components', '@emotion/react',
    'tailwindcss', 'postcss', 'autoprefixer', 'sass', 'node-sass', 'less', 'bootstrap', '@mui/material', 'antd', 'd3', 'three',
    'chart.js', 'ramda', 'immutable', 'validator', 'joi', 'yup', 'zod', 'ajv', 'jsonwebtoken', 'jose', 'bcrypt', 'bcryptjs',
    'passport', 'helmet', 'cors', 'body-parser', 'cookie-parser', 'express-session', 'morgan', 'multer', 'compression',
    'serve-static', 'nodemailer', 'winston', 'pino', 'bunyan', 'ora', 'inquirer', 'prompts', 'execa', 'shelljs', 'cross-env',
    'concurrently', 'nodemon', 'pm2', 'dotenv', 'dotenv-expand', 'config', 'nconf', 'handlebars', 'ejs', 'pug', 'mustache',
    'marked', 'markdown-it', 'highlight.js', 'prismjs', 'qs', 'path-to-regexp', 'ms', 'bytes', 'mime', 'mime-types',
    'iconv-lite', 'core-js', 'regenerator-runtime', 'tslib', 'typescript', 'ts-node', '@types/node', '@types/react',
    'babel-core', '@babel/core', '@babel/preset-env', 'babel-loader', 'webpack', 'webpack-cli', 'webpack-dev-server', 'esbuild',
    'vite', 'rollup', 'parcel', 'terser', 'uglify-js', 'css-loader', 'style-loader', 'file-loader', 'html-webpack-plugin',
    'eslint', 'prettier', 'jest', 'mocha', 'chai', 'sinon', 'karma', 'jasmine', 'cypress', 'puppeteer', 'playwright',
    '@testing-library/react', 'supertest', 'nock', '@faker-js/faker', 'faker', 'deepmerge', 'object-assign', 'extend', 'clone',
    'glob', 'fast-glob', 'rimraf', 'mkdirp', 'fs-extra', 'graceful-fs', 'chokidar', 'micromatch', 'minimatch', 'picomatch',
    'semver', 'readable-stream', 'through2', 'safe-buffer', 'inherits', 'once', 'source-map', 'source-map-support',
    'escape-string-regexp', 'strip-ansi', 'ansi-styles', 'supports-color', 'string-width', 'wrap-ansi', 'tar', 'archiver',
    'adm-zip', 'jszip', 'xml2js', 'fast-xml-parser', 'csv-parse', 'papaparse', 'sharp', 'jimp', 'canvas', 'cheerio', 'jsdom',
    'aws-sdk', '@aws-sdk/client-s3', 'firebase', 'firebase-admin', 'stripe', 'twilio', 'openai', 'graphql', '@apollo/client',
    'apollo-server', 'prisma', '@prisma/client', 'typeorm', 'sequelize', 'knex', 'mongoose', 'mongodb', 'mysql', 'mysql2', 'pg',
    'sqlite3', 'better-sqlite3', 'redis', 'ioredis', 'kafkajs', 'amqplib', 'bull', 'node-cron', 'cron', 'socket.io', 'ws',
    'crypto-js', 'node-forge', 'eventemitter3', 'lru-cache', 'node-cache', 'http-proxy', 'http-proxy-middleware', 'electron',
    'electron-builder', 'expo', 'lerna', 'nx', 'husky', 'lint-staged', 'standard', 'tape', 'ava', 'nyc', 'c8', 'yarn', 'npm',
    'pnpm', 'left-pad', 'event-stream', 'ua-parser-js', 'coa', 'rc'
  ],
  pypi: [
    'requests', 'urllib3', 'certifi', 'charset-normalizer', 'idna', 'numpy', 'pandas', 'scipy', 'matplotlib', 'seaborn',
    'scikit-learn', 'sklearn', 'tensorflow', 'keras', 'torch', 'torchvision', 'transformers', 'tokenizers', 'datasets',
    'huggingface-hub', 'jupyter', 'notebook', 'ipython', 'ipykernel', 'jupyterlab', 'flask', 'django', 'fastapi', 'uvicorn',
    'gunicorn', 'starlette', 'pydantic', 'sqlalchemy', 'alembic', 'psycopg2', 'psycopg2-binary', 'psycopg', 'pymysql',
    'mysqlclient', 'redis', 'celery', 'kombu', 'boto3', 'botocore', 's3transfer', 'awscli', 'google-cloud-storage',
    'google-api-python-client', 'azure-storage-blob', 'pyyaml', 'toml', 'tomli', 'python-dateutil', 'pytz', 'six',
    'setuptools', 'wheel', 'pip', 'virtualenv', 'packaging', 'attrs', 'click', 'jinja2', 'markupsafe', 'werkzeug',
    'itsdangerous', 'cryptography', 'pyopenssl', 'paramiko', 'bcrypt', 'pyjwt', 'oauthlib', 'requests-oauthlib', 'httpx',
    'aiohttp', 'httplib2', 'websockets', 'beautifulsoup4', 'bs4', 'lxml', 'html5lib', 'selenium', 'scrapy', 'pillow',
    'opencv-python', 'imageio', 'pytest', 'pytest-cov', 'coverage', 'tox', 'nose', 'mock', 'black', 'flake8', 'pylint', 'mypy',
    'isort', 'autopep8', 'yapf', 'pre-commit', 'poetry', 'pipenv', 'twine', 'build', 'docutils', 'sphinx', 'colorama',
    'termcolor', 'tqdm', 'rich', 'loguru', 'python-dotenv', 'simplejson', 'ujson', 'orjson', 'msgpack', 'protobuf', 'grpcio',
    'pyzmq', 'kafka-python', 'confluent-kafka', 'pika', 'pymongo', 'elasticsearch', 'cassandra-driver', 'networkx', 'sympy',
    'statsmodels', 'xgboost', 'lightgbm', 'catboost', 'nltk', 'spacy', 'gensim', 'openpyxl', 'xlrd', 'xlsxwriter', 'pyarrow',
    'polars', 'dask', 'joblib', 'psutil', 'pywin32', 'pyserial', 'pexpect', 'cffi', 'pycparser', 'cython', 'numba', 'llvmlite',
    'greenlet', 'gevent', 'eventlet', 'tornado', 'twisted', 'zope-interface', 'pyasn1', 'rsa', 'google-auth', 'cachetools',
    'filelock', 'platformdirs', 'distlib', 'typing-extensions', 'importlib-metadata', 'zipp', 'wrapt', 'decorator',
    'pyparsing', 'regex', 'chardet', 'fsspec', 's3fs', 'openai', 'anthropic', 'langchain', 'tiktoken', 'discord-py',
    'python-telegram-bot', 'tweepy', 'pygame', 'kivy', 'pyqt5', 'pyside6', 'wxpython', 'pyinstaller', 'fabric', 'invoke',
    'ansible', 'docker', 'kubernetes', 'netmiko', 'scapy', 'python-nmap', 'colorlog', 'arrow', 'pendulum', 'humanize', 'babel',
    'marshmallow', 'jsonschema', 'graphene', 'sentry-sdk', 'prometheus-client', 'pymssql', 'oracledb', 'cx-oracle',
    'snowflake-connector-python', 'pyodbc', 'ldap3', 'python-ldap', 'passlib', 'argon2-cffi', 'pynacl', 'pycryptodome',
    'pycrypto', 'faker', 'factory-boy', 'hypothesis', 'freezegun', 'responses', 'requests-mock', 'moto', 'locust', 'gradio',
    'streamlit', 'dash', 'plotly', 'bokeh', 'altair'
  ]
};

// the extra words a squat bolts on, compared with separators already stripped
const NOISE = {
  npm: ['js', 'node', 'nodejs', 'official', 'latest', 'new', 'free', 'lib', 'pkg', 'npm'],
  pypi: ['python', 'python3', 'py', 'py3', 'official', 'latest', 'lib', 'pkg', 'pip']
};

const TECHNIQUES = ['separators', 'look-alike characters', 'extra words', 'scope confusion', 'swapped letters', 'one letter off', 'two letters off'];

function mode() {
  const m = String(db.settings.get('typosquat_mode') || 'warn');
  return MODES.includes(m) ? m : 'warn';
}

function normalize(ecosystem, name) {
  const n = String(name || '').trim().toLowerCase();
  return ecosystem === 'pypi' ? n.replace(/[-_.]+/g, '-') : n;
}

const strip = (s) => s.replace(/[@/._-]+/g, '');
// what a name looks like at a glance. 0 for o, 1 and i for l, rn for m
const skeleton = (s) => strip(s).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1i]/g, 'l').replace(/3/g, 'e').replace(/5/g, 's');

// optimal string alignment distance, gives up past max so long names stay cheap
function distance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev2 = null;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i += 1) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (prev2 && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2] + 1);
      cur.push(v);
      if (v < best) best = v;
    }
    if (best > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length];
}

function swapped(a, b) {
  if (a.length !== b.length) return false;
  const diff = [];
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) diff.push(i);
  return diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]];
}

// how candidate imitates target, or null. both already normalized
function compare(ecosystem, candidate, target) {
  if (!candidate || !target || candidate === target) return null;
  const cs = strip(candidate);
  const ts = strip(target);
  if (!cs || !ts) return null;
  if (cs === ts) return 'separators';
  if (skeleton(candidate) === skeleton(target)) return 'look-alike characters';
  if (ts.length >= 3) {
    for (const word of NOISE[ecosystem] || []) {
      if (cs === word + ts || cs === ts + word) return 'extra words';
    }
  }
  if (ecosystem === 'npm' && target.startsWith('@') && target.includes('/') && !candidate.startsWith('@')) {
    if (cs === ts) return 'scope confusion';
  }
  // edits only mean something on names long enough that one letter is not most of the name
  if (target.length >= 5 && candidate.length >= 4) {
    const max = target.length >= 10 ? 2 : 1;
    const d = distance(candidate, target, max);
    if (d <= max) {
      if (d === 1 && swapped(candidate, target)) return 'swapped letters';
      return d === 1 ? 'one letter off' : 'two letters off';
    }
  }
  return null;
}

// ---------------------------------------------------------------- what counts as known

let cache = null;
let cachedAt = 0;
const memo = new Map();

function invalidate() {
  cache = null;
  memo.clear();
}

function listSetting(key) {
  return String(db.settings.get(key) || '')
    .split(/[\n,]+/)
    .map((s) => s.replace(/#.*$/, '').trim())
    .filter(Boolean)
    .slice(0, 2000);
}

function glob(pattern, text) {
  const p = String(pattern).toLowerCase();
  const t = String(text).toLowerCase();
  let i = 0;
  let j = 0;
  let star = -1;
  let mark = 0;
  while (j < t.length) {
    if (i < p.length && p[i] === '*') {
      star = i;
      i += 1;
      mark = j;
    } else if (i < p.length && p[i] === t[j]) {
      i += 1;
      j += 1;
    } else if (star !== -1) {
      i = star + 1;
      mark += 1;
      j = mark;
    } else {
      return false;
    }
  }
  while (i < p.length && p[i] === '*') i += 1;
  return i === p.length;
}

async function known() {
  if (cache && Date.now() - cachedAt < CACHE_MS) return cache;
  const out = {};
  for (const eco of ['npm', 'pypi']) {
    const norm = (n) => normalize(eco, n);
    const legit = new Set([...BUILTIN[eco], ...listSetting('typosquat_protected')].map(norm));
    const pinned = await rulesRepo.exactAllowPatterns(eco).catch(() => []);
    for (const r of pinned) legit.add(norm(r.pattern));
    const dismissed = new Set((await findings.dismissedNames(eco).catch(() => [])).map((r) => norm(r.package_name)));
    // served a lot here, so worth imitating. only ever a target, never a pass
    const busy = eco === 'npm'
      ? await packagesRepo.busiest(LOCAL_MIN_HITS, LOCAL_TOP).catch(() => [])
      : await pypiFiles.busiest(LOCAL_MIN_HITS, LOCAL_TOP).catch(() => []);
    const flagged = new Set((await findings.flaggedNames(eco).catch(() => [])).map((r) => norm(r.package_name)));
    const targets = new Set(legit);
    for (const r of busy) {
      const n = norm(r.name);
      if (!flagged.has(n)) targets.add(n);
    }
    out[eco] = { legit, dismissed, targets: [...targets] };
  }
  cache = out;
  cachedAt = Date.now();
  return out;
}

// { lookalike, technique, reason } or null. ignores the mode, Check a package asks this too
async function check(ecosystem, name) {
  if (ecosystem !== 'npm' && ecosystem !== 'pypi') return null;
  const n = normalize(ecosystem, name);
  if (!n) return null;
  const key = `${ecosystem} ${n}`;
  const hit = memo.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.finding;

  const k = (await known())[ecosystem];
  let finding = null;
  const exempt = listSetting('typosquat_exempt').some((p) => glob(p, n));
  if (!exempt && !k.legit.has(n) && !k.dismissed.has(n)) {
    let best = null;
    for (const target of k.targets) {
      const technique = compare(ecosystem, n, target);
      if (!technique) continue;
      const rank = TECHNIQUES.indexOf(technique);
      if (!best || rank < best.rank) best = { rank, target, technique };
      if (rank === 0) break;
    }
    if (best) {
      finding = { lookalike: best.target, technique: best.technique, reason: `the name looks like ${best.target} (${best.technique}), a possible typosquat` };
    }
  }
  if (memo.size >= MEMO_MAX) memo.clear();
  memo.set(key, { finding, at: Date.now() });
  return finding;
}

// ---------------------------------------------------------------- recording

const lastWrite = new Map();

async function note(ecosystem, name, finding, action) {
  const key = `${ecosystem} ${name} ${action}`;
  if (Date.now() - (lastWrite.get(key) || 0) < 60000) return;
  if (lastWrite.size > 10000) lastWrite.clear();
  lastWrite.set(key, Date.now());
  try {
    const changed = await findings.record({
      ecosystem, name: String(name).slice(0, 214), lookalike: String(finding.lookalike).slice(0, 214), technique: finding.technique, action
    });
    if (changed === 1) {
      log.warn(`typosquat: ${ecosystem} ${name} looks like ${finding.lookalike} (${finding.technique}), ${action}`);
      await auth.audit(null, 'system', null, 'typosquat.detected', `${ecosystem}:${name}`, `looks like ${finding.lookalike} (${finding.technique}), ${action}`);
    }
  } catch (err) {
    log.error('could not record a typosquat', err.message);
  }
}

// for the registry routes: null, or { block, warn, reason }. learning mode never blocks
async function verdict(ecosystem, name) {
  const m = mode();
  if (m === 'off') return null;
  const finding = await check(ecosystem, name).catch(() => null);
  if (!finding) return null;
  const block = m === 'block' && !db.settings.getBool('audit_mode');
  note(ecosystem, name, finding, block ? 'blocked' : 'warned').catch(() => {});
  return { block, warn: !block, lookalike: finding.lookalike, technique: finding.technique, reason: finding.reason };
}

async function setStatus(id, status, user) {
  await findings.setStatus(id, {
    status, by: status === 'dismissed' ? String(user || '').slice(0, 64) : null, at: status === 'dismissed' ? new Date() : null
  });
  invalidate();
}

module.exports = {
  MODES, BUILTIN, TECHNIQUES, mode, normalize, strip, skeleton, distance, compare, check, verdict, note, setStatus, invalidate, glob
};
