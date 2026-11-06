// The /_api/v1 description: OpenAPI 3 for Swagger, a Postman v2.1 collection, and what the portal's try-it page reads.
// Author: Tim Rice
// one list of operations below, all three are built from it, so they can't disagree with each other (much)

const BASE = '/_api/v1';

const RULE = {
  type: 'object',
  properties: {
    id: { type: 'integer', example: 42 },
    ecosystem: { type: 'string', example: 'npm' },
    pattern: { type: 'string', example: 'left-pad' },
    kind: { type: 'string', enum: ['allow', 'deny'] },
    list: { type: 'string', enum: ['whitelist', 'blacklist'] },
    version_range: { type: 'string', example: '1.3.0' },
    application: { type: 'string', nullable: true },
    environment: { type: 'string', nullable: true },
    note: { type: 'string', nullable: true },
    priority: { type: 'integer', example: 0 },
    enabled: { type: 'boolean' },
    expires_at: { type: 'string', format: 'date-time', nullable: true, description: 'UTC. null = never' },
    expired: { type: 'boolean' },
    created_at: { type: 'string' },
    updated_at: { type: 'string' }
  }
};

const EXPIRES = {
  oneOf: [{ type: 'integer', minimum: 1 }, { type: 'string' }],
  description: 'Days from now (7, "7" or "7d"), a date (yyyy-mm-dd, good until 23:59:59 UTC that day) or an ISO time. ' +
    'An allow (whitelist) rule defaults to 1 day and runs 365 days at most. A deny (blacklist) rule lasts until deleted ' +
    'unless given one, and "never" is accepted for it.',
  example: '7d'
};

const NEW_RULE = {
  type: 'object',
  required: ['kind', 'pattern'],
  properties: {
    kind: { type: 'string', enum: ['allow', 'deny', 'whitelist', 'blacklist'], example: 'allow' },
    ecosystem: { type: 'string', example: 'npm', description: 'npm, pypi, oci, nuget, maven, rubygems, cocoapods, swift, composer, rpm or apt. Blank = npm. See GET /ecosystems.' },
    pattern: { type: 'string', example: 'left-pad', description: 'Package name. A * matches anything.' },
    version_range: { type: 'string', example: '1.3.0', description: 'Blank = every version. Same syntax as the portal.' },
    expires: EXPIRES,
    note: { type: 'string', example: 'CHG0012345 temporary exception' },
    priority: { type: 'integer', example: 0, description: 'Up to the max priority set on the key.' },
    application: { type: 'string', description: 'Only for this application (by name).' },
    environment: { type: 'string', description: 'Only in this environment (by name).' }
  }
};

const PATCH_RULE = {
  type: 'object',
  properties: { expires: EXPIRES, note: { type: 'string' }, priority: { type: 'integer' }, enabled: { type: 'boolean' } }
};

const ERR = { type: 'object', properties: { error: { type: 'string' } } };

// what the try-it page and postman need, and the source for openapi below
const OPERATIONS = [
  { id: 'whoami', method: 'GET', path: '/me', summary: 'The key making the call', scope: null, tag: 'Key' },
  { id: 'ecosystems', method: 'GET', path: '/ecosystems', summary: 'Kinds of registry switched on here', scope: null, tag: 'Key' },
  {
    id: 'listRules', method: 'GET', path: '/rules', summary: 'Rules this key made', scope: 'rules:read', tag: 'Rules',
    query: [
      { name: 'kind', schema: { type: 'string', enum: ['allow', 'deny', 'whitelist', 'blacklist'] } },
      { name: 'ecosystem', schema: { type: 'string' } },
      { name: 'pattern', schema: { type: 'string' }, description: 'exact name' },
      { name: 'state', schema: { type: 'string', enum: ['active', 'expired'] } },
      { name: 'page', schema: { type: 'integer', default: 1 } },
      { name: 'limit', schema: { type: 'integer', default: 50, maximum: 500 } }
    ]
  },
  {
    id: 'createRule', method: 'POST', path: '/rules', summary: 'File a whitelist or blacklist rule', scope: 'rules:write', tag: 'Rules',
    body: NEW_RULE,
    example: { kind: 'whitelist', ecosystem: 'npm', pattern: 'left-pad', version_range: '1.3.0', expires: '7d', note: 'CHG0012345' },
    responses: { 201: 'Made', 200: 'This key already had that rule, its expiry and note were updated', 409: 'A person already has that rule' }
  },
  { id: 'getRule', method: 'GET', path: '/rules/{id}', summary: 'One rule', scope: 'rules:read', tag: 'Rules' },
  {
    id: 'updateRule', method: 'PATCH', path: '/rules/{id}', summary: 'Extend or change a rule', scope: 'rules:write', tag: 'Rules',
    body: PATCH_RULE, example: { expires: '2026-12-31' }
  },
  { id: 'deleteRule', method: 'DELETE', path: '/rules/{id}', summary: 'Take a rule out', scope: 'rules:write', tag: 'Rules', responses: { 204: 'Gone' } }
];

function responsesFor(op) {
  const ok = op.method === 'DELETE' ? { 204: { description: 'Gone' } }
    : { [op.method === 'POST' ? 201 : 200]: { description: 'OK', content: { 'application/json': { schema: op.tag === 'Rules' ? (op.id === 'listRules' ? { type: 'object', properties: { rules: { type: 'array', items: { $ref: '#/components/schemas/Rule' } }, total: { type: 'integer' }, page: { type: 'integer' }, limit: { type: 'integer' } } } : { $ref: '#/components/schemas/Rule' }) : { type: 'object' } } } } };
  const out = { ...ok };
  for (const [code, text] of Object.entries(op.responses || {})) {
    if (!out[code]) out[code] = { description: text, content: Number(code) < 300 ? { 'application/json': { schema: { $ref: '#/components/schemas/Rule' } } } : { 'application/json': { schema: ERR } } };
  }
  const errs = { 400: 'Bad input', 401: 'No key, or a bad, revoked or expired one', 403: 'Not allowed from this address, or the key lacks the scope', 404: 'No such rule, or not one this key made', 429: 'Too many requests' };
  for (const [code, text] of Object.entries(errs)) if (!out[code]) out[code] = { description: text, content: { 'application/json': { schema: ERR } } };
  return out;
}

function openapi(origin) {
  const paths = {};
  for (const op of OPERATIONS) {
    const item = paths[op.path] || (paths[op.path] = {});
    const params = [...(op.query || []).map((q) => ({ in: 'query', name: q.name, schema: q.schema, description: q.description }))];
    if (op.path.includes('{id}')) params.unshift({ in: 'path', name: 'id', required: true, schema: { type: 'integer' } });
    item[op.method.toLowerCase()] = {
      operationId: op.id,
      tags: [op.tag],
      summary: op.summary,
      description: op.scope ? `Needs the ${op.scope} scope.` : 'Any valid key.',
      parameters: params.length ? params : undefined,
      requestBody: op.body ? { required: true, content: { 'application/json': { schema: op.body, example: op.example } } } : undefined,
      responses: responsesFor(op)
    };
  }
  return {
    openapi: '3.0.3',
    info: {
      title: 'ForgeRepo rules API',
      version: '1.0.0',
      description: 'File temporary whitelist (allow) and blacklist (deny) rules from another product. ' +
        'Send an API key from Settings, API as Authorization: Bearer frk_... Every key only works from the networks set on it, ' +
        'and only sees and changes the rules it made itself.'
    },
    servers: [{ url: `${origin || ''}${BASE}` }],
    security: [{ apiKey: [] }],
    tags: [{ name: 'Rules' }, { name: 'Key' }],
    paths,
    components: {
      securitySchemes: { apiKey: { type: 'http', scheme: 'bearer', bearerFormat: 'frk_...' } },
      schemas: { Rule: RULE, NewRule: NEW_RULE, RulePatch: PATCH_RULE, Error: ERR }
    }
  };
}

function postman(origin) {
  return {
    info: {
      name: 'ForgeRepo rules API',
      description: 'Set baseUrl and apiKey in the collection variables. The key only works from the networks set on it.',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    auth: { type: 'bearer', bearer: [{ key: 'token', value: '{{apiKey}}', type: 'string' }] },
    variable: [
      { key: 'baseUrl', value: `${origin || 'https://forgerepo.example.com'}${BASE}` },
      { key: 'apiKey', value: 'frk_paste_your_key_here' },
      { key: 'ruleId', value: '1' }
    ],
    item: OPERATIONS.map((op) => {
      const pathParts = op.path.replace('{id}', '{{ruleId}}').split('/').filter(Boolean);
      const req = {
        method: op.method,
        header: op.body ? [{ key: 'Content-Type', value: 'application/json' }] : [],
        url: {
          raw: `{{baseUrl}}/${pathParts.join('/')}`,
          host: ['{{baseUrl}}'],
          path: pathParts,
          query: (op.query || []).map((q) => ({ key: q.name, value: '', disabled: true }))
        },
        description: `${op.summary}.${op.scope ? ` Needs ${op.scope}.` : ''}`
      };
      if (op.body) req.body = { mode: 'raw', raw: JSON.stringify(op.example || {}, null, 2), options: { raw: { language: 'json' } } };
      return { name: op.summary, request: req };
    })
  };
}

// a trimmed copy for the portal's try-it page
function consoleOps() {
  return OPERATIONS.map((op) => ({
    id: op.id, method: op.method, path: op.path, summary: op.summary, scope: op.scope,
    query: (op.query || []).map((q) => q.name), example: op.example || null
  }));
}

module.exports = { BASE, OPERATIONS, openapi, postman, consoleOps };
