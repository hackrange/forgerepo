// What dotnet reads before it downloads anything: the service index, the version list, and the registration.
// Author: Tim Rice
//
// both lists come from one summary of the package and go through the same filter, so dotnet add package and dotnet
// restore see the same versions. a package with nothing let through is a 404 with the reason in X-NuGet-Warning, and a
// request for it is opened, the same as a refused npm install

const policy = require('../../policy');
const ecosystems = require('../../ecosystems');
const nugetName = require('../../ecosystems/nuget/name');
const versionFilter = require('../shared/versions');
const shared = require('../shared/requests');
const access = require('../shared/access');
const upstream = require('./upstream');
const { record, json, refuse, failed, auditOnly, looksLikeNugetClient } = require('./respond');

const adapter = () => ecosystems.adapter('nuget');
const REGISTRATION_TYPES = ['RegistrationsBaseUrl', 'RegistrationsBaseUrl/3.0.0-beta', 'RegistrationsBaseUrl/3.0.0-rc',
  'RegistrationsBaseUrl/3.4.0', 'RegistrationsBaseUrl/3.6.0', 'RegistrationsBaseUrl/Versioned'];

const base = (req) => `${access.baseUrl(req)}/nuget`;

// only the resources this box answers. no repository signatures (dotnet refuses those over http) and no catalog.
// PackagePublish is there for dotnet nuget push, which only reserved ids get through
function serviceIndex(req, res) {
  const b = base(req);
  record(req, { action: 'allow', reason: 'service index' });
  return json(res, 200, {
    version: '3.0.0',
    resources: [
      { '@id': `${b}/v3-flatcontainer/`, '@type': 'PackageBaseAddress/3.0.0', comment: 'package versions and downloads' },
      ...REGISTRATION_TYPES.map((t) => ({ '@id': `${b}/v3/registration/`, '@type': t, comment: 'versions with their metadata' })),
      { '@id': `${b}/api/v2/package`, '@type': 'PackagePublish/2.0.0', comment: 'dotnet nuget push, reserved ids only' }
    ]
  });
}

// the package's summary and the versions of it this caller may see. null once the answer has gone out
async function listed(req, res, raw) {
  if (!nugetName.valid(raw)) {
    record(req, { action: 'error', status: 404, reason: 'not a NuGet package id' });
    json(res, 404, { error: 'that is not a NuGet package id' });
    return null;
  }
  let got;
  try {
    got = await upstream.summary(raw);
  } catch (err) {
    failed(req, res, err, { package_name: raw });
    return null;
  }
  const { doc } = got;
  const { allowed, excluded } = await versionFilter.visible({
    ecosystem: 'nuget', adapter: adapter(), name: doc.id, versions: doc.versions,
    fileOf: (v) => upstream.fileName(doc.id, v), scope: policy.scopeOf(req), lenient: auditOnly()
  });
  if (!allowed.length) {
    // the rules' own words when they are why, otherwise the first reason there was
    const why = (excluded.find((e) => e.kind === 'rule') || excluded[0] || { reason: 'the feed lists no versions of it' }).reason;
    record(req, { package_name: doc.id, action: 'deny', status: 404, reason: why });
    if (excluded.some((e) => e.kind === 'rule')) {
      await shared.openRequest(req, doc.id, null, why, { ecosystem: 'nuget', looksLikeClient: looksLikeNugetClient(req) });
    }
    refuse(res, doc.id, null, why, 404, true);
    return null;
  }
  return { doc, allowed, excluded, cacheHit: got.cacheHit };
}

// /v3-flatcontainer/{id}/index.json: the versions, lower case, oldest first
async function versionList(req, res) {
  const got = await listed(req, res, req.params[0]);
  if (!got) return null;
  record(req, { package_name: got.doc.id, action: 'allow', reason: `${got.allowed.length} of ${got.doc.versions.length} versions`, cache_hit: got.cacheHit ? 1 : 0 });
  return json(res, 200, { versions: got.allowed.map((v) => v.version) });
}

function entry(b, doc, v) {
  const lower = nugetName.fold(doc.id);
  const content = `${b}/v3-flatcontainer/${lower}/${v.version}/${lower}.${v.version}.nupkg`;
  return {
    '@id': `${b}/v3/registration/${lower}/${v.version}.json`,
    '@type': 'Package',
    catalogEntry: {
      '@id': `${b}/v3/registration/${lower}/${v.version}.json#details`,
      '@type': 'PackageDetails',
      id: doc.id,
      version: v.version,
      listed: v.listed,
      // how nuget.org says unlisted
      published: v.listed ? (v.published || '1970-01-01T00:00:00+00:00') : '1900-01-01T00:00:00+00:00',
      licenseExpression: v.license || '',
      packageContent: content,
      dependencyGroups: (v.deps || []).map((g) => ({ targetFramework: g.framework, dependencies: g.dependencies.map((d) => ({ id: d.id, range: d.range })) })),
      ...(v.deprecated ? { deprecation: { reasons: ['Other'], message: v.deprecated } } : {})
    },
    packageContent: content,
    registration: `${b}/v3/registration/${lower}/index.json`
  };
}

// /v3/registration/{id}/index.json: one page, every version inline, what dotnet add package picks the newest from
async function registration(req, res) {
  const got = await listed(req, res, req.params[0]);
  if (!got) return null;
  const b = base(req);
  const lower = nugetName.fold(got.doc.id);
  const items = got.allowed.map((v) => entry(b, got.doc, v));
  record(req, { package_name: got.doc.id, action: 'allow', reason: `registration, ${items.length} of ${got.doc.versions.length} versions`, cache_hit: got.cacheHit ? 1 : 0 });
  return json(res, 200, {
    '@id': `${b}/v3/registration/${lower}/index.json`,
    '@type': ['catalog:CatalogRoot', 'PackageRegistration', 'catalog:Permalink'],
    count: 1,
    items: [{
      '@id': `${b}/v3/registration/${lower}/index.json#page/${items[0].catalogEntry.version}/${items[items.length - 1].catalogEntry.version}`,
      '@type': 'catalog:CatalogPage',
      count: items.length,
      lower: items[0].catalogEntry.version,
      upper: items[items.length - 1].catalogEntry.version,
      parent: `${b}/v3/registration/${lower}/index.json`,
      items
    }]
  });
}

module.exports = { serviceIndex, versionList, registration };
