// The NuGet facing side. dotnet, nuget.exe and Visual Studio point at /nuget/v3/index.json.
// Author: Tim Rice
// /nuget/v3/index.json, /nuget/v3-flatcontainer/<id>/index.json and its packages, /nuget/v3/registration/<id>/index.json,
// and PUT /nuget/api/v2/package for dotnet nuget push

const express = require('express');
const { wrap } = require('../../lib/http');
const front = require('./front');
const feed = require('./feed');
const { servePackage } = require('./files');
const push = require('./push');
const { record, json } = require('./respond');

const router = express.Router();

router.use(front.ours);
router.use(front.identify);
router.use(front.readOnly);

router.get(/^\/v3\/index\.json$/, feed.serviceIndex);
router.get(/^\/v3-flatcontainer\/([^/]+)\/index\.json$/, wrap(feed.versionList));
router.get(/^\/v3-flatcontainer\/([^/]+)\/([^/]+)\/([^/]+\.nupkg)$/, wrap(servePackage));
router.get(/^\/v3\/registration\/([^/]+)\/index\.json$/, wrap(feed.registration));
router.put(/^\/api\/v2\/package\/?$/, wrap(push.handlePush));
router.delete(/^\/api\/v2\/package\/[^/]+\/[^/]+$/, push.handleDelete);

router.all(/.*/, (req, res) => {
  record(req, { action: 'error', status: 404, reason: 'no such NuGet endpoint' });
  return json(res, 404, { error: 'not found' });
});

module.exports = router;
