// Is this address a container registry? Asked once, when someone saves it.
// Author: Tim Rice
//
// a registry answers GET /v2/ with its api version header, or with a 401 that says how to log in. a website answers
// with a page. saving the website is the most common mistake there is (hub.docker.com instead of registry-1.docker.io),
// so Docker Hub's own web addresses are corrected outright and anything else is asked

const safefetch = require('../../security/safefetch');

const DOCKER_HUB_WEB = /^(hub\.docker\.com|www\.docker\.com|docker\.com|docker\.io|index\.docker\.io|registry\.hub\.docker\.com)$/i;
const DOCKER_HUB_REGISTRY = 'https://registry-1.docker.io';

function dockerHubFix(url) {
  let host;
  try {
    host = new URL(url).hostname;
  } catch (err) {
    return null;
  }
  return DOCKER_HUB_WEB.test(host) ? { url: DOCKER_HUB_REGISTRY, host } : null;
}

/** { registry: true } | { registry: false, status } | { registry: null, error } when it could not be asked */
async function probe(url) {
  let res;
  try {
    res = await safefetch.request(`${String(url).replace(/\/+$/, '')}/v2/`, {
      timeoutMs: 10000, maxBytes: 64 * 1024, headers: { accept: 'application/json', 'user-agent': 'ForgeRepo registry check' }
    });
  } catch (err) {
    return { registry: null, error: err.message };
  }
  const header = (n) => (res.headers && typeof res.headers.get === 'function' ? res.headers.get(n) : null);
  if (res.stream) res.stream.resume();
  if (header('docker-distribution-api-version')) return { registry: true };
  if (res.status === 401 && /^(bearer|basic)\b/i.test(String(header('www-authenticate') || ''))) return { registry: true };
  return { registry: false, status: res.status };
}

module.exports = { probe, dockerHubFix, DOCKER_HUB_REGISTRY };
