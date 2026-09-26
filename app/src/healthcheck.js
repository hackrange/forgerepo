// docker HEALTHCHECK. 0 = alive, 1 = playing dead
// Author: Tim Rice

const port = process.env.PORT || '4444';

fetch(`http://127.0.0.1:${port}/_health`, { signal: AbortSignal.timeout(4000) })
  .then((res) => res.json().then((body) => ({ status: res.status, body })))
  .then(({ status, body }) => {
    if (status === 200 && body.ok) process.exit(0);
    process.stderr.write(`health check said ${status}: ${JSON.stringify(body)}\n`);
    process.exit(1);
  })
  .catch((err) => {
    process.stderr.write(`health check could not connect: ${err.message}\n`);
    process.exit(1);
  });
