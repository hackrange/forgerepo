// Reading a request body with a ceiling. The registry routes have no body parser, publishing is the only write they take.
// Author: Tim Rice
// a declared length over the limit is refused before a byte is read, a lying one when it crosses it

const { httpError } = require('../../lib/errors');

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) {
      reject(httpError(413, `that upload is ${(declared / 1048576).toFixed(1)}MB and the limit is ${Math.round(limit / 1048576)}MB`));
      return;
    }
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (err, value) => {
      if (done) return;
      done = true;
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onAborted);
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > limit) {
        finish(httpError(413, `that upload is over the ${Math.round(limit / 1048576)}MB limit`));
        // stop reading, the client gets its answer and the rest is dropped
        req.pause();
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(null, Buffer.concat(chunks, size));
    const onError = (err) => finish(httpError(400, `the upload broke off: ${err.message}`));
    const onAborted = () => finish(httpError(400, 'the upload broke off before it finished'));
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAborted);
  });
}

module.exports = { readBody };
