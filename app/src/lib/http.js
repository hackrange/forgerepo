// @ts-check
// Express glue that every router shares.
// Author: Tim Rice

/** @typedef {(err?: unknown) => void} Next */

/**
 * rejected promises still reach the error middleware
 * @param {(req: any, res: any, next: Next) => unknown} fn
 * @returns {(req: any, res: any, next: Next) => void}
 */
function wrap(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((err) => next(err));
  };
}

/**
 * a request body has ms to arrive in full, as it always did. paths matching longer (image layers from docker push) are
 * left to their own stall watch, which is why the server's own limit sits higher than this
 * @param {number} ms
 * @param {RegExp} longer
 * @returns {(req: any, res: any, next: Next) => void}
 */
function bodyDeadline(ms, longer) {
  return (req, res, next) => {
    if (req.complete || longer.test(req.path)) return next();
    const timer = setTimeout(() => {
      if (!req.complete) req.destroy();
    }, ms);
    timer.unref();
    const done = () => clearTimeout(timer);
    req.once('end', done);
    req.once('close', done);
    res.once('finish', done);
    res.once('close', done);
    return next();
  };
}

module.exports = { wrap, bodyDeadline };
