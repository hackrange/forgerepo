// @ts-check
// Errors that carry an HTTP status. the error middleware turns them into a clean JSON answer.
// Author: Tim Rice

class HttpError extends Error {
  /**
   * @param {number} status HTTP status the caller should see
   * @param {string} message safe to show, never internals
   */
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * Throws, for validation that reads top to bottom.
 * @param {number} status
 * @param {string} message
 * @returns {never}
 */
function fail(status, message) {
  throw new HttpError(status, message);
}

/**
 * For code that builds the error and throws it itself, or hands it to a promise.
 * @param {number} status
 * @param {string} message
 * @returns {HttpError}
 */
function httpError(status, message) {
  return new HttpError(status, message);
}

module.exports = { HttpError, fail, httpError };
