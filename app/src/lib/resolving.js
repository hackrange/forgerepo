// Turning status-carrying errors into API answers.
// Author: Tim Rice

const { fail } = require('./errors');

// integrity.js and quarantine.js throw plain errors with a status, turn those into api answers
async function resolving(work) {
  try {
    return await work();
  } catch (err) {
    if (err.status) fail(err.status, err.message);
    throw err;
  }
}

module.exports = { resolving };
