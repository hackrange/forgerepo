// Short lived bearer tokens handed out at /v2/token. docker trades its login for one and sends that instead.
// Author: Tim Rice
// only the hash is kept, like the registry tokens themselves, and a bearer is only as good as the token behind it

const db = require('../../db');

async function put(hash, tokenId, seconds) {
  await db.query('INSERT INTO oci_bearers (hash, token_id, expires_at) VALUES (?, ?, NOW() + INTERVAL ? SECOND)', [hash, tokenId, seconds]);
}

// the ones that ran out a while ago. a few at a time, it runs every time one is handed out
async function sweep() {
  await db.query('DELETE FROM oci_bearers WHERE expires_at < NOW() - INTERVAL 1 HOUR LIMIT 500');
}

module.exports = { put, sweep };
