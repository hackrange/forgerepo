// Portal API, JSON columns read back safely.
// Author: Tim Rice

function parseList(raw) {
  try {
    const v = JSON.parse(String(raw || '[]'));
    return Array.isArray(v) ? v : [];
  } catch (err) {
    return [];
  }
}

module.exports = { parseList };
