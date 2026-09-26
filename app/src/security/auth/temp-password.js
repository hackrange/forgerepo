// One-time passwords for a brand new admin account.
// Author: Tim Rice

const crypto = require('crypto');

// No 0, O, 1, I or L, so it can be read off a screen and typed without
// guessing which one it was. 31 characters, 21 of them is about 104 bits.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const GROUPS = [6, 5, 6, 4];

// Looks like H394FW-7YTWX-Y38CFW-JM4S9. randomInt has no modulo bias.
function temporaryPassword() {
  return GROUPS.map((n) => {
    let s = '';
    for (let i = 0; i < n; i++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
    return s;
  }).join('-');
}

module.exports = { temporaryPassword, ALPHABET };
