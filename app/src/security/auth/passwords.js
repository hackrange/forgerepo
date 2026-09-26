// Password hashing and the rules a new password has to meet.
// Author: Tim Rice

const bcrypt = require('bcryptjs');
const db = require('../../db');

const BCRYPT_ROUNDS = 12;

// Has to be a REAL hash. a fake one fails instantly and the timing gap tells you
// which usernames exist. one slow hash at startup, both paths take the same time
const NOBODY_HASH = bcrypt.hashSync('there is no account with this name', BCRYPT_ROUNDS);

async function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  try {
    return await bcrypt.compare(plain, hash);
  } catch (err) {
    return false;
  }
}

// the same work a real account costs, for a name that has none
function burnTime(plain) {
  return bcrypt.compare(String(plain || ''), NOBODY_HASH);
}

//null if the password is fine, otherwise a message for the user
function checkPasswordPolicy(password, username) {
  const min = db.settings.getInt('min_password_length', 12);
  if (typeof password !== 'string' || password.length < min) {
    return `password has to be at least ${min} characters`;
  }
  if (password.length > 200) return 'password is too long';

  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 3) {
    return 'use at least three of these: lower case, upper case, numbers, symbols';
  }
  if (username && password.toLowerCase().includes(String(username).toLowerCase())) {
    return 'password cannot contain your username';
  }
  const junk = ['password', 'changeme', 'qwerty', '123456', 'letmein', 'npmrepo', 'forgerepo', 'welcome'];
  const lower = password.toLowerCase();
  if (junk.some((w) => lower.includes(w))) return 'that password is too easy to guess';
  return null;
}

module.exports = { hashPassword, verifyPassword, burnTime, checkPasswordPolicy };
