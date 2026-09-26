// The box's own signing key for APT mirrors that hand out a filtered index, and checking a distro's signature.
// Author: Tim Rice
//
// apt checks every package through the signed Release file, nothing else. a filtered index is not what the distro
// signed, so the box checks the distro's signature itself (gpgv, against the keyrings shipped in the image) and signs
// the filtered one with its own key. clients trust that key instead (signed-by=), so nothing goes unchecked on the way.
// the key is made on first use and kept in the folder this app owns, readable by it only. emptying the cache only
// empties the package store, the key stays. a new key means every client has to fetch it again

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const config = require('../../config');
const { httpError } = require('../../lib/errors');

const HOME = path.join(config.cacheDir, 'keys', 'apt-signing');
const USER_ID = 'ForgeRepo package mirrors <mirrors@forgerepo.invalid>';
// the keyrings of the distros whose signature the box can check
const KEYRINGS = ['/usr/share/keyrings/debian-archive-keyring.gpg', '/usr/share/keyrings/ubuntu-archive-keyring.gpg'];

// a program's output, fed some input. never through a shell
function run(cmd, args, input, { timeoutMs = 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', GNUPGHOME: HOME, LANG: 'C' } });
    const out = [];
    const err = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString('utf8') });
    });
    child.stdin.end(input || '');
  });
}

const gpg = (args, input) => run('gpg', ['--homedir', HOME, '--batch', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', '', ...args], input);

let ready = null;
// the key, made the first time it is needed
function ensureKey() {
  if (!ready) {
    ready = (async () => {
      await fsp.mkdir(HOME, { recursive: true, mode: 0o700 });
      await fsp.chmod(HOME, 0o700);
      const listed = await gpg(['--list-secret-keys', '--with-colons']);
      if (!/^sec:/m.test(listed.stdout.toString('utf8'))) {
        const made = await gpg(['--quick-gen-key', USER_ID, 'ed25519', 'sign', '0']);
        if (made.code !== 0) throw new Error(`the APT signing key could not be made: ${made.stderr.slice(0, 300)}`);
      }
    })();
    ready.catch(() => {
      ready = null;
    });
  }
  return ready;
}

// the public key, armored, for clients to put in /etc/apt/keyrings
async function publicKey() {
  await ensureKey();
  const got = await gpg(['--armor', '--export', USER_ID]);
  if (got.code !== 0 || !got.stdout.length) throw new Error('the APT signing key could not be exported');
  return got.stdout.toString('utf8');
}

// InRelease: the text, signed in line
async function clearsign(text) {
  await ensureKey();
  const got = await gpg(['--digest-algo', 'SHA512', '--local-user', USER_ID, '--clearsign'], text);
  if (got.code !== 0) throw new Error(`the filtered index could not be signed: ${got.stderr.slice(0, 300)}`);
  return got.stdout.toString('utf8');
}

// Release.gpg: a detached signature of Release
async function detachSign(text) {
  await ensureKey();
  const got = await gpg(['--digest-algo', 'SHA512', '--local-user', USER_ID, '--armor', '--detach-sign'], text);
  if (got.code !== 0) throw new Error(`the filtered index could not be signed: ${got.stderr.slice(0, 300)}`);
  return got.stdout.toString('utf8');
}

// the text a distro signed in its InRelease, or it throws. only the checked text comes back, never the armor around it
async function verified(inRelease) {
  const rings = KEYRINGS.filter((k) => fs.existsSync(k)).flatMap((k) => ['--keyring', k]);
  if (!rings.length) throw httpError(502, 'this box has no distro keyrings to check the index with');
  const got = await run('gpgv', ['--status-fd', '2', ...rings, '--output', '-', '-'], inRelease);
  if (got.code !== 0 || !/\[GNUPG:\] VALIDSIG /.test(got.stderr)) {
    throw httpError(502, 'the mirror\'s InRelease is not signed by a Debian or Ubuntu archive key this box knows, so no filtered index is made from it');
  }
  return got.stdout.toString('utf8');
}

module.exports = { HOME, KEYRINGS, ensureKey, publicKey, clearsign, detachSign, verified };
