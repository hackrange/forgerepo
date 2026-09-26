// Copies this box's database onto an outside MySQL or MariaDB server.
// Author: Tim Rice
//
//   node src/migrate-db.js --check --host db.example.com --user npmrepo --password '...'
//   node src/migrate-db.js --run   --host db.example.com --user npmrepo --password '...'
//
// target comes from flags not env on purpose, once DB_HOST is set there's nothing local to copy. Bit late.
// local db is never touched. run --check first, definitely

const mysql = require('mysql2/promise');
const config = require('./config');
const { copyOrder, leftBehind } = require('./db/copy-tables');

// every table the schema makes. this used to be a hand typed list, and it fell 23 tables behind
const TABLES = copyOrder();

// just a cache, and the biggest table by far
const REFETCHABLE = ['packuments'];

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = true;
    else { out[key] = next; i += 1; }
  }
  return out;
}

function usage() {
  console.log(`
Copy this box's database onto an outside server.

  node src/migrate-db.js --check --host HOST [options]
  node src/migrate-db.js --run   --host HOST [options]

  --host HOST          the outside server            (required)
  --port N             default 3306
  --database NAME      default npmrepo
  --user NAME          default npmrepo
  --password PASS      or set TARGET_DB_PASSWORD
  --ssl rds|1|0        rds verifies against Amazon's CA chain, which ships
                       with the driver. Use it for RDS.
  --skip-packuments    leave the cached npm metadata behind. It is the biggest
                       table by far and it refetches on demand.
  --force              write even if the target already holds rows
  --check              look at everything, change nothing
  --run                do it
`);
}

function fmtBytes(n) {
  if (n > 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function sslFor(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw || raw === '0' || raw === 'false' || raw === 'off') return undefined;
  if (raw === 'rds' || raw === 'amazon rds') return 'Amazon RDS';
  return { rejectUnauthorized: true };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || (!args.check && !args.run)) { usage(); process.exit(args.help ? 0 : 1); }
  if (!args.host) { console.error('--host is required. Try --help.'); process.exit(1); }

  if (config.db.host) {
    console.error(
      `DB_HOST is already set to ${config.db.host}, so this container is using the outside\n` +
      'database and there is no local one to copy from. Clear DB_HOST, restart, then migrate.'
    );
    process.exit(1);
  }

  const target = {
    host: args.host,
    port: parseInt(args.port || '3306', 10),
    user: args.user || 'npmrepo',
    password: args.password || process.env.TARGET_DB_PASSWORD || '',
    database: args.database || 'npmrepo',
    ssl: sslFor(args.ssl),
    charset: 'utf8mb4_unicode_ci',
    dateStrings: true,
    multipleStatements: false
  };
  const tables = TABLES.filter((t) => !(args['skip-packuments'] && REFETCHABLE.includes(t)));

  console.log(`source : the database in this container (${config.db.socketPath})`);
  console.log(`target : ${target.user}@${target.host}:${target.port}/${target.database}` +
    (target.ssl ? `  tls: ${typeof target.ssl === 'string' ? target.ssl : 'on'}` : '  tls: off'));
  console.log('');

  const source = await mysql.createConnection({
    socketPath: config.db.socketPath,
    user: config.db.user,
    password: config.db.password,
    database: config.db.database,
    charset: 'utf8mb4_unicode_ci',
    dateStrings: true
  });

  let dest;
  try {
    dest = await mysql.createConnection(target);
  } catch (err) {
    console.error(`could not connect to the target: ${err.message}`);
    if (/ER_NOT_SUPPORTED_AUTH_MODE|caching_sha2/.test(err.message || '')) {
      console.error('MySQL 8 authenticates in a way that wants an encrypted connection. Add --ssl 1, or --ssl rds on RDS.');
    }
    if (/ER_BAD_DB_ERROR|Unknown database/.test(err.message || '')) {
      console.error(`Create it first:  CREATE DATABASE \`${target.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    }
    await source.end();
    process.exit(1);
  }

  let problems = 0;
  const fail = (msg) => { problems += 1; console.log(`  PROBLEM  ${msg}`); };
  const note = (msg) => console.log(`  note     ${msg}`);
  const ok = (msg) => console.log(`  ok       ${msg}`);

  console.log('preflight');

  const [[ver]] = await dest.query('SELECT VERSION() AS v');
  const flavor = /mariadb/i.test(ver.v) ? 'MariaDB' : 'MySQL';
  ok(`target is ${flavor} ${ver.v}`);

  const [[coll]] = await dest.query(
    'SELECT DEFAULT_CHARACTER_SET_NAME c, DEFAULT_COLLATION_NAME l FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?',
    [target.database]
  );
  if (!coll) fail(`database ${target.database} does not exist on the target`);
  else if (coll.c !== 'utf8mb4') fail(`database charset is ${coll.c}, it needs to be utf8mb4`);
  else if (coll.l !== 'utf8mb4_unicode_ci') {
    // not fatal, tables pin their own collation
    note(`database collation is ${coll.l}, the tables pin utf8mb4_unicode_ci themselves`);
  } else ok('database is utf8mb4 / utf8mb4_unicode_ci');

  //the schema builds itself on every boot, so DML rights alone won't cut it
  try {
    await dest.query('CREATE TABLE IF NOT EXISTS _npmrepo_privcheck (id INT PRIMARY KEY) ENGINE=InnoDB');
    await dest.query('ALTER TABLE _npmrepo_privcheck ADD COLUMN probe INT NULL');
    await dest.query('DROP TABLE _npmrepo_privcheck');
    ok('the account can create, alter and drop tables');
  } catch (err) {
    fail(`the account cannot manage tables: ${err.message}`);
    note('the app runs CREATE TABLE IF NOT EXISTS and ALTER TABLE on every boot, so it needs schema rights');
  }

  // a row has to fit in one packet, and packuments get chunky
  const [[pkt]] = await dest.query("SHOW VARIABLES LIKE 'max_allowed_packet'");
  const packet = parseInt(pkt.Value, 10);
  const [[big]] = await source.query(
    tables.includes('packuments')
      ? 'SELECT COALESCE(MAX(LENGTH(body)),0) AS n FROM packuments'
      : 'SELECT 0 AS n'
  );
  if (Number(big.n) > packet * 0.9) {
    fail(`the largest row is ${fmtBytes(Number(big.n))} and the target accepts ${fmtBytes(packet)} per packet`);
    note('raise max_allowed_packet on the target, or use --skip-packuments');
  } else {
    ok(`largest row ${fmtBytes(Number(big.n))} fits inside the target packet limit of ${fmtBytes(packet)}`);
  }

  const counts = {};
  let totalRows = 0;
  const occupied = [];
  for (const t of tables) {
    const [[c]] = await source.query(`SELECT COUNT(*) AS n FROM \`${t}\``);
    counts[t] = Number(c.n);
    totalRows += counts[t];
    try {
      const [[d]] = await dest.query(`SELECT COUNT(*) AS n FROM \`${t}\``);
      if (Number(d.n) > 0) occupied.push(`${t} (${d.n})`);
    } catch (err) { /* no table yet, totally normal */ }
  }
  if (occupied.length && !args.force) {
    fail(`the target already holds rows in: ${occupied.join(', ')}`);
    note('point at an empty database, or pass --force to write over it');
  } else if (occupied.length) {
    note(`writing over existing rows in: ${occupied.join(', ')}`);
  } else {
    ok('the target has no rows of ours to overwrite');
  }

  // a table here the copy doesn't know about would be left behind without a word
  const [present] = await source.query('SHOW TABLES');
  const stray = leftBehind(present.map((r) => String(Object.values(r)[0])), TABLES);
  if (stray.length) {
    fail(`these tables would not be copied: ${stray.join(', ')}`);
    note('this image is older than the database, run the copy from the image the database came from');
  } else {
    ok(`all ${TABLES.length} tables are copied${args['skip-packuments'] ? ', apart from packuments as asked' : ''}`);
  }

  console.log('');
  console.log(`${totalRows} rows across ${tables.length} tables would move`);
  if (args['skip-packuments']) console.log('packuments is being left behind, it refetches on demand');

  if (problems) {
    console.log(`\n${problems} problem(s). Nothing was changed.`);
    await source.end(); await dest.end();
    process.exit(1);
  }
  if (args.check) {
    console.log('\npreflight passed. Run the same command with --run to do it.');
    await source.end(); await dest.end();
    process.exit(0);
  }

  console.log('\ncopying');
  const budget = Math.max(1, Math.floor(packet * 0.25));   // leaves plenty of room inside one packet
  await dest.query('SET FOREIGN_KEY_CHECKS = 0');
  await dest.query("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'");

  // let db.js build the schema on the target so the DDL can't drift. re-require with new env
  process.env.DB_HOST = target.host;
  process.env.DB_PORT = String(target.port);
  process.env.DB_USER = target.user;
  process.env.DB_PASSWORD = target.password;
  process.env.DB_NAME = target.database;
  if (args.ssl) process.env.DB_SSL = String(args.ssl);
  delete require.cache[require.resolve('./config')];
  delete require.cache[require.resolve('./db')];
  const targetDb = require('./db');
  await targetDb.connect();
  await targetDb.loadSchema();
  console.log('  schema built on the target');
  await targetDb.close();

  for (const t of tables) {
    if (!counts[t]) { console.log(`  ${t}: empty`); continue; }
    const [cols] = await source.query(`SHOW COLUMNS FROM \`${t}\``);
    const names = cols.map((c) => c.Field);
    const list = names.map((n) => `\`${n}\``).join(', ');

    let moved = 0;
    let batch = [];
    let bytes = 0;

    const flush = async () => {
      if (!batch.length) return;
      const marks = batch.map(() => `(${names.map(() => '?').join(', ')})`).join(', ');
      await dest.query(
        `INSERT INTO \`${t}\` (${list}) VALUES ${marks}
         ON DUPLICATE KEY UPDATE \`${names[0]}\` = VALUES(\`${names[0]}\`)`,
        batch.flat()
      );
      moved += batch.length;
      batch = []; bytes = 0;
    };

    // stream the source so a big table never sits in memory twice. RAM is not free
    const stream = source.connection.query(`SELECT ${list} FROM \`${t}\``).stream();
    for await (const row of stream) {
      const values = names.map((n) => row[n]);
      const size = values.reduce((a, v) => a + (v && v.length ? v.length : 8), 0);
      //a row bigger than the whole budget still has to go, just on its own
      if (batch.length && bytes + size > budget) await flush();
      batch.push(values);
      bytes += size;
      if (batch.length >= 500) await flush();
    }
    await flush();
    console.log(`  ${t}: ${moved} row(s)`);
  }

  await dest.query('SET FOREIGN_KEY_CHECKS = 1');

  // ------------------------------------------------------------ verify (trust, but count)
  console.log('\nverifying');
  let mismatched = 0;
  for (const t of tables) {
    const [[d]] = await dest.query(`SELECT COUNT(*) AS n FROM \`${t}\``);
    const got = Number(d.n);
    if (got !== counts[t]) {
      mismatched += 1;
      console.log(`  MISMATCH ${t}: source ${counts[t]}, target ${got}`);
    }
  }
  if (!mismatched) console.log(`  every table matches, ${totalRows} rows`);

  await source.end();
  await dest.end();

  if (mismatched) {
    console.log('\nSomething did not line up. The local database is untouched, so nothing is lost.');
    process.exit(1);
  }

  console.log(`
Done. The local database is untouched.

Next:
  1. put these in .env

     DB_HOST=${target.host}
     DB_PORT=${target.port}
     DB_NAME=${target.database}
     DB_USER=${target.user}
     DB_PASSWORD=<the password>${args.ssl ? `\n     DB_SSL=${args.ssl}` : ''}

  2. docker compose up -d

The container stops running its own database once DB_HOST is set. To go back,
empty DB_HOST and bring it up again; the local data is still there.
`);
}

main().catch((err) => {
  console.error('\nmigration failed:', err.message);
  console.error('The local database is untouched.');
  process.exit(1);
});
