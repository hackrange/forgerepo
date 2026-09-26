#!/bin/bash
# sets up the data dirs and db on first boot, then hands off to supervisor. rerun safe
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
DB_NAME="${DB_NAME:-npmrepo}"
DB_USER="${DB_USER:-npmrepo}"
CREDS_FILE="$DATA_DIR/.dbcreds.json"
SOCKET="/run/mysqld/mysqld.sock"

log() {
    echo "[entrypoint] $*"
}

# without this set -e dies silently and the container restart-loops with an empty log. ask me how I know
trap 'log "stopped: the command at line $LINENO of the entrypoint failed"' ERR

# older images ran as root (yikes), so hand any leftover cache to the app user
own_cache() {
    mkdir -p "$DATA_DIR/cache"
    chown forgerepo:forgerepo "$DATA_DIR/cache"
    find "$DATA_DIR/cache" ! -user forgerepo -exec chown forgerepo:forgerepo {} + 2>/dev/null || true
}

# DB_HOST empty = local db on a socket. set = outside server, no mariadbd here
#LOCAL_DB is read by supervisord.conf via %(ENV_LOCAL_DB)s
if [ -n "${DB_HOST:-}" ]; then
    export LOCAL_DB=false
    log "DB_HOST is set to ${DB_HOST}, using an outside database"
    log "the built in database will not be started"

    mkdir -p "$DATA_DIR/cache" "$DATA_DIR/backups"
    own_cache

    if [ -z "${DB_PASSWORD:-}" ]; then
        log "warning: DB_HOST is set but DB_PASSWORD is empty"
    fi
    # config.js ignores old local creds here, but say so before someone thinks they're live
    if [ -f "$CREDS_FILE" ]; then
        log "note: $CREDS_FILE is from the built in database and is not used in this mode"
    fi

    log "handing off to supervisor"
    exec "$@"
fi

export LOCAL_DB=true

mkdir -p "$DATA_DIR/mysql" "$DATA_DIR/cache" "$DATA_DIR/backups" /run/mysqld
chown -R mysql:mysql "$DATA_DIR/mysql" /run/mysqld
chmod 700 "$DATA_DIR/mysql"
own_cache

FRESH_DB=0

if [ ! -d "$DATA_DIR/mysql/mysql" ]; then
    log "no database found, creating one in $DATA_DIR/mysql"
    mariadb-install-db --user=mysql --datadir="$DATA_DIR/mysql" --auth-root-authentication-method=socket >/dev/null
    FRESH_DB=1
fi

if [ ! -f "$CREDS_FILE" ]; then
    if [ -n "${DB_PASSWORD:-}" ]; then
        GEN_PASS="$DB_PASSWORD"
    else
        GEN_PASS="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    fi
    printf '{"host":"","socketPath":"%s","user":"%s","password":"%s","database":"%s"}\n' \
        "$SOCKET" "$DB_USER" "$GEN_PASS" "$DB_NAME" > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
    NEED_GRANT=1
    log "wrote new database credentials to $CREDS_FILE"
else
    NEED_GRANT=0
fi

#app reads the creds, nobody else
chown root:forgerepo "$CREDS_FILE"
chmod 640 "$CREDS_FILE"

# Newer server than the data: upgrade once, here. Older server: stop. an old
# mariadb on upgraded data wrecks it, so rollback = restore a backup, not retag
NEED_UPGRADE=0
DATA_VERSION=""
SERVER_VERSION="$(mariadbd --version 2>/dev/null | sed -n 's/.* Ver \([0-9][0-9.]*\).*/\1/p' | head -1)"
if [ "$FRESH_DB" = "0" ]; then
    for f in "$DATA_DIR/mysql/mariadb_upgrade_info" "$DATA_DIR/mysql/mysql_upgrade_info"; do
        if [ -z "$DATA_VERSION" ] && [ -f "$f" ]; then
            DATA_VERSION="$(sed -n '1s/^\([0-9][0-9.]*\).*/\1/p' "$f")"
        fi
    done
    if [ -z "$DATA_VERSION" ]; then
        # no version on record = an upgrade died half way (mariadb-upgrade empties the
        # file first). run it again after a backup rather than live on half upgraded tables
        DATA_VERSION="unknown"
        NEED_UPGRADE=1
        log "the database in $DATA_DIR/mysql has no MariaDB version on record, so an earlier upgrade did not finish, and it will be run again"
    elif [ -n "$SERVER_VERSION" ] && [ "$DATA_VERSION" != "$SERVER_VERSION" ]; then
        NEWER="$(printf '%s\n%s\n' "$DATA_VERSION" "$SERVER_VERSION" | sort -V | tail -1)"
        if [ "$NEWER" = "$DATA_VERSION" ]; then
            log "the database in $DATA_DIR/mysql was last upgraded by MariaDB $DATA_VERSION"
            log "this image carries MariaDB $SERVER_VERSION, which is older, and will not open it"
            log "to go back to an older image, restore a backup taken before the upgrade into an empty data directory"
            exit 1
        fi
        NEED_UPGRADE=1
    fi
fi

# fingerprint of the data at rest. same print after a failed upgrade = reuse the
# backup instead of stacking a new one every restart. disks aren't infinite
data_fingerprint() {
    #missing files are fine, they're part of the print
    (cd "$DATA_DIR/mysql" && stat -c '%n %s %y' ib_logfile0 ibdata1 aria_log_control mariadb_upgrade_info mysql_upgrade_info 2>/dev/null || true) | sha256sum | cut -c1-32
}
PENDING="$DATA_DIR/backups/.mariadb-upgrade-pending"

if [ "$FRESH_DB" = "1" ] || [ "$NEED_GRANT" = "1" ] || [ "$NEED_UPGRADE" = "1" ]; then
    PRE_START_FINGERPRINT="$(data_fingerprint)"
    log "starting database for one time setup"
    mariadbd --defaults-file=/etc/mysql/my.cnf --user=mysql >/tmp/db-bootstrap.log 2>&1 &
    BOOT_PID=$!

    # big or crash-recovering dbs are slow to open. wait while it's alive, max 30 min
    DB_WAIT=0
    until mariadb-admin --socket="$SOCKET" ping >/dev/null 2>&1; do
        if ! kill -0 "$BOOT_PID" 2>/dev/null; then
            log "the database stopped before it was ready, here is the log:"
            cat /tmp/db-bootstrap.log
            exit 1
        fi
        DB_WAIT=$((DB_WAIT + 1))
        if [ "$DB_WAIT" -ge 1800 ]; then
            log "the database is still not ready after 30 minutes, here is the log:"
            cat /tmp/db-bootstrap.log
            kill "$BOOT_PID" 2>/dev/null || true
            wait "$BOOT_PID" 2>/dev/null || true
            exit 1
        fi
        if [ $((DB_WAIT % 30)) = 0 ]; then
            log "still waiting for the database to open, ${DB_WAIT}s so far"
        fi
        sleep 1
    done

    # wait till it lets go of the files so the fingerprint is of data at rest
    stop_setup_db() {
        mariadb-admin --socket="$SOCKET" shutdown >/dev/null 2>&1 || true
        wait "$BOOT_PID" 2>/dev/null || true
    }

    if [ "$NEED_UPGRADE" = "1" ]; then
        # say it up front, before someone panics and reaches for rollback
        if [ "$DATA_VERSION" = "unknown" ]; then
            log "finishing the upgrade of this database to MariaDB $SERVER_VERSION now"
        else
            log "this database was written by MariaDB $DATA_VERSION and this image carries $SERVER_VERSION, so it is being upgraded now"
        fi
        log "let it finish. do not start the older image on this data, and do not roll back by retagging it: see 'Moving to Ubuntu 26.04 and MariaDB 11.8' in README.md"

        # this backup is the only way back once upgraded. No copy, no upgrade. Definitely
        BACKUP=""
        if [ -f "$PENDING" ]; then
            read -r P_BACKUP P_FROM P_TO P_FINGERPRINT < "$PENDING" || true
            if [ "${P_FROM:-}" = "$DATA_VERSION" ] && [ "${P_TO:-}" = "$SERVER_VERSION" ] \
                && [ "${P_FINGERPRINT:-}" = "$PRE_START_FINGERPRINT" ] && [ -s "${P_BACKUP:-}" ]; then
                BACKUP="$P_BACKUP"
                log "using the backup the last attempt took, nothing has opened the database since: $BACKUP"
            fi
        fi
        if [ -z "$BACKUP" ]; then
            BACKUP="$DATA_DIR/backups/before-mariadb-$SERVER_VERSION-from-$DATA_VERSION-$(date -u +%Y%m%d-%H%M%S).sql.gz"
            mkdir -p "$DATA_DIR/backups"
            rm -f "$DATA_DIR"/backups/before-mariadb-*.sql.gz.partial
            log "backing up the database to $BACKUP before upgrading it, which takes a few minutes on a large one"
            # check for the closing "Dump completed" line, catches a full disk now not on restore day
            if ! mariadb-dump --socket="$SOCKET" --single-transaction --routines --triggers --databases "$DB_NAME" 2>/tmp/db-backup.log | gzip > "$BACKUP.partial" \
                || ! gzip -t "$BACKUP.partial" 2>>/tmp/db-backup.log \
                || ! gzip -dc "$BACKUP.partial" | tail -n 1 | grep -q '^-- Dump completed'; then
                log "the backup failed, so the database has not been upgraded and nothing was changed:"
                cat /tmp/db-backup.log
                rm -f "$BACKUP.partial"
                df -h "$DATA_DIR/backups" || true
                stop_setup_db
                exit 1
            fi
            mv "$BACKUP.partial" "$BACKUP"
            chmod 600 "$BACKUP"
            log "backup written and checked, $(du -h "$BACKUP" | cut -f1)"
        fi

        log "upgrading the database from MariaDB $DATA_VERSION to $SERVER_VERSION, once"
        if ! mariadb-upgrade --socket="$SOCKET" >/tmp/db-upgrade.log 2>&1; then
            log "the database upgrade failed, here is what it said:"
            cat /tmp/db-upgrade.log
            stop_setup_db
            printf '%s %s %s %s\n' "$BACKUP" "$DATA_VERSION" "$SERVER_VERSION" "$(data_fingerprint)" > "$PENDING"
            log "the backup taken before it is $BACKUP"
            exit 1
        fi
        rm -f "$PENDING"
        log "database upgraded to $SERVER_VERSION"
    fi

    if [ "$FRESH_DB" = "1" ] || [ "$NEED_GRANT" = "1" ]; then
        DB_PASS="$(node -e 'const c=require(process.argv[1]);process.stdout.write(c.password)' "$CREDS_FILE")"

        mariadb --socket="$SOCKET" <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
DELETE FROM mysql.global_priv WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL

        log "database and app user are ready"
    fi
    stop_setup_db
fi

log "handing off to supervisor"
exec "$@"
