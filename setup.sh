#!/usr/bin/env bash
#
# npm-repo installer
# Author: Tim Rice
#
# Run it on a fresh machine and it does the whole lot:
#
#   sudo ./setup.sh
#
# Installs docker if it's missing, puts the files in
# /data/docker/npm-repo, invents a strong admin password and a break glass
# key, builds the image, starts it, and waits for the database to wake up.
# Safe to run twice. Never overwrites an existing .env, never touches your data.
#
# Options (all optional):
#   --url https://npm.example.com   the address your developers will use
#   --dir /somewhere/else           install somewhere other than /data/docker/npm-repo
#   --port 4444                     host port to publish on
#   --name npm-repo                 container name, change it to run two on one box
#   --no-start                      set everything up but don't start it
#
# Moving a box that's already running onto the latest code:
#
#   sudo ./setup.sh --upgrade
#
# Pulls the branch this copy is on, rebuilds the image, restarts the
# container. This is the missing step behind the number one complaint about
# this thing: plain `docker compose up -d` reuses the image it already has, so
# new code sits in the directory and never reaches the container. Your .env,
# data and database are left alone, and the image that was running gets
# tagged npm-repo:previous so a bad upgrade can be undone.
#
#   --upgrade                       pull, rebuild, restart
#
# Building a second node against a database you already have, so both share
# rules, users and audit. That node runs no database of its own:
#
#   --db-host HOST                  outside MySQL or MariaDB, RDS included
#   --db-port 3306
#   --db-name npmrepo
#   --db-user npmrepo
#   --db-password SECRET            or set DB_PASSWORD in the environment
#   --db-ssl rds                    rds, 1 or 0. Use rds on RDS.
# joining node = no new admin, no password printed. env vars work for all of the above

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/data/docker/npm-repo}"
PUBLIC_URL="${PUBLIC_URL:-}"
DB_HOST="${DB_HOST:-}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-npmrepo}"
DB_USER="${DB_USER:-npmrepo}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_SSL="${DB_SSL:-}"
HOST_PORT="${HOST_PORT:-4444}"
CONTAINER_NAME="${CONTAINER_NAME:-npm-repo}"
REPO_URL="${REPO_URL:-https://github.com/hackrange/forgerepo.git}"
START_IT=1
UPGRADE=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --url)      PUBLIC_URL="$2"; shift 2 ;;
        --dir)      INSTALL_DIR="$2"; shift 2 ;;
        --port)     HOST_PORT="$2"; shift 2 ;;
        --name)     CONTAINER_NAME="$2"; shift 2 ;;
        --no-start) START_IT=0; shift ;;
        --upgrade)  UPGRADE=1; shift ;;
        --db-host)     DB_HOST="$2"; shift 2 ;;
        --db-port)     DB_PORT="$2"; shift 2 ;;
        --db-name)     DB_NAME="$2"; shift 2 ;;
        --db-user)     DB_USER="$2"; shift 2 ;;
        --db-password) DB_PASSWORD="$2"; shift 2 ;;
        --db-ssl)      DB_SSL="$2"; shift 2 ;;
        -h|--help)  sed -n '3,44p' "$0"; exit 0 ;;
        *)          echo "do not know what to do with: $1"; exit 1 ;;
    esac
done

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mstopped:\033[0m %s\n\n' "$*" >&2; exit 1; }

# "restarted" isn't "working", so wait for the healthcheck
wait_for_app() {
    local container="$1" label="$2" tries="${3:-90}" _i
    printf '    %s' "$label"
    for _i in $(seq 1 "$tries"); do
        if docker exec "$container" node /opt/npmrepo/src/healthcheck.js >/dev/null 2>&1; then
            printf '\n'
            return 0
        fi
        printf '.'
        sleep 2
    done
    printf '\n'
    return 1
}

#MariaDB version baked into an image, e.g. 11.8.6
image_db_version() {
    docker run --rm --network none --entrypoint mariadbd "$1" --version 2>/dev/null \
        | sed -n 's/.* Ver \([0-9][0-9.]*\).*/\1/p' | head -1
}

# mariadb version that last upgraded the data dir, empty if unknown
data_db_version() {
    local f
    for f in "$1/mysql/mariadb_upgrade_info" "$1/mysql/mysql_upgrade_info"; do
        if [ -f "$f" ]; then
            sed -n '1s/^\([0-9][0-9.]*\).*/\1/p' "$f"
            return 0
        fi
    done
}

version_newer() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

[ "$(id -u)" -eq 0 ] || die "run this as root, it has to install packages. try: sudo $0"

command -v uname >/dev/null && [ "$(uname -s)" = "Linux" ] || die "this only runs on linux"

say "Checking what is already here"

OS_ID="unknown"
OS_VER="0"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-0}"
fi
ok "running on ${PRETTY_NAME:-$OS_ID}"

# tested on ubuntu 22.04/24.04, debian + rhel family should be fine. anything else: coin toss
case "$OS_ID" in
    ubuntu)
        # sort -V, since as strings "9" beats "22", which is wrong
        if [ "$(printf '22.04\n%s\n' "$OS_VER" | sort -V | head -1)" != "22.04" ]; then
            warn "this is built for Ubuntu 22.04 LTS and newer, $OS_VER is older than that"
            warn "carrying on anyway, but docker may not install cleanly"
        else
            ok "Ubuntu $OS_VER is a supported version"
        fi
        ;;
    debian|rocky|almalinux|rhel|centos|fedora)
        ok "$OS_ID is not what this was tested on, but the steps are the same"
        ;;
    *)
        warn "never tested on $OS_ID, carrying on and hoping for the best"
        ;;
esac

for tool in tr head fold shuf sha256sum tar sed grep; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool, install coreutils and try again"
done
[ -r /proc/sys/kernel/random/uuid ] || die "cannot read /proc/sys/kernel/random/uuid, is /proc mounted?"

install_docker() {
    say "Installing docker"

    # official script, brings the compose plugin too
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    elif command -v wget >/dev/null 2>&1; then
        wget -qO /tmp/get-docker.sh https://get.docker.com
    else
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y -qq curl ca-certificates
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q curl ca-certificates
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q curl ca-certificates
        else
            die "no curl and no wget, and I do not recognize this package manager"
        fi
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    fi

    sh /tmp/get-docker.sh >/dev/null 2>&1 || die "the docker install script failed, try running it by hand: sh /tmp/get-docker.sh"
    rm -f /tmp/get-docker.sh
    ok "docker installed"
}

if command -v docker >/dev/null 2>&1; then
    ok "docker is already here ($(docker --version | cut -d, -f1))"
else
    install_docker
fi

#compose v2 plugin, the old standalone one won't cut it
if docker compose version >/dev/null 2>&1; then
    ok "docker compose is already here ($(docker compose version --short 2>/dev/null || echo v2))"
else
    say "Installing the docker compose plugin"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq docker-compose-plugin
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q docker-compose-plugin
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q docker-compose-plugin
    else
        install_docker
    fi
    docker compose version >/dev/null 2>&1 || die "could not get docker compose working"
    ok "docker compose installed"
fi

if ! docker info >/dev/null 2>&1; then
    say "Starting the docker daemon"
    systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
    docker info >/dev/null 2>&1 || die "docker is installed but the daemon will not start. check: systemctl status docker"
    ok "docker is running"
else
    systemctl enable docker >/dev/null 2>&1 || true
    ok "docker daemon is running"
fi

# ---------------------------------------------------------------- upgrade

# plain `up -d` reuses the old image and there's nothing to pull, so rebuild.
# never touches .env, data/ or local edits
upgrade() {
    local dir="" branch before after image_tag image_name container prev_name
    local running_image="" new_image data_src="" db_host data_ver="" new_db="" prev_db="" db_move=0

    if [ -f "$SCRIPT_DIR/docker-compose.yml" ] && [ -f "$SCRIPT_DIR/.env" ]; then
        dir="$SCRIPT_DIR"
    elif [ -f "$INSTALL_DIR/docker-compose.yml" ] && [ -f "$INSTALL_DIR/.env" ]; then
        dir="$INSTALL_DIR"
    else
        die "no installed copy here. --upgrade works on a box this script has already set up, and wants the .env that goes with it. run without --upgrade to install one"
    fi

    cd "$dir"
    say "Upgrading the copy in $dir"

    # || true: a missing key + pipefail would kill the script. strips hand-edit junk too
    container=$(grep -E '^CONTAINER_NAME=' .env | cut -d= -f2- | tr -d "\"' \r\t" || true)
    container="${container:-npm-repo}"
    image_tag=$(grep -E '^IMAGE_TAG=' .env | cut -d= -f2- | tr -d "\"' \r\t" || true)
    image_tag="${image_tag:-latest}"
    image_name="npm-repo:${image_tag}"
    if [ "$image_tag" = "latest" ]; then prev_name="npm-repo:previous"; else prev_name="npm-repo:${image_tag}-previous"; fi
    db_host=$(grep -E '^DB_HOST=' .env | cut -d= -f2- | tr -d "\"' \r\t" || true)

    if [ -d .git ]; then
        command -v git >/dev/null 2>&1 || die "this is a git checkout but there is no git here to update it with"

        # tracked only, a stray csv isn't a reason to refuse
        if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
            git status --short --untracked-files=no | head -10 | sed 's/^/        /'
            die "there are local changes in $dir. commit or stash them first, an upgrade is not going to write over them"
        fi

        branch=$(git rev-parse --abbrev-ref HEAD)
        before=$(git rev-parse HEAD)

        git fetch --prune origin >/tmp/npm-repo-upgrade.log 2>&1 \
            || { tail -5 /tmp/npm-repo-upgrade.log | sed 's/^/        /'; die "could not reach the git remote. the log is in /tmp/npm-repo-upgrade.log"; }

        git rev-parse --verify --quiet "origin/${branch}" >/dev/null \
            || die "the branch here is ${branch} and the remote has no origin/${branch} to pull from"

        # ff only, nobody wants surprise merge commits
        if ! git merge --ff-only "origin/${branch}" >>/tmp/npm-repo-upgrade.log 2>&1; then
            tail -5 /tmp/npm-repo-upgrade.log | sed 's/^/        /'
            die "cannot fast forward ${branch} onto origin/${branch}. sort the history out by hand, then run this again"
        fi

        after=$(git rev-parse HEAD)
        if [ "$before" = "$after" ]; then
            ok "already on the latest ${branch} ($(git rev-parse --short HEAD))"
        else
            ok "${branch} moved from $(git rev-parse --short "$before") to $(git rev-parse --short "$after")"
            git log --oneline "${before}..${after}" | head -20 | sed 's/^/        /'
        fi
    else
        warn "$dir is not a git checkout, fetching a fresh copy instead"
        command -v git >/dev/null 2>&1 || die "no git here, and without it there is nothing to fetch with"
        local tmp
        tmp="$(mktemp -d)"
        if git clone "$REPO_URL" "$tmp/repo" >"$tmp/clone.log" 2>&1; then
            tar cf - -C "$tmp/repo" --exclude=./.git --exclude=./.env --exclude=./data . | tar xf - -C "$dir"
            ok "fetched a fresh copy over the top, .env and data left alone"
            rm -rf "$tmp"
        else
            sed -E 's#(://[^:]+):[^@]+@#\1:***@#' "$tmp/clone.log" | tail -5 | sed 's/^/        /'
            rm -rf "$tmp"
            die "could not fetch $REPO_URL"
        fi
    fi

    # tag what's ACTUALLY running as the rollback, so a rerun after a half-dead
    # upgrade doesn't file the new image as the old one
    running_image=$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null || true)
    if [ -n "$running_image" ]; then
        docker tag "$running_image" "$prev_name" >/dev/null 2>&1 \
            && ok "the image running now is tagged $prev_name" \
            || warn "could not tag the current image, carrying on without a rollback tag"
    elif docker image inspect "$image_name" >/dev/null 2>&1; then
        docker tag "$image_name" "$prev_name" >/dev/null 2>&1 \
            && ok "the image here is tagged $prev_name" \
            || warn "could not tag the current image, carrying on without a rollback tag"
    fi

    say "Rebuilding the image"
    if ! docker compose build >/tmp/npm-repo-build.log 2>&1; then
        warn "the build failed, last few lines:"
        tail -15 /tmp/npm-repo-build.log | sed 's/^/        /'
        die "build failed and nothing was restarted, so you are still running what you were. the whole log is in /tmp/npm-repo-build.log"
    fi
    ok "image built"
    new_image=$(docker image inspect -f '{{.Id}}' "$image_name")

    # new image may bring a newer mariadb. check HERE, while the old one still runs:
    # server not older than the data, and room for the backup
    if [ -z "$db_host" ] && [ "$running_image" != "$new_image" ]; then
        data_src=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$container" 2>/dev/null || true)
        if [ -n "$data_src" ] && [ -d "$data_src/mysql" ]; then
            data_ver=$(data_db_version "$data_src")
            new_db=$(image_db_version "$image_name")
            if [ -n "$data_ver" ] && [ -n "$new_db" ]; then
                if version_newer "$data_ver" "$new_db"; then
                    die "the database was last upgraded by MariaDB $data_ver, and the image just built carries $new_db, which is older and cannot open it. nothing was stopped, the running container is untouched"
                fi
                if version_newer "$new_db" "$data_ver"; then
                    db_move=1
                    say "Checking the database move from MariaDB $data_ver to $new_db"
                    local need avail
                    need=$(du -sb "$data_src/mysql" 2>/dev/null | cut -f1)
                    avail=$(df -B1 --output=avail "$data_src" 2>/dev/null | tail -1 | tr -d ' ')
                    if [ -n "$need" ] && [ -n "$avail" ] && [ "$avail" -lt $((need + 1073741824)) ]; then
                        die "the database is $((need / 1048576)) MB and the upgrade backs it up first, but there is only $((avail / 1048576)) MB free where the data lives. free up at least $(((need + 1073741824 - avail) / 1048576)) MB and run this again. nothing was stopped, the running container is untouched"
                    fi
                    ok "there is room for the backup ($((avail / 1048576)) MB free, the database is $((need / 1048576)) MB)"
                    warn "the data will be upgraded to MariaDB $new_db, and the image before this one cannot open it afterward"
                    warn "going back means restoring the backup, not retagging $prev_name. README.md covers it"
                fi
            fi
        fi
    fi

    # stop with a long grace period, crash recovery right before an upgrade is a bad idea
    if [ -n "$running_image" ] && [ "$running_image" != "$new_image" ] \
        && [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ]; then
        say "Stopping the old container"
        if ! docker stop -t 120 "$container" >/tmp/npm-repo-stop.log 2>&1; then
            tail -5 /tmp/npm-repo-stop.log | sed 's/^/        /'
            die "could not stop $container cleanly. nothing new was started"
        fi
        ok "stopped, the database shut down cleanly"
    fi

    # up -d, NOT restart. restart keeps the old image, the exact bug we're fixing
    say "Starting the new image"
    if ! docker compose up -d >/tmp/npm-repo-start.log 2>&1; then
        warn "it would not start, last few lines:"
        tail -15 /tmp/npm-repo-start.log | sed 's/^/        /'
        die "could not start. $(rollback_advice)"
    fi

    if [ "$db_move" = "1" ]; then
        wait_for_db_move "$container" || {
            warn "the database move did not finish. the last few log lines:"
            docker logs --tail 25 "$container" 2>&1 | grep -v '\[Note\]' | tail -15 | sed 's/^/        /'
            # stop the retry loop so the data holds still under the advice
            docker update --restart=no "$container" >/dev/null 2>&1 || true
            docker stop -t 120 "$container" >/dev/null 2>&1 || true
            warn "the container is stopped so it does not keep retrying while you look"
            die "$(rollback_advice)"
        }
    fi

    wait_for_app "$container" "waiting for it to answer" 90 || {
        warn "it is not answering. the last few log lines:"
        docker compose logs --tail 15 2>/dev/null | sed 's/^/        /'
        die "upgraded but not healthy. $(rollback_advice)"
    }
    ok "the app is answering"

    ok "the schema was brought up to date on boot, there is no migration to run"

    cat <<UPGRADED

$(printf '\033[1;32m')npm-repo is up to date and running.$(printf '\033[0m')

  Directory   ${dir}
  Version     $([ -d .git ] && git log -1 --format='%h %s' | cut -c1-70 || echo 'not a git checkout')
  Rollback    $(rollback_advice)

$(if [ "$db_move" = "1" ]; then
    echo "  The database was upgraded from MariaDB $data_ver to $new_db. The backup taken"
    echo "  before it is $(latest_db_backup)"
    echo "  Your .env and everything else in the data directory were not touched."
else
    echo "  Your .env, your data directory and your database were not touched."
fi)
  Give the portal a hard refresh, the old page is cached for five minutes.

UPGRADED
}

latest_db_backup() {
    ls -1t "$data_src"/backups/before-mariadb-*.sql.gz 2>/dev/null | head -1
}

# retag only while the old image can still read the data. once upgraded, restore the backup
rollback_advice() {
    local now_ver
    [ -n "$data_src" ] || { echo "put the old one back with: docker tag $prev_name ${image_name} && docker compose up -d"; return; }
    now_ver=$(data_db_version "$data_src")
    prev_db=${prev_db:-$(image_db_version "$prev_name")}
    if [ -n "$now_ver" ] && [ -n "$prev_db" ] && version_newer "$now_ver" "$prev_db"; then
        echo "the database is now on MariaDB $now_ver, which the previous image ($prev_db) cannot open, so do not retag $prev_name over it. the way back is restoring $(latest_db_backup || true), as README.md describes under 'Moving to Ubuntu 26.04 and MariaDB 11.8'"
    else
        echo "the database has not been upgraded, so the old one goes back with: docker tag $prev_name ${image_name} && docker compose up -d"
    fi
}

# No timeout on purpose. giving up mid-backup and rolling back on top is the one
# thing that does real damage
wait_for_db_move() {
    local container="$1" logs shown=0 total
    printf '    following the database backup and upgrade\n'
    while :; do
        logs=$(docker logs "$container" 2>&1 | grep '^\[entrypoint\]' || true)
        # everything since last look, not just the newest line
        total=$(printf '%s\n' "$logs" | grep -c . || true)
        if [ "$total" -gt "$shown" ]; then
            printf '%s\n' "$logs" | tail -n $((total - shown)) | sed 's/^\[entrypoint\] /        /'
            shown=$total
        fi
        if printf '%s\n' "$logs" | grep -qE 'backup failed|upgrade failed|will not open it|stopped before it was ready|still not ready after'; then
            return 1
        fi
        if printf '%s\n' "$logs" | grep -q 'handing off to supervisor'; then
            return 0
        fi
        if [ "$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)" != "running" ] \
            && ! printf '%s\n' "$logs" | grep -q 'backing up\|upgrading'; then
            return 1
        fi
        sleep 5
    done
}

# ClamAV hangs now and then, still running but not answering. docker restarts a
# container that exits, not one that's stuck, and the app has no business with
# the docker socket (that's root on the host). so a timer out here on the host
# restarts it when its own healthcheck says unhealthy, at most every 10 minutes
clamav_watchdog() {
    local envfile="" name profiles
    for envfile in "$SCRIPT_DIR/.env" "$INSTALL_DIR/.env" ""; do
        [ -z "$envfile" ] || [ -f "$envfile" ] && break
    done
    [ -n "$envfile" ] || return 0
    name=$(grep -E '^CLAMAV_CONTAINER_NAME=' "$envfile" | tail -1 | cut -d= -f2- | tr -d "\"' \r\t" || true)
    name=${name:-clamav}
    profiles=$(grep -E '^COMPOSE_PROFILES=' "$envfile" | tail -1 | cut -d= -f2- | tr -d "\"' \r\t" || true)
    if ! printf '%s' "$profiles" | grep -qw clamav && ! docker inspect "$name" >/dev/null 2>&1; then
        return 0
    fi
    say "ClamAV watchdog"
    if ! [ -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
        warn "no systemd here, so nothing restarts ClamAV if it hangs. restart it with: docker restart $name"
        return 0
    fi
    if ! printf '%s' "$name" | grep -qE '^[A-Za-z0-9][A-Za-z0-9_.-]*$'; then
        warn "CLAMAV_CONTAINER_NAME is not a plain container name, leaving the watchdog out"
        return 0
    fi

    # nothing in here may stop the install. the app is already up and the rest of setup still has work to do
    if ! {
    cat > /usr/local/sbin/forgerepo-clamav-watchdog.new <<'WATCHDOG' &&
#!/bin/sh
# restarts a ClamAV container its healthcheck calls unhealthy. written by ForgeRepo's setup.sh
set -eu
name="$1"
command -v docker >/dev/null 2>&1 || exit 0
health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$name" 2>/dev/null) || exit 0
[ "$health" = "unhealthy" ] || exit 0
state="/run/forgerepo-clamav-watchdog-$name.last"
now=$(date +%s)
last=$(cat "$state" 2>/dev/null || echo 0)
if [ $((now - last)) -lt 600 ]; then
    logger -t forgerepo-clamav-watchdog "$name is still unhealthy, restarted less than 10 minutes ago, leaving it"
    exit 0
fi
echo "$now" > "$state"
logger -t forgerepo-clamav-watchdog "$name stopped answering, restarting it"
docker restart "$name" >/dev/null
WATCHDOG
    chmod 755 /usr/local/sbin/forgerepo-clamav-watchdog.new &&
    mv /usr/local/sbin/forgerepo-clamav-watchdog.new /usr/local/sbin/forgerepo-clamav-watchdog &&

    cat > /etc/systemd/system/forgerepo-clamav-watchdog@.service <<'UNIT' &&
[Unit]
Description=Restart the ClamAV container %i if it stops answering
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/forgerepo-clamav-watchdog %i
UNIT
    cat > /etc/systemd/system/forgerepo-clamav-watchdog@.timer <<'UNIT' &&
[Unit]
Description=Check the ClamAV container %i every minute

[Timer]
OnBootSec=5min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    } 2>/dev/null; then
        rm -f /usr/local/sbin/forgerepo-clamav-watchdog.new
        warn "could not install the ClamAV watchdog, ClamAV is not watched. restart it with: docker restart $name"
        return 0
    fi
    if systemctl enable --now "forgerepo-clamav-watchdog@${name}.timer" >/dev/null 2>&1; then
        ok "checks $name every minute and restarts it if it hangs (journalctl -t forgerepo-clamav-watchdog)"
    else
        warn "could not start the watchdog timer, ClamAV is not watched"
    fi
}

if [ "$UPGRADE" = "1" ]; then
    upgrade
    clamav_watchdog
    exit 0
fi

say "Putting the files in $INSTALL_DIR"

mkdir -p "$INSTALL_DIR"

if [ -f "$SCRIPT_DIR/Dockerfile" ] && [ -d "$SCRIPT_DIR/app" ]; then
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        tar cf - -C "$SCRIPT_DIR" --exclude=./data --exclude=./.git --exclude=./.env . | tar xf - -C "$INSTALL_DIR"
        ok "copied the project across"
    else
        ok "already in place"
    fi
elif [ -f "$INSTALL_DIR/Dockerfile" ]; then
    ok "project is already in $INSTALL_DIR"
else
    say "Fetching the project"
    command -v git >/dev/null 2>&1 || {
        if command -v apt-get >/dev/null 2>&1; then apt-get install -y -qq git
        elif command -v dnf >/dev/null 2>&1; then dnf install -y -q git
        elif command -v yum >/dev/null 2>&1; then yum install -y -q git
        else die "git is not installed and I cannot install it here"; fi
    }
    # clone elsewhere, git won't clone into a non-empty dir
    TMP_CLONE="$(mktemp -d)"
    if git clone "$REPO_URL" "$TMP_CLONE/repo" >"$TMP_CLONE/clone.log" 2>&1; then
        tar cf - -C "$TMP_CLONE/repo" . | tar xf - -C "$INSTALL_DIR"
        rm -rf "$TMP_CLONE"
        ok "fetched into $INSTALL_DIR"
    else
        warn "the clone failed, this is what git said:"
        sed -E 's#(://[^:]+):[^@]+@#\1:***@#' "$TMP_CLONE/clone.log" | tail -5 | sed 's/^/        /'
        rm -rf "$TMP_CLONE"
        die "could not fetch $REPO_URL. copy the files into $INSTALL_DIR by hand, then run this again"
    fi
fi

cd "$INSTALL_DIR"
[ -f Dockerfile ] || die "no Dockerfile in $INSTALL_DIR, something went wrong"

mkdir -p data/mysql data/cache data/backups
chmod 700 data/mysql
ok "data directories ready"

# passes the app's rules. no $ ` " ' \ or # so .env and shells stay happy
# looks like H394FW-7YTWX-Y38CFW-JM4S9. no 0, O, 1, I or L, so it can be
# read off the screen without guessing. same format the app makes on its own
make_password() {
    local chars='ABCDEFGHJKMNPQRSTUVWXYZ23456789' out='' n
    for n in 6 5 6 4; do
        out="${out:+$out-}$(LC_ALL=C tr -dc "$chars" </dev/urandom | head -c "$n")"
    done
    printf '%s' "$out"
}

say "Writing settings"

BREAKGLASS_UUID=""

if [ -f .env ]; then
    warn ".env already exists, leaving it exactly as it is"
    warn "delete it first if you want a fresh admin password"
    ADMIN_USER=$(grep -E '^ADMIN_USER=' .env | cut -d= -f2- || echo admin)
    ADMIN_PASSWORD=""
else
    ADMIN_USER="admin"
    ADMIN_PASSWORD="$(make_password)"

    # optional, but tarball links like a real one
    if [ -z "$PUBLIC_URL" ] && [ -t 0 ]; then
        printf '\n    What address will developers use? (https://npm.example.com)\n    Leave blank to decide later: '
        read -r PUBLIC_URL || PUBLIC_URL=""
    fi

    SECURE_COOKIES=1
    case "$PUBLIC_URL" in
        http://*) SECURE_COOKIES=0 ;;
        "")       SECURE_COOKIES=0 ;;
    esac

    cat > .env <<ENVFILE
# npm-repo settings for this server, written by setup.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# Keep this file private. It holds the first admin password.

PUBLIC_URL=${PUBLIC_URL}

ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}

# Host directory rather than a named volume, so you can back it up with
# ordinary tools. See .env.example if you would rather use a named volume.
DATA_PATH=./data

HOST_BIND=127.0.0.1
HOST_PORT=${HOST_PORT}

TRUST_PROXY=1
SECURE_COOKIES=${SECURE_COOKIES}

UPSTREAM_REGISTRY=https://registry.npmjs.org
UPSTREAM_TOKEN=

CONTAINER_NAME=${CONTAINER_NAME}
IMAGE_TAG=latest
TZ=UTC
SESSION_HOURS=12
ENVFILE

    if [ -n "$DB_HOST" ]; then
        cat >> .env <<ENVDB

# This node uses an outside database and runs none of its own.
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
ENVDB
        if [ -n "$DB_SSL" ]; then
            echo "DB_SSL=${DB_SSL}" >> .env
        fi
    fi

    chmod 600 .env
    ok "wrote .env with a fresh random admin password"
fi

if [ "$START_IT" = "0" ]; then
    say "Done, but not starting it because of --no-start"
    echo "    when you are ready:  cd $INSTALL_DIR && docker compose up -d --build"
    exit 0
fi

say "Building the image, this takes a couple of minutes the first time"
if ! docker compose build >/tmp/npm-repo-build.log 2>&1; then
    warn "the build failed, last few lines:"
    tail -15 /tmp/npm-repo-build.log | sed 's/^/        /'
    die "build failed, the whole log is in /tmp/npm-repo-build.log"
fi
ok "image built"

say "Starting it up"
if ! docker compose up -d >/tmp/npm-repo-start.log 2>&1; then
    warn "it would not start, last few lines:"
    tail -15 /tmp/npm-repo-start.log | sed 's/^/        /'
    die "could not start, try: cd $INSTALL_DIR && docker compose logs"
fi

clamav_watchdog

CONTAINER=$(grep -E '^CONTAINER_NAME=' .env | cut -d= -f2- || echo npm-repo)
CONTAINER="${CONTAINER:-npm-repo}"

# give it a minute. or three
wait_for_app "$CONTAINER" "waiting for the database" 90 \
    || die "it did not come up in three minutes. check: cd $INSTALL_DIR && docker compose logs"
ok "database is up and the app is answering"

# the printed password lives in scrollback forever, so make it one use only.
# fresh boxes only, joined nodes have no local mariadb
if [ -n "$DB_HOST" ]; then
    ok "this node uses the database at ${DB_HOST}, so accounts and keys come from there"
elif [ -n "${ADMIN_PASSWORD:-}" ]; then
    docker exec "$CONTAINER" mariadb npmrepo -e \
        "UPDATE users SET must_change_password = 1 WHERE username = '${ADMIN_USER}';" 2>/dev/null \
        && ok "the first password is one use only, the portal will ask for a new one" \
        || warn "could not set the password change flag, change the password yourself after signing in"
fi

# ---------------------------------------------------------------- break glass

# only the sha256 is stored, so this is the one moment the key exists. guard it until it's in a vault
if [ -n "$DB_HOST" ]; then
    ok "break glass keys live in the shared database, leaving them alone"
elif [ -z "$(docker exec "$CONTAINER" mariadb -N -B npmrepo -e 'SELECT COUNT(*) FROM breakglass_keys;' 2>/dev/null | tr -d '[:space:]')" ]; then
    warn "could not reach the database to make a break glass key, do it in the portal"
elif [ "$(docker exec "$CONTAINER" mariadb -N -B npmrepo -e 'SELECT COUNT(*) FROM breakglass_keys;' 2>/dev/null | tr -d '[:space:]')" = "0" ]; then
    say "Making a break glass key"
    BREAKGLASS_UUID="$(cat /proc/sys/kernel/random/uuid)"
    BG_HASH="$(printf '%s' "$BREAKGLASS_UUID" | sha256sum | cut -d' ' -f1)"
    BG_HINT="${BREAKGLASS_UUID:0:8}"

    docker exec "$CONTAINER" mariadb npmrepo -e "
        INSERT INTO breakglass_keys (label, uuid_hash, hint, max_uses, grant_minutes, expires_at)
        VALUES ('setup.sh recovery key', '${BG_HASH}', '${BG_HINT}', 0, 60, NULL);" 2>/dev/null \
        && ok "break glass key created" \
        || warn "could not create the break glass key, make one in the portal instead"

    if [ -n "$BREAKGLASS_UUID" ] && ! grep -q '^BREAKGLASS_UUID=' .env; then
        cat >> .env <<ENVBG

# Recovery key for the portal ip whitelist. If you switch the whitelist on and
# your address changes, this is how you get back in:
#
#   ${PUBLIC_URL:-https://your-host}/_admin?bgt=${BREAKGLASS_UUID}
#
# Only its hash is in the database, so this line is the only copy. Put it in a
# password manager and then delete it from here.
BREAKGLASS_UUID=${BREAKGLASS_UUID}
ENVBG
        chmod 600 .env
    fi
else
    ok "break glass key already exists, leaving it alone"
fi

# via the app, joined nodes have no local mariadb
RULES=$(docker exec "$CONTAINER" node -e '
const db=require("/opt/npmrepo/src/db");
(async()=>{try{await db.connect();const r=await db.one("SELECT COUNT(*) AS n FROM rules");process.stdout.write(String(r.n));await db.close();}catch(e){process.stdout.write("?");}})();
' 2>/dev/null | tr -d '[:space:]' || echo '?')

cat <<DONE

$(printf '\033[1;32m')npm-repo is installed and running.$(printf '\033[0m')

  Portal      ${PUBLIC_URL:-http://127.0.0.1:$HOST_PORT}/_admin/
  Registry    ${PUBLIC_URL:-http://127.0.0.1:$HOST_PORT}/
  Listening   127.0.0.1:${HOST_PORT}
  Installed   ${INSTALL_DIR}
  Rules       ${RULES} to start with

DONE

if [ -n "$DB_HOST" ]; then
    printf '  This node shares the database at %s, so it already has your\n' "$DB_HOST"
    printf '  rules, users and audit trail. Sign in with an account you already have.\n'
    printf '\n  It runs no database of its own. Point a load balancer at this node and\n  the other one and they will stay in step.\n'
    printf '\n  The tarball cache is still local to each node. That is only a cache, so a\n  miss is fetched again, but if you switch the upstream off then each node can\n  only serve what it has already pulled.\n'
elif [ -n "${ADMIN_PASSWORD:-}" ]; then
    printf '  Sign in with\n\n     user      %s\n     password  %s\n\n' "$ADMIN_USER" "$ADMIN_PASSWORD"
    printf '  That password is for the first sign in only. The portal will ask you to\n  set your own straight away, and the copy in .env stops working.\n'
else
    printf '  Sign in with the details already in %s/.env\n' "$INSTALL_DIR"
fi

if [ -n "$BREAKGLASS_UUID" ]; then
    printf '\n  Break glass key  %s\n' "$BREAKGLASS_UUID"
    printf '  Only needed if you turn on the ip whitelist and then lock yourself out.\n'
    printf '  It is written to .env as well. Move it to a password manager.\n'
fi

cat <<'NEXT'

  Next
    1. put a reverse proxy in front, there is a worked example in
       nginx/npm-repo.conf.example
    2. sign in and change the password
    3. add the packages you want to allow, or turn on Audit only mode for a
       week first and see what your teams actually pull

  Handy
    docker compose logs -f      watch it
    docker compose restart      restart it
    docker compose down         stop it, your data stays put

NEXT
