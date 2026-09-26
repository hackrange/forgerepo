#!/usr/bin/env bash
#
# npm-repo whitelist
# Author: Tim Rice
#
# Sticks an address or a network on one of the two allow lists. Yes, two. They
# are separate on purpose, and they fail in opposite directions:
#
#   admin    the management portal at /_admin. Not on this list? You get a
#            flat 404, like the portal never existed. Nothing to see here.
#   client   the registry itself, what npm clients get checked against. A
#            blocked developer gets told so, plainly, no mind games.
#
# Have it ask you everything:
#
#   ./whitelist.sh
#
# or just say it up front:
#
#   ./whitelist.sh 203.0.113.7 --admin
#   ./whitelist.sh 10.0.0.0/8 --client --label "build farm"
#   ./whitelist.sh 203.0.113.7 --both
#
# Options, all optional (hence the name):
#   --admin        the portal list
#   --client       the registry list
#   --both         both lists, for the indecisive
#   --label TEXT   what it's called in the portal
#   --name NAME    container name, if you run two on one box
#   -h, --help
#
# A bare address is stored as a single host, so 203.0.113.7 turns into
# 203.0.113.7/32, same as typing it into the portal. Adding one that's
# already on the list just re-enables it and updates the label instead of
# complaining about it. The running server notices within five seconds,
# nothing needs restarting.
#
# works the same on a node with an outside database, since it goes through
# the app instead of poking a local mariadb that might not even exist.

set -euo pipefail

CONTAINER="${CONTAINER_NAME:-npm-repo}"
TARGET=""
LABEL=""
CIDR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --admin|--portal)    TARGET="admin"; shift ;;
        --client|--registry) TARGET="client"; shift ;;
        --both)              TARGET="both"; shift ;;
        --label)             LABEL="${2:-}"; shift 2 ;;
        --name)              CONTAINER="${2:-}"; shift 2 ;;
        -h|--help)           sed -n '3,38p' "$0"; exit 0 ;;
        -*)                  echo "do not know what to do with: $1"; exit 1 ;;
        *)
            [ -n "$CIDR" ] && { echo "one address at a time, got '$CIDR' and '$1'"; exit 1; }
            CIDR="$1"; shift ;;
    esac
done

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mstopped:\033[0m %s\n\n' "$*" >&2; exit 1; }

# no tty = scripted, so fail loud instead of waiting forever. that'd be weird
need_tty() {
    [ -t 0 ] || die "$1 was not given and there is no terminal to ask on. See --help."
}

docker info >/dev/null 2>&1 || die "cannot talk to docker. Try sudo."

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    die "the container '$CONTAINER' is not running. Start it, or name it with --name."
fi

if [ -z "$CIDR" ]; then
    need_tty "an address"
    printf '\nAddress or network to allow, for example 203.0.113.7 or 10.0.0.0/8\n'
    read -r -p '  address: ' CIDR
    [ -n "$CIDR" ] || die "nothing entered."
fi

if [ -z "$TARGET" ]; then
    need_tty "a list"
    printf '\nWhich list?\n'
    printf '  1) admin   the management portal, /_admin\n'
    printf '  2) client  the registry, what npm installs from\n'
    printf '  3) both\n'
    while [ -z "$TARGET" ]; do
        read -r -p '  choice [1/2/3]: ' answer
        case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
            1|admin|portal)    TARGET="admin" ;;
            2|client|registry) TARGET="client" ;;
            3|both)            TARGET="both" ;;
            *) printf '    answer 1, 2 or 3.\n' ;;
        esac
    done
fi

LABEL="${LABEL:-added with whitelist.sh}"

# app's own modules, so parsing and audit match the portal exactly

NODE_SCRIPT='
const db = require("/opt/npmrepo/src/db");
const ipacl = require("/opt/npmrepo/src/security/network/ipacl");
const auth = require("/opt/npmrepo/src/security/auth");

const LISTS = {
  admin:  { table: "ip_acl",       flag: "acl_enabled",          action: "acl.add" },
  client: { table: "registry_acl", flag: "registry_acl_enabled", action: "registry.acl.add" }
};

(async () => {
  const raw = process.env.WL_CIDR || "";
  const cidr = ipacl.normalizeCidr(raw);
  if (!cidr) {
    console.error("BAD\t" + raw);
    process.exit(2);
  }

  const label = process.env.WL_LABEL || "";
  const actor = process.env.WL_ACTOR || "whitelist.sh";
  const which = process.env.WL_TARGET === "both" ? ["admin", "client"] : [process.env.WL_TARGET];

  await db.connect();
  await db.settings.load();

  for (const name of which) {
    const list = LISTS[name];
    const before = await db.one("SELECT COUNT(*) AS n FROM " + list.table + " WHERE enabled = 1");
    const existing = await db.one("SELECT id FROM " + list.table + " WHERE cidr = ? AND enabled = 1", [cidr]);

    await db.query(
      "INSERT INTO " + list.table + " (cidr, label, enabled, created_by) VALUES (?, ?, 1, ?) " +
      "ON DUPLICATE KEY UPDATE label = VALUES(label), enabled = 1",
      [cidr, label, actor]
    );
    await auth.audit(null, actor, null, list.action, cidr, label);

    // list-off says the whole filter is switched off, so this entry is stored
    // but decides nothing. first-entry says the list was empty, and an empty
    // list is treated as wide open, so this add is what starts the filtering.
    const state = [
      db.settings.getBool(list.flag) ? "list-on" : "list-off",
      existing ? "already" : "added",
      Number(before.n) === 0 ? "first-entry" : "joins-" + before.n
    ];
    console.log("OK\t" + name + "\t" + cidr + "\t" + state.join("\t"));
  }

  await db.close();
})().catch((err) => {
  console.error("ERR\t" + err.message);
  process.exit(1);
});
'

say "Allowing $CIDR"

set +e
OUTPUT="$(docker exec \
    -e WL_CIDR="$CIDR" \
    -e WL_TARGET="$TARGET" \
    -e WL_LABEL="$LABEL" \
    -e WL_ACTOR="whitelist.sh" \
    "$CONTAINER" node -e "$NODE_SCRIPT" 2>&1)"
STATUS=$?
set -e

if [ "$STATUS" -eq 2 ]; then
    die "\"$CIDR\" is not an address or a network. Try 203.0.113.7 or 10.0.0.0/8."
fi
if [ "$STATUS" -ne 0 ]; then
    printf '%s\n' "$OUTPUT" | sed 's/^ERR\t/    /' >&2
    die "the change was not made."
fi

while IFS=$'\t' read -r tag name cidr enabled seen size; do
    [ "$tag" = "OK" ] || continue

    if [ "$name" = "admin" ]; then
        where="the management portal"
    else
        where="the registry"
    fi

    if [ "$seen" = "already" ]; then
        ok "$cidr was already on the $name list, label updated"
    else
        ok "$cidr can now reach $where"
    fi

    [ "$enabled" = "list-off" ] && \
        warn "the $name allow list is switched off, so this entry decides nothing until you turn it on in Settings"

    [ "$size" = "first-entry" ] && [ "$enabled" = "list-on" ] && \
        warn "that was the first entry on the $name list. An empty list means anyone, so everything except $cidr has just lost access to $where"
done <<< "$OUTPUT"

printf '\n    The running server picks this up within five seconds.\n\n'
