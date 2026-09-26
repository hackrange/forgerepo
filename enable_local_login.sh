#!/usr/bin/env bash
#
# npm-repo local login
# Author: Tim Rice
#
# Puts the password form back on the portal login page when single sign on is
# out to lunch. For the morning the identity provider is down, the client secret
# has expired, or somebody typed the issuer wrong and hit save. It happens.
#
# With sso_only set there's no way back in through the portal, because getting
# into the portal is the exact thing that's broken. So this goes at the database
# instead, through the app's own settings, and the running server picks it up
# within thirty seconds. No restart, nobody gets logged out.
#
#   ./enable_local_login.sh                 put the password form back
#   ./enable_local_login.sh --status        say how sign in is set up, change nothing
#   ./enable_local_login.sh --off-sso       the above, plus switch sso off entirely
#   ./enable_local_login.sh --admin NAME    also clear a lockout on that account
#   ./enable_local_login.sh --name BOX      container name, for two on one host
#
# what it does NOT do is create an account or set a password. If nobody has a
# local password there's nothing to sign in with, so make an account while sso
# still works, not after it's definitely broken.
#
# Then: sign in, fix the provider, set the mode back to sso_only in Settings.

set -euo pipefail

CONTAINER="${CONTAINER_NAME:-npm-repo}"
MODE="enable"
CLEAR_USER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --status)          MODE="status"; shift ;;
        --off-sso|--disable-sso) MODE="off"; shift ;;
        --admin|--user)    CLEAR_USER="${2:-}"; shift 2 ;;
        --name)            CONTAINER="${2:-}"; shift 2 ;;
        -h|--help)         sed -n '3,25p' "$0"; exit 0 ;;
        *)                 echo "do not know what to do with: $1"; exit 1 ;;
    esac
done

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mstopped:\033[0m %s\n\n' "$*" >&2; exit 1; }

docker info >/dev/null 2>&1 || die "cannot talk to docker. Try sudo."

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    die "the container '$CONTAINER' is not running. Start it, or name it with --name."
fi

#same modules as the portal, so it lands in the audit trail. no sneaking around

NODE_SCRIPT='
const db = require("/opt/npmrepo/src/db");
const auth = require("/opt/npmrepo/src/security/auth");

(async () => {
  const mode = process.env.LL_MODE;
  const clearUser = process.env.LL_USER || "";

  await db.connect();
  await db.settings.load();

  const was = {
    enabled: db.settings.getBool("sso_enabled") ? "on" : "off",
    mode: db.settings.get("sso_mode") || "both",
    issuer: db.settings.get("oidc_issuer") || "(none)"
  };
  const locals = await db.one("SELECT COUNT(*) AS n FROM users WHERE disabled = 0");
  // the role goes in as a parameter rather than a quoted literal, because this
  // whole script is inside single quotes in the shell above
  const admins = await db.one("SELECT COUNT(*) AS n FROM users WHERE disabled = 0 AND role = ?", ["admin"]);

  console.log("WAS\t" + was.enabled + "\t" + was.mode + "\t" + was.issuer);
  console.log("USERS\t" + locals.n + "\t" + admins.n);

  if (mode !== "status") {
    await db.settings.set("sso_mode", "both");
    if (mode === "off") await db.settings.set("sso_enabled", "0");
    await db.settings.load(true);
    await auth.audit(null, "enable_local_login.sh", null, "sso.local_login",
      mode === "off" ? "sso switched off" : "password login allowed again", "run on the server");
    console.log("SET\tboth\t" + (mode === "off" ? "sso-off" : "sso-unchanged"));
  }

  if (clearUser) {
    const row = await db.one("SELECT id, username, disabled FROM users WHERE username = ?", [clearUser]);
    if (!row) {
      console.log("NOUSER\t" + clearUser);
    } else {
      await db.query(
        "UPDATE users SET failed_logins = 0, locked_until = NULL, disabled = 0 WHERE id = ?",
        [row.id]
      );
      await auth.audit(null, "enable_local_login.sh", null, "user.unlock", row.username, "run on the server");
      console.log("CLEARED\t" + row.username + "\t" + (row.disabled ? "was-disabled" : "was-enabled"));
    }
  }

  await db.close();
})().catch((err) => {
  console.error("ERR\t" + err.message);
  process.exit(1);
});
'

case "$MODE" in
    status) say "How sign in is set up on $CONTAINER" ;;
    off)    say "Putting local login back and switching single sign on off" ;;
    *)      say "Putting local login back on $CONTAINER" ;;
esac

OUTPUT=$(docker exec -e LL_MODE="$MODE" -e LL_USER="$CLEAR_USER" -i "$CONTAINER" node -e "$NODE_SCRIPT" 2>&1) || {
    printf '%s\n' "$OUTPUT" >&2
    die "could not change the setting. The output above is what the box said."
}

while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
        WAS)
            printf '    single sign on was %s, mode was %s\n' "$a" "$b"
            printf '    provider: %s\n' "$c"
            ;;
        USERS)
            printf '    accounts on this box: %s, of which admins: %s\n' "$a" "$b"
            [ "$b" = "0" ] && warn "no admin account here can hold a password, so there may be nothing to sign in as"
            ;;
        SET)
            ok "the password form is back on the login page"
            [ "$b" = "sso-off" ] && ok "single sign on is switched off as well"
            ;;
        CLEARED)  ok "cleared the lockout on $a" ;;
        NOUSER)   warn "there is no account called $a" ;;
        ERR)      die "$a" ;;
    esac
done <<< "$OUTPUT"

if [ "$MODE" = "status" ]; then
    printf '\n    nothing was changed. Run it without --status to put local login back.\n\n'
    exit 0
fi

cat <<'NOTE'

    The running server picks this up within thirty seconds. Nothing needs
    restarting and nobody has been logged out.

    Sign in with a local account, sort out the provider, and put the mode back
    to sso_only in Settings when it is working again.

NOTE
