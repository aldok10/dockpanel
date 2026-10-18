#!/usr/bin/env bash
#
# Regression pins for per-user OS (SSH) login accounts.
#
# An administrator may give a panel user a Linux login name; the agent creates
# the matching account so the person can sign in over SSH. Two properties are
# load-bearing and easy to undo by accident:
#
#   * NO PRIVILEGE. The account must never be added to sudo/wheel. A careless
#     `-aG sudo` here would turn every panel user who has a login into a root
#     user on the box. This suite fails if that ever appears.
#   * ONE CREDENTIAL. Every door that changes a panel password (admin reset,
#     self-service change, forgot-password, reseller reset) must also move the
#     SSH password, or an old password keeps working over SSH after the user
#     believes they rotated it.
#
# It also pins that the account is optional (NULL for panel-only users), that a
# name can never collide with an existing/service account, and that the OS
# commands run through the unsandboxed escape (`/etc/passwd` lives outside the
# agent unit's ReadWritePaths, so a sandboxed `useradd` fails with EROFS).
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

SVC=panel/agent/src/services/os_accounts.rs
SVC_MOD=panel/agent/src/services/mod.rs
AGENT_ROUTE=panel/agent/src/routes/os_users.rs
AGENT_MOD=panel/agent/src/routes/mod.rs
AGENT_MAIN=panel/agent/src/main.rs
BACKEND=panel/backend/src/routes/users.rs
AUTH=panel/backend/src/routes/auth.rs
RESELLER=panel/backend/src/routes/reseller_dashboard.rs
MIGRATION=panel/backend/migrations/20261017000000_user_os_accounts.sql
FRONTEND=panel/frontend/src/pages/Users.tsx

for f in "$SVC" "$SVC_MOD" "$AGENT_ROUTE" "$AGENT_MOD" "$AGENT_MAIN" \
         "$BACKEND" "$AUTH" "$RESELLER" "$MIGRATION" "$FRONTEND"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo
echo "── 1. the agent can create, secure and remove the account ──"

if grep -q 'useradd' "$SVC" && grep -q '"-m"' "$SVC"; then
  ok "provision runs useradd -m (a real account with a home directory)"
else
  bad "os_accounts.rs no longer runs useradd -m — the SSH account has no home"
fi

# A login shell, never nologin: the whole point is interactive SSH. The
# candidate list is pinned by name so a regression that reaches for `nologin`
# is caught here rather than only on a box.
if grep -qE '"/bin/(bash|ash|sh)"' "$SVC"; then
  ok "provision picks a real login shell (bash/ash/sh)"
else
  bad "the login-shell candidates changed — check it is not a nologin shell"
fi

if grep -q 'ShaCrypt' "$SVC" && ! grep -q '"chpasswd"' "$SVC"; then
  ok "the OS password is hashed in-process (SHA-512-crypt), never piped as plaintext"
else
  bad "the password path changed — plaintext chpasswd must not be used"
fi

if grep -q 'userdel' "$SVC" && grep -q '"-r"' "$SVC"; then
  ok "deprovision removes the account and its home (userdel -r)"
else
  bad "deprovision no longer runs userdel -r — a home directory would be orphaned"
fi

# THE POLICY. Positive control first: the file is readable and mentions a
# privilege-adjacent word ("sudo") in prose, so the absence check below is a real
# absence and not a broken grep.
if grep -q 'sudo' "$SVC"; then
  ok "os_accounts.rs is readable and discusses privilege (control for the next check)"
else
  bad "positive control failed — os_accounts.rs does not mention 'sudo' at all"
fi
if ! grep -qE '"-aG"|"sudo"|"wheel"' "$SVC"; then
  ok "no command adds the account to sudo/wheel — the no-privilege policy holds"
else
  bad "os_accounts.rs passes sudo/wheel to a command — panel users would get root"
fi

if grep -qE 'account_exists|id", &\[\]' "$SVC"; then
  ok "provision refuses a name that already exists on the box (id -u check)"
else
  bad "the existing-account check is gone — useradd could target root or a service account"
fi

if grep -q 'is_reserved_username' "$SVC"; then
  ok "the reserved system/service names are refused"
else
  bad "the reserved-name refusal is gone"
fi

if grep -q 'safe_command_unsandboxed' "$SVC"; then
  ok "useradd/usermod/userdel run through the unsandboxed escape (they write /etc/passwd)"
else
  bad "the OS commands are no longer unsandboxed — they would fail with EROFS on every install"
fi

echo
echo "── 2. the agent exposes the routes and wires them in ──"

for path in '/os-users/provision' '/os-users/password' '/os-users/state' '/os-users/{username}'; do
  if grep -qF "\"$path\"" "$AGENT_ROUTE"; then
    ok "agent route $path is registered"
  else
    bad "agent route $path is missing from os_users.rs"
  fi
done

if grep -q 'pub mod os_users;' "$AGENT_MOD"; then
  ok "routes::os_users is declared"
else
  bad "os_users is not declared in routes/mod.rs"
fi

if grep -q 'routes::os_users::router()' "$AGENT_MAIN"; then
  ok "the os_users router is merged into the agent app"
else
  bad "the os_users router is not merged in main.rs — the routes would 404"
fi

if grep -q 'pub mod os_accounts;' "$SVC_MOD"; then
  ok "services::os_accounts is declared"
else
  bad "os_accounts is not declared in services/mod.rs"
fi

echo
echo "── 3. the panel carries the login name and drives the lifecycle ──"

if grep -qE 'ADD COLUMN os_username' "$MIGRATION"; then
  ok "migration adds users.os_username"
else
  bad "migration does not add os_username"
fi

if grep -q 'UNIQUE INDEX' "$MIGRATION" && grep -q 'WHERE os_username IS NOT NULL' "$MIGRATION"; then
  ok "os_username is unique among non-null rows (partial index)"
else
  bad "the partial unique index on os_username is missing — two users could claim one login"
fi

if grep -q 'os_username: Option<String>' "$BACKEND"; then
  ok "CreateUserRequest accepts an optional os_username"
else
  bad "CreateUserRequest no longer carries os_username"
fi

if grep -q '/os-users/provision' "$BACKEND"; then
  ok "create/update provision the SSH account through the agent"
else
  bad "the panel never calls /os-users/provision — no OS account would be created"
fi

# The rollback: a failed provision must not leave a panel user whose promised
# login does not exist.
if grep -q 'could not be provisioned' "$BACKEND" && grep -q 'DELETE FROM users WHERE id = \$1' "$BACKEND"; then
  ok "create rolls the panel row back when the SSH account cannot be provisioned"
else
  bad "no rollback on a failed provision — a panel user could exist with no SSH login"
fi

if grep -q 'sync_ssh_password' "$BACKEND"; then
  ok "the shared password sync helper exists in users.rs"
else
  bad "sync_ssh_password is gone"
fi

# Every door that changes a panel password must move the SSH one too.
for f in "$AUTH" "$RESELLER"; do
  if grep -q 'sync_ssh_password' "$f"; then
    ok "$(basename "$f") mirrors password changes onto the SSH login"
  else
    bad "$(basename "$f") changes a panel password without touching the SSH login — it would go stale"
  fi
done

# Count the calls in auth.rs: change-password AND reset-confirm are two doors.
AUTH_CALLS=$(grep -c 'sync_ssh_password' "$AUTH")
if [ "$AUTH_CALLS" -ge 2 ]; then
  ok "auth.rs syncs on both self-service change and forgot-password reset ($AUTH_CALLS call sites)"
else
  bad "auth.rs syncs the SSH password at only $AUTH_CALLS door(s) — one is missing"
fi

if grep -q '/os-users/state' "$BACKEND"; then
  ok "suspend/unsuspend locks the SSH account password"
else
  bad "toggle-suspend no longer locks the SSH account"
fi

if grep -q '/os-users/' "$BACKEND" && grep -q '\.delete(' "$BACKEND"; then
  ok "delete removes the SSH account"
else
  bad "user delete no longer removes the SSH account"
fi

if grep -q 'u.os_username' "$BACKEND"; then
  ok "the user list selects os_username so the table can show it"
else
  bad "os_username is not selected in the user list"
fi

echo
echo "── 4. the create screen offers the field ──"

if grep -q 'os_username' "$FRONTEND"; then
  ok "Users.tsx sends os_username when creating a user"
else
  bad "Users.tsx does not send os_username"
fi

if grep -q 'SSH Username' "$FRONTEND"; then
  ok "Users.tsx labels the SSH username field"
else
  bad "the SSH username field is not labelled in the create dialog"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
