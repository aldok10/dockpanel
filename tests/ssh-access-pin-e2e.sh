#!/usr/bin/env bash
#
# Regression pins for the SSH screen — the management surface for the Linux
# logins the panel itself created.
#
# `user-os-account-pin-e2e.sh` holds down the account lifecycle (no privilege,
# one credential, no collisions). This suite holds down the second half, the part
# an operator reaches for afterwards, and the traps that only show up once you
# are writing FILES as another user:
#
#   * FINGERPRINTS. OpenSSH strips base64 padding from a key body, so a decoder
#     that only accepts the PADDED alphabet leaves the body undecoded and hashes
#     an EMPTY buffer — still a well-formed `SHA256:…`. The remove route matches
#     on that value, so a wrong fingerprint looks exactly like a right one and
#     keys become unremovable. Pinned with a known-answer unit test.
#   * FINGERPRINTS IN PATHS. A standard-base64 fingerprint can contain `/`, which
#     would split the URL segment; the model's path writer percent-encodes it.
#   * PROTECTHOME. `~/.ssh/authorized_keys` is invisible inside the agent's
#     namespace, so the key writes must escape it — the same way `useradd` does.
#   * THE EFFECTIVE LOCK. Suspension locks SSH, but so does the SSH screen's own
#     lock, and un-suspending must NOT silently re-open SSH that was shut.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

SVC=panel/agent/src/services/os_accounts.rs
AGENT_ROUTE=panel/agent/src/routes/os_users.rs
SSH=panel/backend/src/routes/ssh.rs
ROUTES=panel/backend/src/routes/mod.rs
MODELS=panel/backend/src/models.rs
USERS=panel/backend/src/routes/users.rs
MIGRATION=panel/backend/migrations/20261018000000_user_os_locked.sql
NAV=panel/frontend/src/data/navItems.ts
MAIN=panel/frontend/src/main.tsx
PAGE=panel/frontend/src/pages/Ssh.tsx

for f in "$SVC" "$AGENT_ROUTE" "$SSH" "$ROUTES" "$MODELS" "$USERS" \
         "$MIGRATION" "$NAV" "$MAIN" "$PAGE"; do
  [ -f "$f" ] || { echo "missing source file: $f"; exit 1; }
done

echo
echo "── 1. the agent manages an account's authorized_keys ──"

if grep -q 'STANDARD_NO_PAD' "$SVC"; then
  ok "the fingerprint decoder falls back to the unpadded base64 alphabet (OpenSSH strips '=')"
else
  bad "fingerprint_of only accepts padded base64 — an unpadded body hashes empty and the key cannot be removed"
fi

if grep -q 'fingerprints_match_openssh' "$SVC"; then
  ok "a known-answer test pins the fingerprint against ssh-keygen's value"
else
  bad "the known-answer fingerprint test is gone — the empty-buffer trap is unpinned"
fi

if grep -q 'SSH key options are not allowed' "$SVC" && grep -q 'command=' "$SVC"; then
  ok "keys with authorized_keys options are refused (a key cannot pin the login to one program)"
else
  bad "the authorized_keys-options refusal is gone"
fi

# Not `/home/<name>` by assumption: useradd's base dir comes from login.defs, and
# a wrong guess writes a file sshd never reads.
if grep -q '"/etc/passwd"' "$SVC"; then
  ok "the home directory is resolved from the passwd entry, not assumed"
else
  bad "home_dir no longer reads /etc/passwd — a custom home would orphan the key file"
fi

if grep -q 'safe_command_unsandboxed("install"' "$SVC"; then
  ok "key files are written through the unsandboxed escape (ProtectHome hides /home)"
else
  bad "the key write no longer escapes the sandbox — it would fail with EROFS on every install"
fi

if grep -q '"-m", "700", "-o"' "$SVC"; then
  ok ".ssh is created mode 700 and owned by the account (sshd StrictModes)"
else
  bad ".ssh is no longer created 700/owned by the user — sshd would refuse the login"
fi

if grep -q '"-m", "600", "-o"' "$SVC"; then
  ok "authorized_keys is installed mode 600 and owned by the account"
else
  bad "authorized_keys mode/owner changed — sshd StrictModes would refuse it"
fi

# A typed-wrong key or a bad name is the caller's mistake and must answer 400;
# only a box failure is a 500. A bare String error collapses the two.
if grep -q 'enum KeyError' "$SVC" && grep -q 'KeyError::Client' "$SVC" && grep -q 'KeyError::Server' "$SVC"; then
  ok "key errors are split into client (400) and server (500) arms"
else
  bad "KeyError no longer distinguishes a typo from a box failure — a 400 would render as an incident id"
fi

# The no-privilege policy from the sibling suite, re-checked here because this
# module now writes files and a careless install could have smuggled a group in.
if ! grep -qE '"-aG"|"sudo"|"wheel"' "$SVC"; then
  ok "no key path adds the account to sudo/wheel — the no-privilege policy still holds"
else
  bad "a privilege-adjacent group appears in os_accounts.rs — panel users would get root"
fi

echo
echo "── 2. the agent exposes and classifies the key routes ──"

for path in '/os-users/{username}/keys' '/os-users/{username}/keys/{fingerprint}'; do
  if grep -qF "\"$path\"" "$AGENT_ROUTE"; then
    ok "agent route $path is registered"
  else
    bad "agent route $path is missing from os_users.rs"
  fi
done

if grep -q 'KeyError::Client(m) => err(StatusCode::BAD_REQUEST' "$AGENT_ROUTE"; then
  ok "a client key error answers 400"
else
  bad "the client key error no longer maps to 400"
fi

if grep -q 'KeyError::Server(m) => err(StatusCode::INTERNAL_SERVER_ERROR' "$AGENT_ROUTE"; then
  ok "a server key error answers 500"
else
  bad "the server key error no longer maps to 500"
fi

echo
echo "── 3. the panel module drives the accounts and keys ──"

if grep -q 'AdminUser' "$SSH"; then
  ok "the SSH module is behind the admin extractor"
else
  bad "ssh.rs does not require an AdminUser — the routes would be open"
fi

if grep -q 'os_locked' "$SSH" && grep -q 'SELECT id, email, role, os_username, os_locked' "$SSH"; then
  ok "the account list selects os_locked so the screen can show the lock"
else
  bad "the SSH account list no longer carries os_locked"
fi

if grep -q 'is_other_admin' "$SSH"; then
  ok "acts on another administrator's account are refused (peer is not subordinate)"
else
  bad "the other-admin guard is gone — an admin could manage a peer's SSH login"
fi

if grep -q 'could not be provisioned' "$SSH" && grep -q 'UPDATE users SET os_username = NULL' "$SSH"; then
  ok "attach persists the name first and rolls it back when the provision fails"
else
  bad "attach lost its rollback — a panel user could claim an SSH login that does not exist"
fi

if grep -q 'role == "suspended"' "$SSH"; then
  ok "a login attached to a suspended account is locked immediately, not left open"
else
  bad "attach no longer locks a suspended account's new SSH login"
fi

if grep -q 'Remove SSH account' "$SSH" && grep -q 'os_username = NULL' "$SSH"; then
  ok "remove takes the OS account off the box and then clears the panel record"
else
  bad "remove no longer removes the OS account before clearing the record"
fi

if grep -q 'suspended || body.locked' "$SSH"; then
  ok "the effective lock is suspended OR the explicit lock (un-suspend cannot re-open a shut login)"
else
  bad "the effective-lock rule changed — a suspend/unsuspend cycle could re-open SSH"
fi

if grep -q 'Set SSH account state' "$SSH"; then
  ok "the box is told to lock/unlock before the panel records the new state"
else
  bad "the state write no longer applies to the box before the DB"
fi

if grep -q 'fn enc_segment' "$SSH" && grep -q 'enc_segment(&fingerprint)' "$SSH"; then
  ok "the remove-key path percent-encodes the fingerprint (a base64 '/' must not split the segment)"
else
  bad "the fingerprint is no longer encoded for the agent path — keys containing '/' become unremovable"
fi

for fn in list_keys add_key remove_key; do
  if grep -q "pub async fn $fn" "$SSH"; then
    ok "handler $fn exists in the SSH module"
  else
    bad "handler $fn is missing from ssh.rs"
  fi
done

echo
echo "── 4. the routes are registered ──"

if grep -q 'pub mod ssh;' "$ROUTES"; then
  ok "routes::ssh is declared"
else
  bad "ssh is not declared in routes/mod.rs"
fi

for path in '/api/ssh/accounts' '/api/ssh/accounts/{id}' '/api/ssh/accounts/{id}/state' \
            '/api/ssh/accounts/{id}/keys' '/api/ssh/accounts/{id}/keys/{fingerprint}'; do
  if grep -qF "\"$path\"" "$ROUTES"; then
    ok "backend route $path is registered"
  else
    bad "backend route $path is missing from routes/mod.rs"
  fi
done

echo
echo "── 5. the lock state is stored and respected ──"

if grep -qE 'ADD COLUMN os_locked' "$MIGRATION"; then
  ok "migration adds users.os_locked"
else
  bad "migration does not add os_locked"
fi

if grep -q 'NOT NULL DEFAULT FALSE' "$MIGRATION"; then
  ok "os_locked defaults FALSE (existing accounts stay unlocked)"
else
  bad "os_locked is not NOT NULL DEFAULT FALSE — existing rows could be left NULL"
fi

if grep -q 'pub os_locked: bool' "$MODELS"; then
  ok "the User model carries os_locked"
else
  bad "models::User does not carry os_locked"
fi

if grep -q 'user.os_locked' "$USERS"; then
  ok "user suspension restores the explicit SSH lock instead of blindly unlocking"
else
  bad "toggle-suspend ignores os_locked — an SSH lock would be lost across a suspend cycle"
fi

echo
echo "── 6. the frontend offers the screen ──"

if grep -qE 'to: "/ssh".*adminOnly' "$NAV"; then
  ok "the SSH nav row exists and is adminOnly"
else
  bad "the SSH nav row is missing or not adminOnly"
fi

if grep -qF 'pages/Ssh' "$MAIN" && grep -qF 'path="/ssh"' "$MAIN"; then
  ok "the /ssh route renders the SSH page"
else
  bad "the /ssh route is not wired in main.tsx"
fi

if grep -q 'authUser?.role !== "admin"' "$PAGE"; then
  ok "the page guards itself for admins (a non-admin is redirected)"
else
  bad "the SSH page does not guard itself for admins"
fi

for pat in '/ssh/accounts' '/ssh/accounts/${acct.id}/state' '/ssh/accounts/${keysFor.id}/keys' '/ssh-keys'; do
  if grep -qF "$pat" "$PAGE"; then
    ok "the page calls $pat"
  else
    bad "the page no longer calls $pat"
  fi
done

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
