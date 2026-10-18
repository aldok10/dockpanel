#!/usr/bin/env bash
#
# Regression pin for the RESOURCE-MUTATION AUDIT LOG extension.
#
# WHAT THIS CLOSES. DockPanel already had two logging paths: `activity::
# log_activity(...)`, which writes to the MUTABLE `activity_logs` table (no
# trigger stops an UPDATE/DELETE on it), and `security_hardening::audit_log
# (...)`, which writes to the IMMUTABLE `security_audit_log` table (a Postgres
# trigger blocks UPDATE/DELETE on it) plus an append-only tamper-resistant
# file. Before this change, audit_log was only ever called from auth.rs,
# security.rs, git_deploys.rs, passkeys.rs and services/auto_healer.rs — every
# OTHER destructive or privilege-sensitive action (deleting a site or server,
# promoting/demoting a reseller, resetting another user's password or 2FA,
# rotating a secret or server token, disabling SSH password auth, etc.) only
# ever reached the mutable table. DockPanel supports teams/resellers/multiple
# admins, so a compromised admin account or a malicious insider could perform
# one of those actions and then edit or delete the activity_logs row that
# recorded it, leaving zero forensic trace.
#
# THE FIX. 96 call sites across 32 route files were classified (a 7-agent
# survey over every activity::log_activity(...)/log_activity_on_server(...)
# call in panel/backend/src/routes) as destructive, privilege-changing,
# credential-lifecycle, or infrastructure-topology mutations, and each now
# ALSO writes an immutable audit_log() entry alongside its existing
# log_activity() call — same actor, same target, same details, reusing the
# real caller IP wherever `headers: HeaderMap` could be threaded through
# (adding that parameter to 81 handlers that didn't already have it). A live
# smoke test against this box's real Postgres during development found a
# 97th site the survey's grep pattern couldn't see: auth.rs's login handler
# has a THIRD logging variant, log_activity_system(...), on the "no such
# account" branch — the one call in the whole codebase that uses it, and (per
# its own comment) "the branch that matters for detection", since credential
# stuffing and username enumeration are attempts against emails that don't
# exist. Fixed and added to this pin (§3) as its own targeted assertion,
# distinct from the sibling "wrong password for a real account" branch.
# Ship any of this without a per-site pin and a single reverted call site (or
# a severity silently downgraded from "critical" to "warning" on something
# like site.delete) is invisible until an incident review goes looking for a
# trail that was never guaranteed to survive.
#
# Pure source analysis: no box, no network, no build, no Docker/Postgres.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

ROUTES=panel/backend/src/routes
MIGRATION=panel/backend/migrations/20260324000000_security_enhancements.sql

# Strip line comments only — a block-comment stripper is what deleted 485
# lines of real code until s294; this deliberately does the narrow, safe thing.
code() { sed 's://.*$::' "$1"; }

# ── 0. Files exist ──────────────────────────────────────────────────────
FILES="api_keys auth backup_orchestrator backups cdn crons databases dns \
docker_apps extensions git_deploys iac logs mail oauth passkeys \
reseller_dashboard resellers secrets security servers settings sites ssl \
stacks staging system teams tls_certificates users webhook_gateway whmcs"

for f in $FILES; do
  [ -f "$ROUTES/$f.rs" ] || { echo "missing $ROUTES/$f.rs"; exit 1; }
done
[ -f "$MIGRATION" ] || { echo "missing $MIGRATION"; exit 1; }

# ── 1. Per-file audit_log() call counts — the count-based backstop ─────
#
# Each number is the file's TOTAL security_hardening::audit_log(...) call
# count after this change (pre-existing calls + the ones this change added).
# Dropping ANY one of the 96 new calls anywhere shows up here as a wrong
# count for its file, without needing to spell out every dynamic event
# string this file's audit trail also depends on (see §2 for the highest-
# value ones spelled out explicitly).
check_count() {
  local file="$1" expected="$2"
  local actual
  actual=$(code "$ROUTES/$file.rs" | grep -c "audit_log(")
  if [ "$actual" -eq "$expected" ]; then
    ok "$file.rs has exactly $expected audit_log() call(s)"
  else
    bad "$file.rs: expected $expected audit_log() call(s), found $actual"
  fi
}

check_count api_keys 3
check_count auth 11
check_count backup_orchestrator 2
check_count backups 2
check_count cdn 1
check_count crons 1
check_count databases 2
check_count dns 3
check_count docker_apps 4
check_count extensions 3
check_count git_deploys 2
check_count iac 1
check_count logs 1
check_count mail 7
check_count oauth 3
check_count passkeys 6
check_count reseller_dashboard 2
check_count resellers 5
check_count secrets 1
check_count security 15
check_count servers 5
check_count settings 2
check_count sites 12
check_count ssl 1
check_count stacks 1
check_count staging 2
check_count system 6
check_count teams 1
check_count tls_certificates 3
check_count users 6
check_count webhook_gateway 1
check_count whmcs 2

# ── 2. Grand total — independent of how the per-file counts above sum ──
TOTAL=0
for f in $FILES; do
  n=$(code "$ROUTES/$f.rs" | grep -c "audit_log(")
  TOTAL=$((TOTAL + n))
done
if [ "$TOTAL" -eq 117 ]; then
  ok "grand total audit_log() calls across all 32 files is 117 (13 pre-existing + 97 from this session's own extension + 3 from the SFTP feature's own enable/disable/reset-password credential-lifecycle events + 4 from the jailed-shell feature's ssh enable/disable and site-key add/remove events)"
else
  bad "grand total audit_log() calls: expected 117, found $TOTAL"
fi

# ── 3. Targeted content checks — the highest-value / trickiest sites ───
#
# A call-count match doesn't prove the RIGHT event fired with the RIGHT
# severity — a swapped severity or a copy-pasted wrong event_type would still
# leave the count untouched. These spell out the sites where getting it wrong
# would matter most (the four "critical"-severity destructive actions) and
# the trickiest mechanical shapes (dynamic event strings, and the oauth.rs
# sites where the real caller IP was sitting right there and had to be wired
# in, not left as None).
# Each file's code is flattened ONCE into a variable (never piped into a
# boolean grep — a `producer | grep -q` under `set -o pipefail` reads a
# successful early-exit match as a failure the moment grep stops reading
# before the producer finishes writing, the exact SIGPIPE-false-negative
# class this project's own pipefail-sigpipe-pin-e2e.sh exists to catch).
# Whitespace is stripped from both the haystack and every needle below so
# formatting (single-line vs multi-line calls) can't cause a false miss.
SITES_FLAT=$(printf '%s' "$(code "$ROUTES/sites.rs")" | tr -d ' \t\n')
SERVERS_FLAT=$(printf '%s' "$(code "$ROUTES/servers.rs")" | tr -d ' \t\n')
USERS_FLAT=$(printf '%s' "$(code "$ROUTES/users.rs")" | tr -d ' \t\n')
DNS_FLAT=$(printf '%s' "$(code "$ROUTES/dns.rs")" | tr -d ' \t\n')
AUTH_FLAT=$(printf '%s' "$(code "$ROUTES/auth.rs")" | tr -d ' \t\n')
OAUTH_FLAT=$(printf '%s' "$(code "$ROUTES/oauth.rs")" | tr -d ' \t\n')

must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc — pattern not found (whitespace-insensitive): $needle" ;;
  esac
}

# The four CRITICAL-severity destructive actions — an attacker (or a script
# bug) silently downgrading one of these to "warning" is exactly the kind of
# regression a count-only check would miss.
must_contain "$SITES_FLAT" '"site.delete", Some(&claims.email), ip.as_deref(),
        Some("site"), Some(&site.domain), None, None, "critical",' "site.delete is audit-logged at severity=critical"
must_contain "$SITES_FLAT" '"site.transfer",
        Some(&claims.email),
        crate::routes::client_ip(&headers).as_deref(),
        Some("site"),
        Some(&domain),
        Some(&format!("{previous_owner} -> {new_owner} ({email})")),
        None,
        "critical",' "site.transfer is audit-logged at severity=critical"
must_contain "$SERVERS_FLAT" '"server.delete",
        Some(&claims.email),
        ip.as_deref(),
        Some("server"),
        Some(&server.name),
        None,
        None,
        "critical",' "server.delete is audit-logged at severity=critical"
must_contain "$SERVERS_FLAT" '"server.rotate_token",
        Some(&claims.email),
        ip.as_deref(),
        Some("server"),
        None,
        None,
        None,
        "critical",' "server.rotate_token is audit-logged at severity=critical"

# Dynamic event strings — the action isn't a literal, so the regression to
# guard against is someone "simplifying" the call to a hardcoded half of the
# branch (e.g. always "user.suspend" even on the unsuspend path).
must_contain "$USERS_FLAT" 'audit_log(
        &state.db, action, Some(&claims.email), ip.as_deref(),' "user.suspend/user.unsuspend reuses the shared dynamic \`action\` variable, not a hardcoded literal"
must_contain "$SITES_FLAT" '&format!("site.waf.{}", if enabled { "enabled" } else { "disabled" }),
        Some(&claims.email), ip.as_deref(),' "site.waf.{enabled|disabled} reuses the same format! expression as log_activity, not a hardcoded literal"
must_contain "$DNS_FLAT" '&format!("dns.cf.setting.{setting}"), Some(&claims.email), ip.as_deref(),' "dns.cf.setting.{setting} reuses the dynamic setting name, not a hardcoded literal"

# auth.login_failed has TWO call sites (auth.rs's `login` handler branches on
# whether the email matches a real account), and both were gaps before this
# change (auth.rs already audit-logged successful "login"; neither failure
# branch was covered). A live-verification smoke test against this box's real
# Postgres during development caught the second one: the discovery survey
# grepped for `log_activity(` and `log_activity_on_server(`, and the
# non-existent-account branch calls a THIRD variant, `log_activity_system(`,
# which was never in scope — so the mechanical `audit_log()` pass silently
# skipped the one call this codebase's own comment calls "the branch that
# matters for detection": credential stuffing and username enumeration are,
# by definition, attempts against emails that do not exist, so a login-audit
# surface fed only by the wrong-password-for-a-real-account branch would look
# complete while missing the actual attack signal.
must_contain "$AUTH_FLAT" '"auth.login_failed", Some(&u.email), Some(&ip),' "auth.login_failed (wrong password, real account) is audit-logged"
must_contain "$AUTH_FLAT" '"auth.login_failed", Some(&body.email), Some(&ip),
                None, None, Some("unknown_user"), None, "warning",' "auth.login_failed (no such account — the actual enumeration/credential-stuffing signal) is audit-logged"

# oauth.rs — all three call sites originally logged ip_address/actor_ip as a
# literal `None` even though `headers`/a computed `ip` was available in scope
# for the session-row insert a few lines away. Left as None, every OAuth
# audit entry would be forensically useless for IP-based investigation.
must_contain "$OAUTH_FLAT" 'let ip = crate::routes::client_ip(&headers);
                activity::log_activity(
                    &state.db, u.id, &u.email, "auth.oauth_link",
                    Some("user"), Some(&provider_name), None, ip.as_deref(),' "auth.oauth_link captures the real caller IP, not None"
must_contain "$OAUTH_FLAT" 'let ip = crate::routes::client_ip(&headers);
            activity::log_activity(
                &state.db, new_user.id, &new_user.email, "auth.oauth_register",
                Some("user"), Some(&provider_name), None, ip.as_deref(),' "auth.oauth_register captures the real caller IP, not None"
must_contain "$OAUTH_FLAT" 'crate::services::activity::log_activity(
        &state.db, user.id, &user.email, "auth.oauth_login",
        Some("user"), Some(&provider_name), None, ip.as_deref(),' "auth.oauth_login captures the real caller IP, not None"

# ── 4. The immutability guarantee this whole feature depends on ────────
MIG_CODE=$(code "$MIGRATION" | tr -d '\n')
case "$MIG_CODE" in
  *'CREATE TRIGGER trg_immutable_audit_log    BEFORE UPDATE OR DELETE ON security_audit_log'*)
    ok "security_audit_log keeps its BEFORE UPDATE OR DELETE immutability trigger" ;;
  *)
    bad "security_audit_log's immutability trigger is missing or was weakened" ;;
esac
case "$MIG_CODE" in
  *"RAISE EXCEPTION 'Security audit log is immutable"*)
    ok "the trigger function still raises on UPDATE/DELETE rather than silently ignoring it" ;;
  *)
    bad "the trigger function no longer raises on UPDATE/DELETE" ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
