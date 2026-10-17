#!/usr/bin/env bash
# Regression pins for the "Database not found" bug on
# /backup-orchestrator?tab=databases (panel/backend/src/routes/backup_orchestrator.rs).
#
# A `databases` row carries exactly ONE owner FK (`chk_databases_owner`): a site
# (`site_id`) OR a docker stack (`stack_id`), the other NULL. Since v2.242.0's
# standalone-DB-for-stacks ship, stack-owned rows have `site_id IS NULL`. The
# Databases tab lists those rows via `/databases` (whose own query already
# LEFT JOINs both owner tables) and renders a Quick Backup button for each — but
# `create_db_backup` resolved the row with a plain `JOIN sites`, so pressing the
# button answered `404 "Database not found"` for every stack-owned database.
#
# The same blind spot ran through the rest of the manual DB-backup path, each a
# new failure once create was unblocked:
#   * list_db_backups   — a created stack backup would never be listed.
#   * delete_db_backup  — "Backup not found" for a backup that exists.
#   * restore_db_backup — "Backup not found", DR unreachable for stack DBs.
#   * services/backup_verifier.rs — stack archives were never auto-verified.
#
# Fix: LEFT JOIN both owner tables + COALESCE, the pattern databases.rs
# list()/get() and backup_policy_executor already use, plus the same admin
# widening list() grants (an admin who can SEE a database must be able to act on
# it). This suite pins that shape and, as a negative control, that the plain
# `JOIN sites` that caused the 404 has not crept back.
#
# Pure SOURCE pins — no box, no network, no build.
#
#   run: bash tests/db-backup-stack-owner-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORCH="$REPO/panel/backend/src/routes/backup_orchestrator.rs"
VERIFIER="$REPO/panel/backend/src/services/backup_verifier.rs"
DATABASES="$REPO/panel/backend/src/routes/databases.rs"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
hasIn()    { grep -qF -- "$2" <<< "$1" && ok "$3" || bad "$3"; }
absentIn() { grep -qF -- "$2" <<< "$1" && bad "$3" || ok "$3"; }

extract() { sed -n "/pub async fn $1(/,/^}/p" "$ORCH"; }

CREATE=$(extract create_db_backup)
LIST=$(extract list_db_backups)
DEL=$(extract delete_db_backup)
RESTORE=$(extract restore_db_backup)
VERIFIER_SRC=$(cat "$VERIFIER")

echo "== A. create_db_backup resolves BOTH owners (the reported 404) =="

hasIn "$CREATE" 'LEFT JOIN sites s ON d.site_id = s.id' \
  "A1 create_db_backup LEFT JOINs sites (site-owned databases resolve)"
hasIn "$CREATE" 'LEFT JOIN docker_stacks st ON d.stack_id = st.id' \
  "A2 create_db_backup LEFT JOINs docker_stacks (stack-owned databases resolve)"
hasIn "$CREATE" 'COALESCE(s.server_id, st.server_id)' \
  "A3 the dump host comes from whichever owner is present"
hasIn "$CREATE" 'COALESCE(s.user_id, st.user_id) = $2' \
  "A4 ownership is the site-or-stack owner, not the site alone"
hasIn "$CREATE" "u.role = 'admin'" \
  "A5 the admin widening mirrors /databases, so a visible database is actionable"
absentIn "$CREATE" 'FROM databases d JOIN sites' \
  "A6 negative control: the plain JOIN sites that produced 'Database not found' is gone"

echo
echo "== B. list_db_backups SHOWS a stack-owned database's archives =="

hasIn "$LIST" 'LEFT JOIN docker_stacks st ON d.stack_id = st.id' \
  "B1 list_db_backups LEFT JOINs docker_stacks"
hasIn "$LIST" 'COALESCE(s.user_id, st.user_id) = $1' \
  "B2 list_db_backups scopes by the site-or-stack owner"
absentIn "$LIST" 'JOIN sites s ON d.site_id = s.id AND s.user_id = $1' \
  "B3 negative control: the site-only scoped join is gone"

echo
echo "== C. delete_db_backup / restore_db_backup reach stack-owned backups =="

hasIn "$DEL" 'COALESCE(s.user_id, st.user_id) = $1' \
  "C1 delete_db_backup scopes by the site-or-stack owner"
hasIn "$RESTORE" 'COALESCE(s.user_id, st.user_id) = $1' \
  "C2 restore_db_backup scopes by the site-or-stack owner"

echo
echo "== D. backup_verifier auto-verifies stack archives too =="

hasIn "$VERIFIER_SRC" 'LEFT JOIN docker_stacks st ON st.id = d.stack_id' \
  "D1 the verifier's db-backup sweep LEFT JOINs docker_stacks"
hasIn "$VERIFIER_SRC" 'AND COALESCE(s.server_id, st.server_id) IS NOT NULL' \
  "D2 a NULL-owner archive is skipped rather than verified against a guessed host"
# Count occurrences: if every `JOIN sites s ON s.id = d.site_id` is a LEFT JOIN,
# plain and LEFT counts are equal. A creeping plain join would make them differ.
N_ANY=$(printf '%s' "$VERIFIER_SRC" | grep -oF 'JOIN sites s ON s.id = d.site_id' | wc -l)
N_LEFT=$(printf '%s' "$VERIFIER_SRC" | grep -oF 'LEFT JOIN sites s ON s.id = d.site_id' | wc -l)
if [ "$N_ANY" -ge 1 ] && [ "$N_ANY" -eq "$N_LEFT" ]; then
  ok "D3 no plain site join remains in the verifier ($N_LEFT/$N_ANY are LEFT JOINs)"
else
  bad "D3 no plain site join remains in the verifier (any=$N_ANY, left=$N_LEFT)"
fi

echo
echo "== E. the fix mirrors the source of truth (databases.rs) =="

hasIn "$(cat "$DATABASES")" 'COALESCE(s.user_id, st.user_id) = $1' \
  "E1 databases.rs still carries the owner predicate this fix copies"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
