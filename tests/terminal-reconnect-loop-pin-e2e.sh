#!/usr/bin/env bash
# terminal-reconnect-loop-pin-e2e.sh — the reconnect loop cannot silently return.
#
# THE SENTENCE THIS SUITE EXISTS TO PROVE, written out so a mutation can be aimed
# at it rather than at whatever the arms happen to catch:
#
#   "Replacing a terminal socket must not let the socket it replaced schedule
#    another reconnect; and a socket that opens only to be dropped again must
#    not be able to reset the backoff that exists to stop the retrying."
#
# THE DEFECT. `Terminal.tsx` reset the shared `intentionalClose` flag to false
# SYNCHRONOUSLY, but `.close()` delivers `onclose` on a later tick — by which
# time the flag read "the current connection is intentional", so the socket the
# `connect()` call had just replaced treated its own closure as an unexpected
# drop and scheduled a fresh reconnect. One extra reconnect per `connect()`.
# The loop was self-sustaining for a second reason: `onopen` cleared the attempt
# counter immediately, so a connection that opened and was dropped moments later
# reset the backoff on every cycle and the "give up after 3" branch was
# unreachable. On the box that produced the report, nginx logged bursts of tiny
# 22–49-byte `101` handshakes seconds apart — the loop, on a healthy server.
#
# A third, smaller amplifier lived in the agent: the once-per-second handshake
# limiter used `swap()` and therefore recorded the current second even for the
# request it then REFUSED, so two handshakes in the same second were BOTH
# answered 429 — and a refused caller pushed the window forward for its own
# retry.
#
# So the mutations this suite must survive are: drop the identity guard, reset
# the attempt counter in `onopen` again, replace the socket before nulling the
# ref, or go back to `swap()` for the rate limit.
#
#   §A  the frontend ties a close event to the socket it belongs to
#   §B  a flapping connection cannot clear the backoff
#   §C  the agent limiter only advances its window on an ACCEPTED handshake
#
# Pure source analysis: no box, no network, no build.
#
# NO PIPES INTO `grep -q` (see terminal-scope-signed-pin-e2e.sh for why): under
# `set -o pipefail` a `grep -q` closes the pipe on its first match and reddens a
# correct arm. Every arm here feeds grep a here-string.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

FE=panel/frontend/src/pages/Terminal.tsx
AG=panel/agent/src/routes/terminal.rs

for f in "$FE" "$AG"; do [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"; done

# Comments out, CODE INTACT — the fix's own comments quote the very strings the
# arms below must not match.
code() {
  perl -0777 -pe '
    s{/\*.*?\*/}{}gs;
    s{^\s*//.*$}{}gm;
  ' "$1"
}
subj() { local t; t=$(code "$1"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
has()   { grep -qE -- "$2" <<< "$1"; }
count() { grep -cE -- "$2" <<< "$1" || true; }

# One function/handler body, bounded by its OWN closing brace in column 0.
# `Terminal.tsx` uses arrow bodies, so we bound by the marker the handler opens.
fn_body() { awk -v pat="$1" '$0 ~ pat {f=1} f {print} f && /^        \};/ {exit}' <<< "$2"; }
# Order predicate: does `first` appear before `second` in `body`?
before() {
  local body="$1" first="$2" second="$3" a b
  a=$(grep -nE -- "$first" <<< "$body" | head -1 | cut -d: -f1)
  b=$(grep -nE -- "$second" <<< "$body" | head -1 | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

FE_S=$(subj "$FE" || true)
AG_S=$(subj "$AG" || true)

echo "§A  the frontend ties a close event to the socket it belongs to"

CONNECT=$(fn_body 'const connect = useCallback' "$FE_S" || true)
ONCLOSE=$(fn_body 'ws\.onclose = ' "$FE_S" || true)
ONMESSAGE=$(fn_body 'ws\.onmessage = ' "$FE_S" || true)
ONOPEN=$(fn_body 'ws\.onopen = ' "$FE_S" || true)

# A1 — `onclose` refuses to act on a socket that is not the current one.
if [ -z "$ONCLOSE" ]; then
  bad "A1 SKIPPED: could not isolate ws.onclose in $FE"
elif has "$ONCLOSE" 'wsRef\.current !== ws'; then
  ok "A1 ws.onclose ignores events from a superseded socket"
else
  bad "A1 ws.onclose acts on ANY socket — a replaced socket schedules a reconnect (the loop)"
fi

# A2 — `onmessage` does the same, so a stale frame is not written into a
# terminal that has already been disposed.
if [ -z "$ONMESSAGE" ]; then
  bad "A2 SKIPPED: could not isolate ws.onmessage in $FE"
elif has "$ONMESSAGE" 'wsRef\.current !== ws'; then
  ok "A2 ws.onmessage ignores frames from a superseded socket"
else
  bad "A2 ws.onmessage writes frames from a superseded socket into a disposed terminal"
fi

# A3 — the ref is NULLED before the old socket is closed, which is what makes
# the guard above see a mismatch when the stale close finally arrives.
if [ -z "$CONNECT" ]; then
  bad "A3 SKIPPED: could not isolate connect() in $FE"
elif [ -n "$(grep -nE -- 'wsRef\.current = null' <<< "$CONNECT")" ] \
   && before "$CONNECT" 'wsRef\.current = null' 'previous\.close\(\)'; then
  ok "A3 connect() nulls wsRef.current before closing the replaced socket"
else
  bad "A3 connect() closes the replaced socket before nulling the ref — the guard cannot fire"
fi

echo "§B  a flapping connection cannot clear the backoff"

# B1 — the reset must live INSIDE the deferred timer, not run on open. A reset
# that appears before the timer is scheduled is the synchronous bug.
if [ -z "$ONOPEN" ]; then
  bad "B1 SKIPPED: could not isolate ws.onopen in $FE"
elif has "$ONOPEN" 'stableTimer\.current = setTimeout' \
   && ! before "$ONOPEN" 'reconnectAttempts\.current = 0' 'stableTimer\.current = setTimeout'; then
  ok "B1 the attempt reset lives inside the stability timer, not on open"
else
  bad "B1 ws.onopen resets reconnectAttempts before the grace timer — a flapping link loops for ever"
fi

# B2 — it resets inside a deferred timer instead, so only a connection that
# SURVIVES the grace period counts as recovered.
if [ -n "$ONOPEN" ] && has "$FE_S" 'STABLE_CONNECTION_MS' \
   && has "$ONOPEN" 'stableTimer\.current = setTimeout'; then
  ok "B2 the attempt counter is cleared only after STABLE_CONNECTION_MS"
else
  bad "B2 no stability grace period — a socket dropped right after open still loops"
fi

# B3 — a close clears that pending timer, so a dead connection cannot later
# "recover" the counter it never earned.
if [ -n "$ONCLOSE" ] && has "$ONCLOSE" 'clearTimeout\(stableTimer\.current\)'; then
  ok "B3 ws.onclose cancels the pending stability timer"
else
  bad "B3 ws.onclose leaves the stability timer running"
fi

echo "§C  the agent limiter only advances its window on an ACCEPTED handshake"

# C1 — `swap()` is the defect: it writes `now` even on the request it refuses.
LIMITER=$(fn_body 'async fn ws_handler' "$AG_S" || true)
if [ -z "$LIMITER" ]; then
  bad "C1 SKIPPED: could not isolate ws_handler in $AG"
elif has "$LIMITER" 'LAST_CONNECT\.swap\('; then
  bad "C1 the limiter uses swap() — a refused request advances the window for its own retry"
else
  ok "C1 the limiter no longer uses swap()"
fi

# C2 — admission is a compare-exchange against the observed value.
if [ -n "$LIMITER" ] && has "$LIMITER" 'compare_exchange_weak\(last, now'; then
  ok "C2 the limiter advances only via compare_exchange on an accepted handshake"
else
  bad "C2 the limiter has no compare-exchange admission path"
fi

# C3 — a refused caller returns 429 without having touched the window; the
# return sits INSIDE the loop, before any write.
if [ -n "$LIMITER" ] \
   && has "$LIMITER" 'TERMINAL_MIN_INTERVAL_SECS' \
   && before "$LIMITER" 'TOO_MANY_REQUESTS' 'compare_exchange_weak\(last, now'; then
  ok "C3 the window is judged before it is written, so a refusal costs nothing"
else
  bad "C3 the refusal path and the window write are not ordered by the guard"
fi

echo
echo "── terminal-reconnect-loop: $PASS passed, $FAIL failed ────────────────"
[ "$FAIL" -eq 0 ]
