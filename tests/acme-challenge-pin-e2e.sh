#!/usr/bin/env bash
# Regression pins for the ACME challenge surviving the bot-protection blocks.
#
# `bot_protection = "challenge"` (and `"block"`) write a server-level
# `if … return`, and a server-level `if` runs in the REWRITE phase — BEFORE nginx
# chooses a location. So `if ($bot_challenge) { return 200 '<html>…'; }` shadowed
# the `location /.well-known/acme-challenge/` the same template defines below it:
# a CA fetching `/.well-known/acme-challenge/<token>` was answered with the
# verification page's 200 HTML instead of the token, and EVERY order and renewal
# for the site failed validation. The `block` mode had the same shape and a
# different symptom: a validator whose User-Agent the bad-bot map dislikes (or an
# empty one) was 403'd before the location ran. The HTTP-01 path must never be
# behind either block; the templates already exempt `/.well-known/bot-verify`, so
# the exemption is spelled the same way.
#
# The same class of mistake produced a third, quieter defect: the bare directory
# `/.well-known/acme-challenge/` has no index, so nginx answered 403
# "directory index … is forbidden" — which an operator opening it in a browser
# reads as a broken challenge setup. A token is a FILE; the directory now answers
# 404 explicitly.
#
# SOURCE pins: no running panel, no nginx.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

G=/usr/bin/grep
HTTP=panel/agent/src/templates/nginx/http.conf
PROXY=panel/agent/src/templates/nginx/proxy.conf
HTTPS=panel/agent/src/templates/nginx/https.conf

# Occurrences of a literal in a file. `grep -c` prints 0 and exits 1 on no match.
n() { $G -cF "$2" "$1" 2>/dev/null || true; }
# Occurrences of a DIRECTIVE (a whole line), so the explanatory comments that
# quote a directive are not themselves counted as one.
nrx() { $G -cE "$2" "$1" 2>/dev/null || true; }

CHALLENGE_EXEMPT='if ($uri ~ ^/\.well-known/acme-challenge/) { set $bot_challenge 0; }'
BLOCK_EXEMPT='if ($uri ~ ^/\.well-known/acme-challenge/) { set $bot_blocked 0; }'
# The predicate the negative arms exercise: do the templates carry the
# traversal-safe exemption (`$uri`, not `$request_uri`)?
has_challenge_exempt() { $G -qF "$CHALLENGE_EXEMPT" "$1"; }
has_block_exempt()     { $G -qF "$BLOCK_EXEMPT" "$1"; }

for T in "$HTTP" "$PROXY" "$HTTPS"; do
  echo "── $(basename "$T") ──"

  # ── A. the challenge mode cannot swallow the challenge ─────────────────────
  eq "A1 challenge mode exempts the ACME path (once)" \
     "$(n "$T" "$CHALLENGE_EXEMPT")" "1"
  # `$uri` is normalized, so `/.well-known/acme-challenge/../secret` cannot borrow
  # the exemption; `$request_uri` is the raw line and would match it.
  eq "A2 …using the normalized uri, never the raw request_uri" \
     "$(n "$T" 'if ($request_uri ~ ^/\.well-known/acme-challenge/)')" "0"
  eq "A3 the bare challenge return is still there" \
     "$(n "$T" "if (\$bot_challenge) {")" "1"

  # ── B. the block mode cannot 403 the challenge ─────────────────────────────
  # A single `if ($bad_bot) { return 403; }` is the shadow; it must route through a
  # variable so the ACME path can be cleared first.
  eq "B1 block mode no longer returns 403 inline" \
     "$(nrx "$T" '^[[:space:]]*if \(\$bad_bot\) \{ return 403; \}$')" "0"
  eq "B2 …it sets the variable instead" \
     "$(n "$T" 'if ($bad_bot) { set $bot_blocked 1; }')" "1"
  eq "B3 …and exempts the ACME path" \
     "$(n "$T" "$BLOCK_EXEMPT")" "1"
  eq "B4 the block still fires for everything else" \
     "$(n "$T" 'if ($bot_blocked) { return 403; }')" "1"

  # ── C. the token is still served from the shared webroot ───────────────────
  eq "C1 the prefix location is present" \
     "$(n "$T" 'location /.well-known/acme-challenge/ {')" "1"
  eq "C2 …and points at /var/www/acme" \
     "$(n "$T" 'root /var/www/acme;')" "1"

  # ── D. the bare directory is not a 403 ─────────────────────────────────────
  # Exact matches win over every prefix AND regex location, and (unlike a prefix
  # match) they are not reached only after the rewrite-phase `if`s — so a bare
  # directory request lands here.
  eq "D1 the bare directory answers 404 (trailing slash)" \
     "$(n "$T" 'location = /.well-known/acme-challenge/ { return 404; }')" "1"
  eq "D2 …and without the trailing slash" \
     "$(n "$T" 'location = /.well-known/acme-challenge { return 404; }')" "1"
  echo
done

echo "── E. the pins can fail: they reject an unexempted template ──"
tmp=$(mktemp)
# A vhost that looks right but never learned the exemption — exactly the file the
# defect shipped.
cat > "$tmp" <<'EOF'
    set $bot_challenge 0;
    if ($http_cookie !~* "dp_verified=1") { set $bot_challenge 1; }
    if ($request_uri = /.well-known/bot-verify) { set $bot_challenge 0; }
    if ($bot_challenge) { return 200 'html'; }
EOF
has_challenge_exempt "$tmp" && bad "E1 the check accepts an unexempted file" "predicate said yes" \
                           || ok "E1 the check rejects a file without the exemption"
# A file that uses the RAW uri — it would let `…/../` borrow the exemption.
cat > "$tmp" <<'EOF'
    if ($request_uri ~ ^/\.well-known/acme-challenge/) { set $bot_challenge 0; }
EOF
has_challenge_exempt "$tmp" && bad 'E2 the check accepts the raw-request_uri spelling' "predicate said yes" \
                           || ok "E2 the check rejects the raw-request_uri spelling"
# And the real templates must satisfy it.
has_challenge_exempt "$HTTP" && ok "E3 http.conf carries the exemption" || bad "E3 http.conf carries the exemption" "missing"
has_block_exempt "$PROXY"    && ok "E4 proxy.conf carries the block exemption" || bad "E4 proxy.conf carries the block exemption" "missing"
rm -f "$tmp"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
