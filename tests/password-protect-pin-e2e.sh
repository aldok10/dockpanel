#!/usr/bin/env bash
# Regression pins for the password-protection rollback — s372.
#
# The panel's basic-auth feature answered 400 "Nginx config test failed" on every
# attempt for the WHOLE SITE, and took nginx down with it. Both halves of that are
# pinned here.
#
# WHY IT ALWAYS FAILED. The handler wrote its include as a `location / { … }`
# block. Every vhost this panel renders already defines `location /` — that is
# what serves the site (`try_files`, and for a PHP site the handler behind it) — and
# two locations with the same name in one server block are fatal:
#
#     nginx: [emerg] duplicate location "/" in /etc/nginx/auth/<domain>.conf:1
#
# So the config test went red, the handler returned a bare "Nginx config test
# failed" with no nginx text, and it had ALREADY written the include into the
# site's vhost. Nothing rolled back, so the broken include stayed on disk and
# EVERY later `nginx -t` on the box failed too: any panel action that reloads
# nginx was dead, and `rc-service nginx restart` would not have come up at all.
# The agent's own audit log showed the whole sequence — ten 400s on
# POST /nginx/password-protect between 10:09 and 10:31, interleaved with the
# operator removing and re-adding when the site seemed to work again.
#
# It was not an edge case: deploying a sidecar app (phpMyAdmin, Dozzle) calls this
# door itself with `"path": "/"` (backend/src/routes/docker_apps.rs), so every
# such deploy hit it. §A and §B are the two halves of the repair; §C is why the
# protection now survives the next vhost rewrite; §D/§E are the list and remove
# doors, which had the same two defects (a parser that read comments as paths, and
# a failure arm that swallowed the error and reported success).
#
# SOURCE pins: no running panel, no nginx.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

G=/usr/bin/grep
NGINX_RS=panel/agent/src/routes/nginx.rs

# The handler, its two auth-block arms, and the two other doors that touch the
# same files. `sed` ranges on `/^async fn NAME/,/^}$/`: rustfmt closes a top-level
# function in column 0, and every nested block is indented, so the first `^}` is
# the function's own end.
handler() { /usr/bin/sed -n '/^async fn password_protect/,/^}$/p' "$NGINX_RS"; }
lister()  { /usr/bin/sed -n '/^async fn list_protected/,/^}$/p' "$NGINX_RS"; }
remover() { /usr/bin/sed -n '/^async fn remove_protection/,/^}$/p' "$NGINX_RS"; }

AUTH_BLOCK=$(handler | /usr/bin/sed -n '/let auth_block = if path == "\/"/,/^    };$/p')
# Split on the arm boundary: the whole-site arm must carry NO `location`, and the
# sub-path arm must be the only one that has one.
ROOT_ARM=$(printf '%s\n' "$AUTH_BLOCK" | /usr/bin/sed -n '/if path == "\/"/,/} else {/p')
SUB_ARM=$(printf '%s\n' "$AUTH_BLOCK" | /usr/bin/sed -n '/} else {/,/^    };$/p')

acme_block() { /usr/bin/sed -n '/location \/.well-known\/acme-challenge\/ {/,/^    }$/p' \
                 "panel/agent/src/templates/nginx/$1.conf"; }

echo "── A. the whole-site form cannot collide with the vhost's own location / ──"

if [ -z "$AUTH_BLOCK" ]; then
  bad "A0 could not extract the auth-block arms from $NGINX_RS" \
      "every arm below would read 0 — and 0 is what four of them expect"
else
  eq "A1 the two forms are chosen by path" \
     "$(printf '%s' "$AUTH_BLOCK" | $G -cF 'if path == "/"')" "1"
  eq "A2 the WHOLE SITE writes auth_basic at server scope" \
     "$(printf '%s' "$ROOT_ARM" | $G -cF 'auth_basic')" "1"
  eq "A3 …with its user file" \
     "$(printf '%s' "$ROOT_ARM" | $G -cF 'auth_basic_user_file')" "1"
  # The defect itself. One `location` here and the config test is red for the
  # whole server again, because the vhost already has `location /`.
  eq "A4 …and NO location wrapper (the duplicate-location fatal)" \
     "$(printf '%s' "$ROOT_ARM" | $G -cF 'location')" "0"
  eq "A5 a sub-path still gets the location block it needs" \
     "$(printf '%s' "$SUB_ARM" | $G -cF 'location')" "1"
fi

echo
echo "── B. a failed configuration is put back, and says why ──"

# One rollback helper, called from all three failure arms (reload failed, test
# failed, test could not run). Three calls, not one: a repair that only covers the
# common arm is the bug again with a smaller blast radius.
eq "B1 the rollback goes through one helper" \
   "$(handler | $G -cF 'restore_auth_include')" "1"
eq "B2 …which every failure arm calls" \
   "$(handler | $G -cF 'put_back()')" "3"
eq "B3 …and every arm reports whether it succeeded" \
   "$(handler | $G -cF 'restore_note(restored)')" "3"
# The operator could not diagnose this because the agent threw nginx's text away.
eq "B4 nginx's own stderr reaches the caller" \
   "$(handler | $G -cF 'output.stderr')" "1"
eq "B5 the bare 'Nginx config test failed' (no detail) is gone" \
   "$(handler | $G -cF '"Nginx config test failed",')" "0"
# The include is staged as a dot-prefixed file and renamed into place: a plain
# write can leave a half-written file that nginx then reads, and the vhost pulls
# this directory in with the mask <domain>.conf*, so a leftover
# <domain>.conf.restore would itself be included as a second copy of the file.
eq "B6 the include is written atomically" \
   "$(handler | $G -cF 'write_auth_include(&auth_file')" "1"
eq "B7 …never with a bare write" \
   "$(handler | $G -cF 'std::fs::write(&auth_file')" "0"
# A vhost rendered before the template carried the include gets it added once, and
# that edit is covered by the same rollback.
eq "B8 the legacy-vhost repair is rolled back too" \
   "$(handler | $G -cF 'restore_or_remove(&site_conf')" "1"

echo
echo "── C. the protection survives a vhost rewrite ──"

# It used to be inserted into the RENDERED vhost, so the next settings change
# re-rendered the file from the template and the include was silently gone: the
# operator's password protection stayed on disk and stopped guarding anything.
# The line now lives in the template. A WILDCARD mask on purpose — nginx skips a
# mask that matches nothing, but FAILS the entire configuration on a literal path
# that is absent — so an unprotected site needs no placeholder file.
c=0
for tpl in http https proxy; do
  c=$((c+1))
  eq "C$c $tpl.conf pulls the include in, as a mask" \
     "$($G -cF 'include /etc/nginx/auth/{{ domain }}.conf*;' "panel/agent/src/templates/nginx/$tpl.conf")" "1"
done

# Server-scope auth also covers the ACME location, and a CA validating an HTTP-01
# challenge cannot answer a 401. http.conf and proxy.conf serve it from the same
# server block; in https.conf it lives in the port-80 redirect block, which the
# include does not touch.
for tpl in http proxy; do
  c=$((c+1))
  eq "C$c $tpl.conf exempts the ACME challenge" \
     "$(acme_block "$tpl" | $G -cF 'auth_basic off;')" "1"
done

echo
echo "── D. the list reads the file it was given ──"

# The old filter matched any line CONTAINING "location " — so a comment that
# merely mentioned `location /` was reported to the operator as a protected path.
eq "D1 only a real location line counts" \
   "$(lister | $G -cF 'l.starts_with("location ")')" "1"
eq "D2 …and it must actually open a block" \
   "$(lister | $G -cF "l.ends_with('{')")" "1"
eq "D3 the naive 'contains location' filter is gone" \
   "$(lister | $G -cF 'contains("location ")' )" "0"
# The whole-site form has no location line; showing a protected site as
# unprotected is the failure mode this arm exists for.
eq "D4 whole-site protection is reported as /" \
   "$(lister | $G -cF 'paths.push("/".to_string())')" "1"

echo
echo "── E. remove understands both shapes, and refuses to lie ──"

eq "E1 remove knows the whole-site (header) form" \
   "$(remover | $G -cF 'if path == "/"')" "1"
eq "E2 …and strips both directives" \
   "$(remover | $G -cF 'line.starts_with("auth_basic")')" "1"
# It used to answer 200 no matter what the config test said (`Ok(output) if
# output.success => …, _ => {}`), so the operator was told the protection was off
# while nginx still had it — or while the box was broken.
eq "E3 remove rolls back on every failure arm" \
   "$(remover | $G -cF 'restore_auth_include')" "3"
eq "E4 …through the same atomic writer" \
   "$(remover | $G -cF 'write_auth_include(&auth_file')" "1"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
