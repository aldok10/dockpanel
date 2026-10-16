#!/usr/bin/env bash
# Regression pins for domain aliases surviving a vhost rewrite — s373.
#
# "Additional domains that serve the same site content" is advertised in the site
# screen, and it did serve them — until the next rewrite. The handler appended the
# name to the `server_name` line it found on disk, and the alias existed ONLY in
# that rendered file. Every other writer regenerates the vhost from the templates
# (`build_nginx_body` → `render_site_config`): a settings save, an SSL renewal, a
# security-hardening pass, the auto-healer. So the alias held until one of those
# ran and then vanished with no error at all — the site kept serving, the second
# hostname stopped resolving, and `GET /nginx/aliases/{domain}` reported none,
# because it was reading the same file that had just been rewritten without it.
#
# Three more defects sat in the same thirty lines:
#   * `add` matched the literal `server_name <domain>;`, which no longer exists
#     once the line carries an alias — so a site could never hold more than ONE.
#   * `remove` ran two `str::replace` calls over the WHOLE file, deleting the name
#     from comments, log paths and any `custom_nginx` body that mentioned it.
#   * neither handler had anything to roll back but the vhost, and `remove`
#     swallowed a failed config test and answered 200 anyway.
#
# The store is now `/etc/nginx/aliases/{domain}` (one name per line) and the render
# reads it, so an alias is re-applied every time the vhost is generated. It is a
# file rather than a `sites` column because the agent is already the authority the
# backend asks, and an add must land on a live box without a backend migration.
#
# SOURCE pins: no running panel, no nginx.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
ok()  { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

G=/usr/bin/grep
SVC=panel/agent/src/services/nginx.rs
NGINX_RS=panel/agent/src/routes/nginx.rs

# `sed` ranges on `/^async fn NAME/,/^}$/`: rustfmt closes a top-level function in
# column 0 and every nested block is indented, so the first `^}` is its own end.
applier() { /usr/bin/sed -n '/^async fn apply_aliases/,/^}$/p' "$NGINX_RS"; }
adder()   { /usr/bin/sed -n '/^async fn add_alias/,/^}$/p' "$NGINX_RS"; }
lister()  { /usr/bin/sed -n '/^async fn list_aliases/,/^}$/p' "$NGINX_RS"; }
remover() { /usr/bin/sed -n '/^async fn remove_alias/,/^}$/p' "$NGINX_RS"; }
renderer() { /usr/bin/sed -n '/^pub fn render_site_config/,/^}$/p' "$SVC"; }

echo "── A. the alias lives in a store the RENDER reads, not in the file it rewrites ──"

# The path is a single spelling in one function; three call sites building it by
# hand is how the store and the reader end up disagreeing.
eq "A1 the store has one spelling" \
   "$($G -cF 'pub fn aliases_dir()' "$SVC")" "1"
eq "A2 …under /etc/nginx/aliases" \
   "$($G -cF '"/etc/nginx/aliases"' "$SVC")" "1"
# This line is the whole fix: a rewrite now re-applies the name instead of
# dropping it, because the renderer asks the store every time it renders.
eq "A3 the render pulls the aliases from the store" \
   "$(renderer | $G -cF 'aliases_for(domain)')" "1"
eq "A4 …and puts them in the template context" \
   "$(renderer | $G -cF 'ctx.insert("aliases"')" "1"
# Reading the vhost to answer "which aliases does this site have" is what made the
# panel report the alias as present right up until the rewrite that removed it.
eq "A5 the list reads the store" \
   "$(lister | $G -cF 'aliases_for(&domain)')" "1"
eq "A6 …and no longer parses the vhost for them" \
   "$(lister | $G -cF 'sites_dir()')" "0"

echo
echo "── B. every server_name the domain owns takes the alias ──"

# An alias that reaches the :443 block but not the :80 redirect (or the reverse)
# answers on one scheme and not the other. https.conf has two such lines.
c=0
for tpl in http proxy; do
  c=$((c+1))
  eq "B$c $tpl.conf appends the aliases" \
     "$($G -cF 'server_name {{ domain }}{% if aliases %} {{ aliases }}{% endif %};' "panel/agent/src/templates/nginx/$tpl.conf")" "1"
done
eq "B3 https.conf carries both of its server_name lines" \
   "$($G -cF 'server_name {{ domain }}{% if aliases %} {{ aliases }}{% endif %};' panel/agent/src/templates/nginx/https.conf)" "2"

# Line-scoped editing, not a whole-file replace: a first name that is not this
# domain is somebody else's server_name (a custom snippet) and is left alone.
eq "B5 the rewrite is keyed to this domain's own line" \
   "$($G -cF 'rest.trim_end_matches('"'"';'"'"').split_whitespace().next() == Some(domain)' "$SVC")" "1"
eq "B6 …and builds the line rather than substituting text" \
   "$($G -cF 'pub fn with_server_names' "$SVC")" "1"
# The old removal deleted the name from anywhere in the file — comments, log
# paths, a custom_nginx body.
eq "B7 the whole-file alias replace is gone" \
   "$(remover | $G -cF '.replace(&format!(" {alias}"), "")')" "0"
# And `add` could only ever fire on a bare `server_name <domain>;`, so the second
# alias of a site always failed with "Could not find server_name directive".
eq "B8 …so the literal bare-line match that capped a site at one alias is gone" \
   "$(adder | $G -cF '&format!("server_name {};", body.domain)')" "0"

echo
echo "── C. a name that is not a name never reaches the config ──"

# The value is rendered into a root-owned directive; a stray space or newline from
# a hand-edited store file would become a second directive.
eq "C1 the door validates the alias" \
   "$(adder | $G -cF 'is_valid_domain(&body.alias)')" "1"
eq "C2 the store is read through the sanitizer" \
   "$($G -cF 'sanitize_aliases(names, domain)' "$SVC")" "1"
eq "C3 …which rejects anything is_valid_domain refuses" \
   "$($G -cF 'is_valid_domain(&name)' "$SVC")" "1"
eq "C4 …drops the domain itself" \
   "$($G -cF 'name == domain' "$SVC")" "1"

echo
echo "── D. a refused configuration is put back, and says why ──"

# Both doors move the same two files, so both go through one applier: two copies
# of this sequence is how the second one loses the rollback the first one has.
eq "D1 add and remove share one applier" \
   "$(adder | $G -cF 'apply_aliases(&body.domain, &current, &next)')" "1"
eq "D2 …and remove goes through it too" \
   "$(remover | $G -cF 'apply_aliases(&domain, &current, &next)')" "1"
# The store has to come back as well as the vhost: `list` reads the store, so a
# half-rollback would report an alias the live config does not serve. Two calls —
# the shared rollback, and the branch where the vhost itself went missing.
eq "D3 the store is rolled back" \
   "$(applier | $G -cF 'write_alias_store(domain, previous)')" "2"
eq "D4 …through the same helper the vhost uses" \
   "$(applier | $G -cF 'restore_or_remove(&conf_path')" "1"
eq "D5 every failure arm rolls back" \
   "$(applier | $G -cF 'let note = rollback();')" "3"
eq "D6 nginx's own stderr reaches the caller" \
   "$(applier | $G -cF 'output.stderr')" "1"
# `remove` used to end `_ => {}` — the operator was told the alias was gone while
# nginx still had it, or while the box was broken.
eq "D7 remove no longer swallows a failed test" \
   "$(remover | $G -cF 'Nginx config test failed')" "0"
eq "D8 the store is written atomically" \
   "$($G -cF 'std::fs::rename(&tmp, &file)' "$SVC")" "1"

echo
echo "── E. re-saying or unsaying a name is not an error ──"

eq "E1 re-adding a name a site already answers on is a no-op" \
   "$(adder | $G -cF 'return Ok(Json(serde_json::json!({ "ok": true, "alias": body.alias })));')" "1"
eq "E2 removing a name that is not configured answers ok" \
   "$(remover | $G -cF 'next.len() == current.len()')" "1"
# A disabled site's vhost is parked beside a stub; nginx does not read it, so no
# test or reload is owed — the store keeps the name for the re-enable.
eq "E3 a parked vhost skips the test and the reload" \
   "$(applier | $G -cF 'if !target.is_live()')" "1"
# Leaving the store behind would re-attach names to whatever site is created on
# this domain next — names that may belong to another tenant by then.
eq "E4 deleting a site takes its alias store with it" \
   "$(/usr/bin/sed -n '/^async fn delete_site/,/^}$/p' "$NGINX_RS" | $G -cF 'aliases_dir()')" "1"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
