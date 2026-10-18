#!/bin/bash
# DockPanel build-artifact cleanup
# Frees disk space by removing compiled Rust targets, frontend build output,
# and Docker build leftovers. Safe by default: supports --dry-run and asks
# before deleting unless --yes is passed.
#
# Measured on this box before writing this script (2026-10-18):
#   panel/backend/target   6.5G  (5.3G debug + 1.1G release)
#   panel/agent/target     3.8G
#   panel/mailapi/target   2.6G
#   panel/frontend/node_modules  106M, dist 2.2M
# The Rust target dirs are the real offenders — incremental debug builds
# accumulate stale artifacts that `cargo build` never reuses or reclaims.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DRY_RUN=false
ASSUME_YES=false
KEEP_RELEASE=false
CLEAN_DOCKER=false
CLEAN_NODE=false

usage() {
  cat <<EOF
Usage: cleanup-build.sh [options]

Options:
  -n, --dry-run        Show what would be removed without deleting
  -y, --yes            Skip the confirmation prompt
  --keep-release       Keep release/ target dirs (only clean debug builds)
  --docker             Also prune dangling images, stopped containers and build cache
  --node               Also remove frontend node_modules and dist (rebuild with npm ci)
  -h, --help           Show this help

Default (no flags): removes Rust debug+release target dirs for all three crates,
plus frontend dist and tsbuildinfo. That recovers the vast majority of space.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--dry-run) DRY_RUN=true ;;
    -y|--yes) ASSUME_YES=true ;;
    --keep-release) KEEP_RELEASE=true ;;
    --docker) CLEAN_DOCKER=true ;;
    --node) CLEAN_NODE=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo -e "${RED}Unknown option: $1${NC}"; usage; exit 1 ;;
  esac
  shift
done

# Rust crates that carry their own target/ directory.
CRATES=(panel/backend panel/agent panel/mailapi)

human() {
  # Human-readable size of a path, 0 if it does not exist.
  local dir="$1"
  if [[ -d "$dir" ]]; then
    du -sh "$dir" 2>/dev/null | cut -f1
  else
    echo "0"
  fi
}

REMOVE_LIST=()

plan_rust() {
  for crate in "${CRATES[@]}"; do
    local target="$REPO_ROOT/$crate/target"
    [[ -d "$target" ]] || continue
    if $KEEP_RELEASE; then
      for profile in debug incremental; do
        [[ -d "$target/$profile" ]] && REMOVE_LIST+=("$target/$profile")
      done
    else
      REMOVE_LIST+=("$target")
    fi
  done
}

plan_frontend() {
  local fe="$REPO_ROOT/panel/frontend"
  [[ -d "$fe/dist" ]] && REMOVE_LIST+=("$fe/dist")
  [[ -f "$fe/tsconfig.tsbuildinfo" ]] && REMOVE_LIST+=("$fe/tsconfig.tsbuildinfo")
  if $CLEAN_NODE; then
    [[ -d "$fe/node_modules" ]] && REMOVE_LIST+=("$fe/node_modules")
  fi
}

plan_rust
plan_frontend

echo -e "${CYAN}=== DockPanel build-artifact cleanup ===${NC}"
echo "Repo: $REPO_ROOT"
echo

if [[ ${#REMOVE_LIST[@]} -eq 0 ]]; then
  echo -e "${GREEN}Nothing to clean — build dirs are already gone.${NC}"
  exit 0
fi

TOTAL_BEFORE=0
echo "Planned removals:"
for path in "${REMOVE_LIST[@]}"; do
  size_kb=$(du -sk "$path" 2>/dev/null | cut -f1 || echo 0)
  TOTAL_BEFORE=$((TOTAL_BEFORE + size_kb))
  rel="${path#"$REPO_ROOT"/}"
  printf "  %-45s %s\n" "$rel" "$(human "$path")"
done
echo
echo -e "Total to reclaim: ${YELLOW}$((TOTAL_BEFORE / 1024))M${NC}"
echo

if $DRY_RUN; then
  echo -e "${GREEN}Dry run — nothing was deleted.${NC}"
  exit 0
fi

if ! $ASSUME_YES; then
  read -rp "Delete these paths? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

for path in "${REMOVE_LIST[@]}"; do
  echo -n "Removing ${path#"$REPO_ROOT"/} ... "
  rm -rf "$path"
  echo -e "${GREEN}ok${NC}"
done

if $CLEAN_DOCKER; then
  echo
  echo "Pruning Docker (dangling images, stopped containers, build cache)..."
  docker container prune -f >/dev/null 2>&1 || true
  docker image prune -f >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
  echo -e "${GREEN}ok${NC}"
fi

echo
echo "Disk usage after cleanup:"
df -h "$REPO_ROOT" | tail -1

if $CLEAN_NODE; then
  echo
  echo -e "${YELLOW}Note: node_modules was removed. Run 'npm ci' in panel/frontend before building again.${NC}"
fi

# Rebuilding from scratch re-warms the cache; drop that hint so nobody is
# surprised the next build is slow.
echo -e "${CYAN}Note: the next Rust build will be a full rebuild (slower once, then incremental).${NC}"
