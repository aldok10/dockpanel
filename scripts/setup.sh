#!/usr/bin/env bash
#
# DockPanel Setup
# Installs DockPanel on a fresh server.
# Supports: Ubuntu 20+, Debian 11+, CentOS 9+, Rocky 9+, Fedora 39+, Amazon Linux 2023,
#           Alpine 3.19+ (OpenRC and apk instead of systemd and apt)
# Architectures: x86_64, ARM64 (aarch64)
#
# Architecture:
#   - PostgreSQL 16 (Docker container on port 5450)
#   - Agent (Rust binary, service-managed, Unix socket)
#   - API (Rust binary, service-managed, port 3080)
#   - CLI (Rust binary, /usr/local/bin/dockpanel)
#   - Frontend (Vite build, served by nginx)
#   - Nginx (reverse proxy + static files)
#
# Service manager: systemd where present, OpenRC on Alpine. Both are driven
# through the svc_* helpers below, so nothing here names one of them directly.
# Where there is neither, the panel is installed and the commands to run it by
# hand are printed instead of a service that silently never starts.
#
# Usage:
#   bash scripts/setup.sh                         # Interactive (asks for domain)
#   PANEL_DOMAIN=panel.example.com bash scripts/setup.sh  # Non-interactive with domain
#   INSTALL_FROM_RELEASE=1 bash scripts/setup.sh  # Download pre-built binaries
#   PANEL_PORT=9090 bash scripts/setup.sh         # Custom port (no domain)
#   DOCKPANEL_SKIP_FIREWALL=1 bash scripts/setup.sh  # Leave the firewall alone
#
set -euo pipefail

# ── Configuration (override with env vars) ──────────────────────────────
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
PANEL_PORT="${PANEL_PORT:-8443}"
CONFIG_DIR="/etc/dockpanel"
AGENT_BIN="/usr/local/bin/dockpanel-agent"
API_BIN="/usr/local/bin/dockpanel-api"
CLI_BIN="/usr/local/bin/dockpanel"
DB_PORT=5450
DB_CONTAINER="dockpanel-postgres"
INSTALL_FROM_RELEASE="${INSTALL_FROM_RELEASE:-0}"
GITHUB_REPO="ovexro/dockpanel"
# Set to 1 by configure_nginx when the panel is served over a self-signed
# certificate (no domain → no Let's Encrypt). print_summary reads it to print
# the right scheme and explain the browser warning before it happens.
PANEL_SELF_SIGNED=0
# Set to 1 by provision_panel_ssl only when certbot actually issued a
# certificate. print_summary reads it so a failed issuance can never be
# reported as an https:// panel URL.
PANEL_SSL_OK=0
# Which firewall this box is enforcing with: firewalld | ufw | none.
# Resolved by detect_firewall in main().
FW_MGR="none"

# ── Resolve repo root ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FRONTEND_DIR="$REPO_DIR/panel/frontend"
AGENT_SRC="$REPO_DIR/panel/agent"
API_SRC="$REPO_DIR/panel/backend"
CLI_SRC="$REPO_DIR/panel/cli"
MCP_SRC="$REPO_DIR/panel/mcp"

# Directories the agent unit declares in ReadWritePaths, with any `-` prefix
# stripped. The unit (panel/agent/dockpanel-agent.service) is the single source
# of truth, so this can never fall behind it the way a hand-copied list does.
# Prints nothing if no unit is readable; callers must tolerate an empty result.
agent_rwp_dirs() {
    local unit="$AGENT_SRC/dockpanel-agent.service"
    [ -f "$unit" ] || unit="/etc/systemd/system/dockpanel-agent.service"
    [ -f "$unit" ] || return 0
    sed -n 's/^ReadWritePaths=//p' "$unit" | tr ' ' '\n' | sed 's/^-//' | grep '^/' || true
}

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DIM='\033[2m'
WHITE='\033[1;37m'

# ── Install log + terminal detection ─────────────────────────────────────
# Everything a wrapped command prints is captured here, so a failure at any
# step leaves full forensics behind instead of vanishing into >/dev/null.
INSTALL_LOG="/var/log/dockpanel-install.log"
IS_TTY=0
if [ -t 1 ]; then IS_TTY=1; fi

# Spinner frames: braille on UTF-8 terminals, plain ASCII everywhere else.
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]*8*) SPIN_FRAMES='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' ;;
    *)                SPIN_FRAMES='|/-\' ;;
esac
SPIN_NFRAMES=${#SPIN_FRAMES}

plog() {  # append a plain line to the install log; never fails, never echoes
    printf '%s\n' "$*" >> "$INSTALL_LOG" 2>/dev/null || true
}

log()    { echo -e "  ${GREEN}✓${NC} $1";   plog "  [ok]   $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC} $1";  plog "  [warn] $1"; }
error()  { echo -e "  ${RED}✗${NC} $1" >&2; plog "  [FAIL] $1"; }
info()   { echo -e "  ${CYAN}→${NC} $1";    plog "  [..]   $1"; }

# ── Spinner-wrapped command runner ───────────────────────────────────────
# run "Label" cmd [args...] — runs cmd with all output captured to the
# install log, animating a spinner + live elapsed seconds while it works
# (falls back to a static line when stdout isn't a terminal). Returns the
# command's exit code; the caller decides whether that's fatal.
SPIN_PID=""
run() {
    local label="$1"; shift
    plog "→ RUN: $label"
    plog "  \$ $*"
    local rc=0
    if [ "$IS_TTY" = "1" ]; then
        "$@" >> "$INSTALL_LOG" 2>&1 &
        SPIN_PID=$!
        local i=0 start now frame
        start=$(date +%s)
        while kill -0 "$SPIN_PID" 2>/dev/null; do
            frame="${SPIN_FRAMES:$((i % SPIN_NFRAMES)):1}"
            now=$(( $(date +%s) - start ))
            # Colours live in the FORMAT string as literal escapes; the frame
            # char goes through %s so a backslash frame (ASCII set) can't merge
            # with a following escape and print literal garbage.
            printf '\r\033[2K  \033[0;36m%s\033[0m %s \033[2m%ss\033[0m' "$frame" "$label" "$now"
            i=$((i + 1))
            sleep 0.12 2>/dev/null || sleep 1
        done
        if wait "$SPIN_PID"; then rc=0; else rc=$?; fi
        SPIN_PID=""
        printf '\r\033[2K'
    else
        info "$label"
        if "$@" >> "$INSTALL_LOG" 2>&1; then rc=0; else rc=$?; fi
    fi
    plog "← DONE rc=$rc: $label"
    return $rc
}

# ── Failure box (EXIT trap) ──────────────────────────────────────────────
# If the installer dies anywhere before the summary, tell the user exactly
# where it stopped, show the tail of the log, and how to retry — instead of
# cutting off mid-paint.
CURRENT_STEP_NAME="starting up"
INSTALL_DONE=0
on_exit() {
    local rc=$?
    if [ -n "$SPIN_PID" ]; then kill "$SPIN_PID" 2>/dev/null || true; fi
    if [ "$INSTALL_DONE" = "1" ]; then return 0; fi
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║           DockPanel install did not finish           ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Stopped during: ${BOLD}${CURRENT_STEP_NAME}${NC} (exit code ${rc})"
    if [ -s "$INSTALL_LOG" ]; then
        echo ""
        echo -e "  Last lines of the install log:"
        tail -n 8 "$INSTALL_LOG" 2>/dev/null | sed 's/^/    /' || true
        echo ""
        echo -e "  Full log:  ${BOLD}${INSTALL_LOG}${NC}"
    fi
    echo ""
    echo -e "  Re-running the installer is safe — it picks up where it left off:"
    echo -e "    ${BOLD}curl -sL https://dockpanel.dev/install.sh | sudo bash${NC}"
    echo ""
    echo -e "  Stuck? Open an issue: https://github.com/ovexro/dockpanel/issues"
    echo ""
}
trap on_exit EXIT

# ── Service outcome tracking ─────────────────────────────────────────────
# The final summary prints what ACTUALLY happened, not a wishlist.
SVC_OK=()
SVC_FAIL=()
svc_ok()   { SVC_OK+=("$1"); }
svc_fail() { SVC_FAIL+=("$1"); }

# ── Init system ──────────────────────────────────────────────────────────
# Two things about the box used to be taken for granted here: that a service is
# started with systemctl, and that the package manager is apt/dnf/yum. Alpine is
# neither — it installs with apk and boots with OpenRC — so this block detects
# what the box actually has and every call site below goes through the svc_*
# helpers rather than naming one init system. setup.sh fits the panel to the box
# instead of assuming the box.
#
#   systemd — units in /etc/systemd/system, driven by systemctl
#   openrc  — runscripts in /etc/init.d, driven by rc-service/rc-update
#   none    — no service manager reachable (bare container, chroot). Everything
#             is installed and the exact commands to run the panel by hand are
#             printed at the end, rather than a "success" over three services
#             that were never started.
detect_init() {
    if command -v systemctl > /dev/null 2>&1 && [ -d /run/systemd/system ]; then
        INIT="systemd"
    elif command -v rc-service > /dev/null 2>&1 && command -v rc-update > /dev/null 2>&1; then
        INIT="openrc"
    else
        INIT="none"
    fi
}

# Debian's php8.4-fpm is Alpine's php-fpm84. The agent asks for the Debian
# spelling by name (services/nginx.rs builds `php{version}-fpm`), so the mapping
# has to happen somewhere — here, and in the systemctl shim written by
# create_services, which is the copy the agent actually reaches.
alpine_service_name() {
    local v
    v=$(printf '%s' "$1" | sed -n 's/^php\([0-9]*\)\.\([0-9]*\)-fpm$/\1\2/p')
    if [ -n "$v" ]; then printf 'php-fpm%s' "$v"; else printf '%s' "$1"; fi
}

# The name this init system knows a service by.
service_name_for() {
    if [ "$INIT" = "openrc" ]; then alpine_service_name "$1"; else printf '%s' "$1"; fi
}

svc_start() {
    case "$INIT" in
        systemd) systemctl start "$@" ;;
        openrc)  local s; for s in "$@"; do rc-service "$s" start; done ;;
        *)       return 1 ;;
    esac
}

svc_stop() {
    case "$INIT" in
        systemd) systemctl stop "$@" ;;
        openrc)  local s; for s in "$@"; do rc-service "$s" stop; done ;;
        *)       return 1 ;;
    esac
}

svc_restart() {
    case "$INIT" in
        systemd) systemctl restart "$@" ;;
        openrc)  local s; for s in "$@"; do rc-service "$s" restart; done ;;
        *)       return 1 ;;
    esac
}

# reload when the runscript can, restart when it cannot. OpenRC runscripts only
# support reload if they define the function; rc-service says so by failing.
svc_reload() {
    case "$INIT" in
        systemd) systemctl reload "$@" ;;
        openrc)  local s; for s in "$@"; do rc-service "$s" reload 2>/dev/null || rc-service "$s" restart; done ;;
        *)       return 1 ;;
    esac
}

svc_enable() {
    case "$INIT" in
        systemd) systemctl enable "$@" ;;
        openrc)  local s; for s in "$@"; do rc-update add "$s" default; done ;;
        *)       return 1 ;;
    esac
}

svc_disable() {
    case "$INIT" in
        systemd) systemctl disable "$@" ;;
        openrc)  local s; for s in "$@"; do rc-update del "$s" default 2>/dev/null || true; done ;;
        *)       return 1 ;;
    esac
}

# enable + start, best-effort: a missing runscript must not abort an install
# that is otherwise fine.
svc_enable_now() {
    svc_enable "$@" > /dev/null 2>&1 || true
    svc_start "$@" > /dev/null 2>&1 || true
}

# Prints the same vocabulary systemctl does (active/inactive/failed/activating)
# because callers below branch on those words, not on an exit code.
svc_is_active() {
    case "$INIT" in
        systemd) systemctl is-active "$1" 2>/dev/null || true ;;
        openrc)  if rc-service "$1" status > /dev/null 2>&1; then echo active; else echo inactive; fi ;;
        *)       echo inactive ;;
    esac
}

# Wait for a unit to come up, and do not confuse "not running" with "could not ask".
#
# `systemctl is-active` answers three different questions with two exit codes.
# During install, dbus can be momentarily unavailable — the call then prints
#   Failed to retrieve unit state: Message recipient disconnected from message
#   bus without replying
# to stderr, exits non-zero, and says nothing on stdout. A caller that reads only
# the exit code concludes the service failed. Observed on a genuinely fresh
# Ubuntu 24.04 box (s258): the installer aborted at step 11/15 with "Agent failed
# to start" while its own journal excerpt, printed directly underneath, showed the
# agent started and listening on its socket. The install stopped four steps from
# the end over a question that was never answered.
#
# So read the ANSWER, not the exit code: `active` succeeds, `failed` gives up
# immediately (waiting cannot help a unit that already failed), and anything else
# — `activating`, `inactive`, or the empty string we get when the bus is out — is
# treated as "not yet" and retried inside a bounded window.
wait_for_unit() {
    local unit="$1" tries="${2:-20}" state
    unit="$(service_name_for "$unit")"
    for _ in $(seq 1 "$tries"); do
        state=$(svc_is_active "$unit")
        case "$state" in
            active) return 0 ;;
            failed) return 1 ;;
            *)      sleep 1 ;;
        esac
    done
    [ "$(svc_is_active "$unit")" = "active" ]
}

join_comma() {
    local out="" item
    for item in "$@"; do
        if [ -z "$out" ]; then out="$item"; else out="$out, $item"; fi
    done
    printf '%s' "$out"
}

# ── Progress tracking ─────────────────────────────────────────────────
# TOTAL_STEPS is recomputed in main() once the install mode (release vs
# source) and domain are known, so the bar reaches 100% exactly at the end
# instead of jumping from 93%.
TOTAL_STEPS=14
CURRENT_STEP=0
SETUP_START=0

progress_bar() {
    local pct=$1
    local width=40
    local filled=$((pct * width / 100))
    local empty=$((width - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    echo -n "$bar"
}

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    CURRENT_STEP_NAME="$1"
    local pct=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    if [ "$pct" -gt 100 ]; then pct=100; fi
    local elapsed=""
    if [ "$SETUP_START" -gt 0 ]; then
        local now
        now=$(date +%s)
        local secs=$((now - SETUP_START))
        elapsed=" ${DIM}${secs}s${NC}"
    fi
    echo ""
    echo -e "  ${DIM}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${CYAN}$(progress_bar $pct)${NC} ${WHITE}${pct}%${NC}${elapsed}"
    echo -e "  ${BOLD}$1${NC}"
    echo ""
    plog ""
    plog "== STEP ${CURRENT_STEP}/${TOTAL_STEPS}: $1 =="
}

header() { step "$1"; }

# ── Pre-flight Checks ───────────────────────────────────────────────────
preflight_checks() {
    info "Running pre-flight checks..."

    # Check disk space (need at least 3GB)
    FREE_KB=$(df /opt 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$FREE_KB" ] && [ "$FREE_KB" -lt 3145728 ]; then
        error "Less than 3GB free disk space. Need at least 3GB."
        exit 1
    fi

    # Check available memory (warn if very low)
    FREE_MEM=$(free -m | awk '/^Mem:/ {print $7}')
    if [ -n "$FREE_MEM" ] && [ "$FREE_MEM" -lt 256 ]; then
        warn "Less than 256MB available memory. Performance may be degraded."
    fi

    info "Pre-flight checks passed."
}

# ── Package manager ──────────────────────────────────────────────────────
# Panel-driven updates run apt from inside dockpanel-agent. apt's needrestart
# hook restarts every unit linked against an upgraded library — and since the
# agent links libc, an ordinary libc6 upgrade puts dockpanel-agent.service on
# that list. needrestart then kills the very process that is streaming the
# update's own progress. The apt transaction survives (safe_command_unsandboxed
# runs it in a systemd-run transient scope, so it is not a child of the agent),
# but the NDJSON stream dies before its final {"type":"done"} line, and the
# panel reports a fully clean update as "Update completed with errors".
#
# Excluding only the agent keeps every other service restarting normally, which
# is the part that actually matters for security. The agent picks up the new
# libraries on the next reboot or panel-initiated agent restart.
dockpanel_needrestart_override() {
    [ -d /etc/needrestart ] || return 0
    mkdir -p /etc/needrestart/conf.d
    # Subscript assignment ADDS to the hash the main needrestart.conf already
    # filled in; writing `$nrconf{override_rc} = {...}` here would replace it
    # and silently drop the distro's own exclusions (dbus, display managers…).
    # No `.service` suffix in the regex — needrestart's own defaults are bare
    # prefixes, and this matches whether or not the suffix is present.
    cat > /etc/needrestart/conf.d/99-dockpanel.conf << 'NR_EOF'
# Managed by DockPanel — do not edit; rewritten by setup.sh/update.sh.
$nrconf{override_rc}{qr(^dockpanel-agent)} = 0;
1;
NR_EOF
}

detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MGR="apt"
        # Tell apt to wait up to 5 min for the dpkg lock instead of failing
        # immediately. Without this, agent installers (PHP, services, updates)
        # fail with "Could not get lock /var/lib/dpkg/lock-frontend" whenever
        # unattended-upgrades is running in the background — common on fresh
        # Debian 13 boots, where the auto-update kicks off right after install.
        mkdir -p /etc/apt/apt.conf.d
        cat > /etc/apt/apt.conf.d/99-dockpanel-lock-wait.conf << 'APT_EOF'
DPkg::Lock::Timeout "300";
APT_EOF
        dockpanel_needrestart_override
    elif command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
    elif command -v apk &> /dev/null; then
        # Alpine. `apk add` is already non-interactive (no -y flag exists) and
        # the index refresh is a separate command that pkg_update runs.
        PKG_MGR="apk"
    else
        error "No supported package manager found (apt/dnf/yum/apk)"
        exit 1
    fi
}

# Plain installers — meant to be wrapped in `run`, which captures their full
# output into $INSTALL_LOG (the old versions swallowed output, so failures
# left nothing to debug with).
pkg_install() {
    case "$PKG_MGR" in
        apt) apt-get install -y "$@" ;;
        dnf) dnf install -y "$@" ;;
        yum) yum install -y "$@" ;;
        apk) apk add "$@" ;;
    esac
}

pkg_update() {
    case "$PKG_MGR" in
        apt) apt-get update -y ;;
        dnf) dnf check-update || true ;;
        yum) yum check-update || true ;;
        apk) apk update ;;
    esac
}

# True when the apk index knows this package. The Alpine counterpart of
# apt_has_candidate, and needed for the same reason: `apk add` fails the WHOLE
# transaction on one unknown name, so the optional extras (PHP extensions that
# a given PHP version folds into core) have to be filtered before they are
# handed to it. `apk search -x` matches the exact name only; `-q` drops the
# version suffix.
apk_has_pkg() {
    apk search -xq "$1" > /dev/null 2>&1
}

# ── Firewall ─────────────────────────────────────────────────────────────
# Sibling of detect_pkg_manager: find the firewall the box is ALREADY
# enforcing with, so we configure that one instead of installing a second.
# Debian/Ubuntu images normally ship neither -> we install UFW. RHEL-family
# images ship firewalld running -> we use it. Never both (see the s265 note
# in install_recommended_services).
detect_firewall() {
    if command -v firewall-cmd &> /dev/null && firewall-cmd --state &> /dev/null; then
        FW_MGR="firewalld"
    elif command -v ufw &> /dev/null; then
        FW_MGR="ufw"
    else
        FW_MGR="none"
    fi
}

# Allow a port, e.g. `fw_allow 443/tcp`. Returns non-zero when there is no
# firewall to configure or the rule could not be added — callers must not
# assume success, which is exactly what the old code did.
fw_allow() {
    local port="$1"
    case "$FW_MGR" in
        firewalld) firewall-cmd --permanent --add-port="$port" > /dev/null 2>&1 ;;
        ufw)       ufw allow "$port" > /dev/null 2>&1 ;;
        *)         return 1 ;;
    esac
}

# firewalld stages --permanent rules; they do nothing until reloaded. UFW
# applies immediately, so this is a no-op there.
fw_reload() {
    case "$FW_MGR" in
        firewalld) firewall-cmd --reload > /dev/null 2>&1 || true ;;
    esac
}

# ── SELinux ──────────────────────────────────────────────────────────────
# On Enforcing systems (the RHEL family default) nginx may not open outbound
# TCP connections unless httpd_can_network_connect is set. The panel vhost
# proxies to the API on 127.0.0.1:3080 and every site vhost proxies to PHP-FPM
# or an app container, so without this EVERY request returns 502 — including
# from the box itself. s265 measured it: the boolean alone flipped 502 -> 200.
# The denial is dontaudit'ed, so nothing appears in ausearch or the journal;
# there is no breadcrumb to follow, which is why this must be set up front.
configure_selinux() {
    command -v getenforce &> /dev/null || return 0
    [ "$(getenforce 2>/dev/null)" = "Enforcing" ] || return 0

    header "SELinux"
    if command -v setsebool &> /dev/null && \
       run "Allowing nginx to reach the panel API (httpd_can_network_connect)" \
           setsebool -P httpd_can_network_connect on; then
        log "SELinux: nginx may now proxy to the API and to site backends"
        svc_ok "SELinux policy"
    else
        warn "SELinux is Enforcing and httpd_can_network_connect could not be set —"
        warn "the panel will answer 502 until you run: setsebool -P httpd_can_network_connect on"
        svc_fail "SELinux policy"
    fi
}

# True when apt has a real installation candidate for a package. `apt-cache
# show` is NOT enough — on Ubuntu 26.04 `php-opcache` still has a stanza but
# `Candidate: (none)` (OPcache became built-in in PHP 8.5), and one dead
# package fails an entire apt transaction.
apt_has_candidate() {
    local c
    # LC_ALL=C: apt-cache localises the "Candidate:" label (fr "Candidat :",
    # de "Installationskandidat:"), which would make the sed match nothing on
    # a non-English box and silently block the whole PHP install.
    c=$(LC_ALL=C apt-cache policy "$1" 2>/dev/null | sed -n 's/^  Candidate: //p')
    [ -n "$c" ] && [ "$c" != "(none)" ]
}

# ── Banner ───────────────────────────────────────────────────────────────
print_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
    ____             __   ____                  __
   / __ \____  _____/ /__/ __ \____ _____  ___  / /
  / / / / __ \/ ___/ //_/ /_/ / __ `/ __ \/ _ \/ /
 / /_/ / /_/ / /__/ ,< / ____/ /_/ / / / /  __/ /
/_____/\____/\___/_/|_/_/    \__,_/_/ /_/\___/_/
BANNER
    echo -e "${NC}"
    echo -e "  ${BOLD}Your server. Your rules. Your panel.${NC}"
    echo -e "  Free & open source — https://dockpanel.dev"
    echo ""
}

# ── Checks ───────────────────────────────────────────────────────────────
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root (or with sudo)"
        exit 1
    fi
}

check_source() {
    # Source check only needed if building from source
    if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
        return
    fi
    if [ ! -d "$AGENT_SRC/src" ]; then
        error "Cannot find agent source at $AGENT_SRC"
        error "Run this script from the DockPanel repository root,"
        error "or set INSTALL_FROM_RELEASE=1 to download pre-built binaries."
        exit 1
    fi
}

detect_os() {
    header "Detecting OS"

    if [ ! -f /etc/os-release ]; then
        error "Cannot detect OS — /etc/os-release not found"
        exit 1
    fi

    . /etc/os-release

    case "${ID:-}" in
        ubuntu|debian)
            log "Detected: $PRETTY_NAME"
            ;;
        centos|rocky|almalinux|fedora)
            log "Detected: $PRETTY_NAME"
            ;;
        amzn)
            log "Detected: $PRETTY_NAME (Amazon Linux)"
            ;;
        alpine)
            log "Detected: $PRETTY_NAME (Alpine — apk + OpenRC)"
            ;;
        *)
            warn "Untested OS: ${ID:-unknown} — proceeding anyway"
            ;;
    esac

    # Architecture check
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  DL_ARCH="amd64"; log "Architecture: x86_64" ;;
        aarch64) DL_ARCH="arm64"; log "Architecture: ARM64 (homelab ready)" ;;
        *) error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    # Check for swap on low-memory systems (Rust compilation needs ~1.5GB RAM)
    if [ "$INSTALL_FROM_RELEASE" != "1" ]; then
        local total_mem
        total_mem=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "0")
        local swap_total
        swap_total=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "0")

        if [ "$total_mem" -lt 1500 ] && [ "$swap_total" -lt 512 ]; then
            warn "Low memory detected (${total_mem}MB RAM, ${swap_total}MB swap)"
            warn "Rust compilation may fail. Creating 2GB swap file..."
            if [ ! -f /swapfile ]; then
                dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
                chmod 600 /swapfile
                mkswap /swapfile > /dev/null 2>&1
                swapon /swapfile
                log "Temporary 2GB swap file created"
            else
                log "Swap file already exists"
            fi
        fi
    fi
}

# ── Install Dependencies ────────────────────────────────────────────────
install_dependencies() {
    header "Installing Dependencies"

    run "Refreshing package index" pkg_update || true

    # EPEL for RHEL-family (needed for certbot, fail2ban, etc.)
    #
    # CRB ("CodeReady Builder", called PowerTools on EL8) must be enabled
    # ALONGSIDE it. EPEL's own installation instructions require it, because
    # EPEL packages routinely link against libraries EL keeps there — and a
    # missing CRB does not fail loudly, it fails at the point some LATER package
    # is installed. Measured on Rocky 9.8 (s268): `opendkim` and
    # `opendkim-tools` need `libmilter.so.1.0` (sendmail-milter) and
    # `libmemcached.so.11` (libmemcached-awesome), both CRB-only, so the mail
    # installer died on "nothing provides …" — while a name-availability probe
    # said all four packages were available, which is how the product came to
    # claim the packages resolved here.
    if [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
        run "Enabling EPEL repository" pkg_install epel-release || true
        # The repo id is `crb` on EL9+/Rocky/Alma and `powertools` on EL8.
        # Try both; neither existing is not fatal on its own.
        if command -v dnf >/dev/null 2>&1; then
            run "Enabling CRB repository (required by EPEL)" \
                sh -c 'dnf -y config-manager --set-enabled crb 2>/dev/null \
                    || dnf -y config-manager --set-enabled powertools 2>/dev/null \
                    || dnf -y install dnf-plugins-core >/dev/null 2>&1 && \
                       { dnf -y config-manager --set-enabled crb 2>/dev/null \
                      || dnf -y config-manager --set-enabled powertools 2>/dev/null; }' || true
        fi
    fi

    # openssh-client is the SFTP backup destination's runtime: the agent shells out
    # to scp/ssh for every SFTP upload. Present by default on the images we test, but
    # a dependency that happens to be satisfied is still an undeclared dependency.
    local BASE_PKGS="curl, openssl, ca-certificates, openssh-client"
    if [ "$PKG_MGR" = "apt" ]; then
        # gnupg + lsb-release only exist/matter on Debian-based
        run "Installing base packages (${BASE_PKGS}, gnupg, lsb-release)" \
            pkg_install curl openssl ca-certificates openssh-client gnupg lsb-release
    elif [ "$PKG_MGR" = "apk" ]; then
        # Alpine's names, plus four packages that are load-bearing on this
        # distro specifically rather than nice-to-have:
        #
        #   bash   — Alpine ships BusyBox ash. Every script here (and the
        #            update path the panel runs) is bash, and the shebang is
        #            #!/usr/bin/env bash.
        #   shadow — provides useradd/usermod/groupadd. BusyBox has adduser but
        #            NOT the names the agent shells out to when it creates a
        #            site's system user.
        #   grep   — GNU grep. BusyBox grep has no -P, and the vhost/IP probes
        #            in this file used to depend on it (they no longer do, but
        #            the agent and operator muscle memory still reach for it).
        #   iproute2 — BusyBox `ip` has no `route get`, which is how the
        #            interface IP for a domain-bound vhost is found.
        #   rsync  — the agent's site clone/git-deploy/staging paths all shell
        #            out to it. It is on every Debian and RHEL base image, which
        #            is why nothing ever declared it; Alpine does not ship it, so
        #            a clone or a git deploy on Alpine would fail at the copy.
        #   sudo   — WP-CLI runs as the site owner (`sudo -u www-data wp …`,
        #            routes/nginx.rs, services/wordpress.rs). Debian and RHEL
        #            base images have sudo; Alpine has neither sudo nor runuser,
        #            so those actions would fail on a box where everything else
        #            about the site works. Root needs no sudoers entry to use
        #            `-u`.
        run "Installing base packages (${BASE_PKGS}, bash, shadow, grep, iproute2, rsync, sudo)" \
            pkg_install curl openssl ca-certificates openssh-client gnupg bash shadow grep iproute2 rsync sudo
    else
        # RHEL-family names the ssh client package openssh-clients (plural).
        run "Installing base packages (${BASE_PKGS})" \
            pkg_install curl openssl ca-certificates openssh-clients
    fi

    # sshpass — required for PASSWORD-authenticated SFTP backup destinations, which
    # is the mode the panel's destination form offers first. Nothing installed it, so
    # on a fresh box every such destination failed at Test Connection with an opaque
    # 502 ("No such file or directory (os error 2)"); s288 measured SFTP as working
    # only because the test rig had apt-installed sshpass itself (s289).
    #
    # Best-effort ON PURPOSE, and not in BASE_PKGS: on RHEL-family sshpass comes from
    # EPEL, whose enablement above is itself `|| true`, and this script runs under
    # `set -e`. Making it mandatory would turn "no EPEL" into a failed install for
    # everyone — trading a backup-destination bug for a total install failure. When
    # it is missing the agent now says so by name, and key auth is unaffected.
    if ! run "Installing sshpass (password-authenticated SFTP backups)" pkg_install sshpass; then
        warn "sshpass could not be installed — SFTP backup destinations that authenticate"
        warn "by PASSWORD will not work. Install it manually, or use an SSH key instead."
    fi

    # Build tools required for Rust compilation (cmake for aws-lc-sys, gcc for ring)
    if [ "$INSTALL_FROM_RELEASE" != "1" ]; then
        if [ "$PKG_MGR" = "apt" ]; then
            run "Installing build tools (build-essential, cmake, pkg-config, libssl-dev)" \
                pkg_install build-essential cmake pkg-config libssl-dev
        elif [ "$PKG_MGR" = "apk" ]; then
            # build-base is Alpine's build-essential (gcc, g++, make, libc-dev).
            run "Installing build tools (build-base, cmake, pkgconf, openssl-dev)" \
                pkg_install build-base cmake pkgconf openssl-dev
        else
            run "Installing build tools (gcc, cmake, make, pkg-config, openssl-devel)" \
                pkg_install gcc gcc-c++ cmake make pkg-config openssl-devel
        fi
        log "Build tools installed"
    fi

    log "Base packages installed"
}

# Docker's convenience script points each distro at its own repo path under
# download.docker.com/linux/<distro>. For the RHEL rebuilds that path is a trap:
# `linux/rocky/9/` EXISTS and serves valid metadata, but upstream fills it with
# containerd.io and the plugins only — no docker-ce, no docker-ce-cli. So on
# Rocky the script cheerfully adds the repo and the very next command dies with
# `Error: Unable to find a match: docker-ce docker-ce-cli`, aborting the install
# at step 3 of 15. AlmaLinux fares worse still: it is not in the script's distro
# list at all, so it never reaches a repo.
#
# The packages under `linux/centos/$releasever` are plain el$releasever builds
# that install cleanly on every RHEL rebuild (that path carried 198 docker-ce
# RPMs when this was written, against rocky's 0), so point the clones there
# ourselves rather than at a directory upstream does not fill.
docker_repo_rhel_clone() {
    cat > /etc/yum.repos.d/docker-ce.repo << 'REPOEOF'
[docker-ce-stable]
name=Docker CE Stable - $basearch
baseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://download.docker.com/linux/centos/gpg
REPOEOF
}

# ── www-data user (Alpine) ───────────────────────────────────────────────
ensure_www_data_user() {
    # Debian and RHEL packages create `www-data`; Alpine ships only the GROUP
    # (gid 82, with nginx as a member), which is why `id nginx` looks like the
    # account is there while `chown www-data:www-data`, the PHP-FPM pool's
    # `user =` line and the agent's `sudo -u www-data` all fail. The panel names
    # that account in ~50 places, so it creates it rather than teaching every
    # one of them a second name for the same thing.
    #
    # The agent does this again at startup (`services::init::ensure_web_user`),
    # for boxes whose install predates this function and for fleet members;
    # both are idempotent, and doing it here means a fresh install is correct
    # before the agent has ever run — PHP-FPM refuses to start a pool whose
    # user is missing, so the ordering matters on the first PHP site.
    [ "$INIT" = "openrc" ] || return 0

    if ! grep -q '^www-data:' /etc/group; then
        addgroup -S www-data
    fi
    if grep -q '^www-data:' /etc/passwd; then
        log "www-data user already present"
        return 0
    fi
    # BusyBox adduser (Alpine's /usr/sbin/adduser): -S system account, -D no
    # password, -H no home directory, -G the group that already exists,
    # -s a shell that cannot log in.
    if adduser -S -D -H -G www-data -s /sbin/nologin www-data; then
        log "Created www-data user (Alpine ships the group only)"
    else
        warn "Could not create the www-data user — PHP-FPM pools will run as nobody"
    fi
}

install_docker() {
    header "Docker"

    if command -v docker &> /dev/null; then
        log "Docker already installed: $(docker --version | head -1)"
    else
        local DOCKER_OS_ID=""
        [ -f /etc/os-release ] && DOCKER_OS_ID=$(. /etc/os-release && echo "${ID:-}")

        case "$DOCKER_OS_ID" in
            rocky|almalinux|centos|rhel|ol)
                docker_repo_rhel_clone
                # --allowerasing is precautionary, not load-bearing: a stock
                # rockylinux:9 has no conflicting runtime and installs fine
                # without it (checked). It is here because RHEL-family CLOUD
                # images commonly preinstall podman/runc, which containerd.io
                # obsoletes — and dnf aborts the whole transaction on a conflict
                # rather than substituting.
                run "Installing Docker (docker-ce, el-clone repo)" \
                    bash -c 'dnf install -y --allowerasing docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
                ;;
            alpine)
                # get.docker.com does not support Alpine at all, and there is no
                # docker-ce repo for it: the packages come from the community
                # repo. `docker` pulls the engine + CLI, `docker-cli-compose`
                # is the compose v2 plugin (Alpine has no apt-style
                # docker-compose-plugin), and docker-openrc — which carries the
                # /etc/init.d/docker runscript this install then starts —
                # arrives by install_if, as nginx-openrc does.
                run "Installing Docker (apk: docker, docker-cli-compose)" \
                    pkg_install docker docker-cli-compose
                ;;
            *)
                run "Installing Docker (get.docker.com — takes a minute)" \
                    bash -c 'curl -fsSL https://get.docker.com | sh'
                ;;
        esac
        svc_enable_now docker
        if ! command -v docker &> /dev/null; then
            error "Docker installation failed — see $INSTALL_LOG"
            exit 1
        fi
        log "Docker installed: $(docker --version | head -1)"
    fi
    local dv
    dv=$(docker --version 2>/dev/null | sed -n 's/^Docker version \([0-9.]*\).*/\1/p')
    svc_ok "Docker${dv:+ $dv}"
}

install_nginx() {
    header "Nginx"

    if command -v nginx &> /dev/null; then
        log "Nginx already installed"
    else
        run "Installing Nginx" pkg_install nginx
        if ! command -v nginx &> /dev/null; then
            error "Nginx installation failed — see $INSTALL_LOG"
            exit 1
        fi
        log "Nginx installed"
    fi

    # Enable + start whether or not the install was ours, and NOT inside the else
    # above: Debian's nginx package starts and enables itself, so a box that
    # already had nginx was assumed to have it running. Alpine's arrives
    # DISABLED with nothing having started it, which would leave the panel
    # installed and unreachable on the very boxes this supports.
    svc_enable_now nginx

    local nv
    nv=$(nginx -v 2>&1 | sed -n 's|^nginx version: nginx/\([0-9.]*\).*|\1|p')
    svc_ok "Nginx${nv:+ $nv}"
}

install_node() {
    header "Node.js (for frontend build)"

    # Skip if using pre-built release (frontend comes as tarball)
    if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
        log "Skipping Node.js (using pre-built frontend)"
        return
    fi

    if command -v node &> /dev/null; then
        log "Node.js already installed: $(node --version)"
    else
        # `set -o pipefail` inside the wrapper is load-bearing: without it a
        # failed nodesource curl pipes nothing into `bash -` (which exits 0),
        # the `&&` then installs the distro's much-older Node, and the build
        # later dies cryptically. With pipefail the curl failure aborts here.
        if [ "$PKG_MGR" = "apk" ]; then
            # NodeSource publishes deb and rpm only — nothing for Alpine. The
            # distro's own nodejs is current enough to build the frontend with
            # (Alpine 3.22 ships 22.x, well past the Vite requirement), and it
            # is the only option that does not involve a third-party repo.
            run "Installing Node.js (apk: nodejs, npm)" pkg_install nodejs npm
        elif [ "$PKG_MGR" = "apt" ]; then
            run "Installing Node.js 20 LTS (nodesource)" \
                bash -c 'set -o pipefail; curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs'
        else
            run "Installing Node.js 20 LTS (nodesource)" \
                bash -c "set -o pipefail; curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && $PKG_MGR install -y nodejs"
        fi
        if ! command -v node &> /dev/null; then
            error "Node.js installation failed — see $INSTALL_LOG"
            exit 1
        fi
        log "Node.js installed: $(node --version)"
    fi
}

# ── Directories ──────────────────────────────────────────────────────────
create_directories() {
    header "Creating Directories"

    mkdir -p -m 0700 "$CONFIG_DIR"
    mkdir -p /var/run/dockpanel
    mkdir -p /etc/dockpanel/ssl
    mkdir -p /var/backups/dockpanel
    mkdir -p /var/www/acme

    # Ensure socket directory persists across tmpfiles cleanup/reboot.
    #
    # tmpfiles.d is a systemd mechanism: on an OpenRC box nothing reads it and
    # /etc/tmpfiles.d may not exist at all, so writing it there would be a
    # failure that means nothing. On OpenRC the directory is recreated by the
    # init script written in create_services, which is the equivalent guarantee.
    if [ "$INIT" = "systemd" ]; then
        mkdir -p /etc/tmpfiles.d
        echo "d /run/dockpanel 0755 root root -" > /etc/tmpfiles.d/dockpanel.conf
    fi

    # Create all directories required by the agent unit's ReadWritePaths, DERIVED
    # FROM THE UNIT rather than hand-mirrored here.
    #
    # Two different failure modes make this load-bearing, and the `-` prefix is
    # what separates them:
    #   * an UNPREFIXED entry that does not exist fails the namespace mount, and
    #     the agent does not start at all — loud, and therefore self-correcting.
    #   * a `-`-prefixed entry means "bind IF IT EXISTS". When it is absent
    #     systemd skips it silently, the unit starts and reports success, and
    #     every write under that path fails with `Read-only file system` for the
    #     lifetime of the namespace. Creating the directory afterwards does not
    #     help: the mount namespace is fixed at start, so only a restart recovers.
    #
    # This list was hand-copied into setup.sh AND update.sh and drifted (s269:
    # /var/spool/cron reached the unit and setup.sh but never update.sh, so an
    # upgraded box without a cron spool got a silently unwritable one — the exact
    # defect s268 had just fixed, re-entering through the upgrade door).
    # Deriving it from the single-source unit removes the drift, not one instance.
    _rwp="$(agent_rwp_dirs)"
    [ -n "$_rwp" ] && mkdir -p $_rwp
    # Paths the agent reaches through an escape hatch or that are not RWP entries.
    mkdir -p /run/opendkim /var/lib/nginx
    # The panel's own package operations (and the agent unit's ReadWritePaths
    # list) name the state directories of whichever package manager this box
    # has, so create that family's and not the other's.
    case "$PKG_MGR" in
        apt) mkdir -p /var/lib/dpkg /var/cache/apt /var/lib/apt ;;
        apk) mkdir -p /etc/apk /lib/apk/db /var/cache/apk ;;
    esac
    mkdir -p /var/lib/dockpanel/git /var/lib/dockpanel/recordings /var/cache/nginx/fastcgi
    touch /etc/opendkim.conf /run/nginx.pid 2>/dev/null || true

    log "Directories created"
}

# ── Secrets ──────────────────────────────────────────────────────────────
generate_secrets() {
    header "Generating Secrets"

    # Agent token (persistent — reuse if exists)
    if [ -f "$CONFIG_DIR/agent.token" ]; then
        AGENT_TOKEN=$(cat "$CONFIG_DIR/agent.token")
        log "Agent token: reusing existing"
    else
        AGENT_TOKEN=$(openssl rand -hex 16)
        echo "$AGENT_TOKEN" > "$CONFIG_DIR/agent.token"
        chmod 600 "$CONFIG_DIR/agent.token"
        log "Agent token: generated"
    fi

    # Reuse from existing api.env if present (idempotent reinstall)
    if [ -f "$CONFIG_DIR/api.env" ]; then
        EXISTING_DB_PW=$(grep '^DATABASE_URL=' "$CONFIG_DIR/api.env" 2>/dev/null | sed 's|.*://dockpanel:\(.*\)@.*|\1|' || true)
        EXISTING_JWT=$(grep '^JWT_SECRET=' "$CONFIG_DIR/api.env" 2>/dev/null | cut -d= -f2- || true)
    fi

    if [ -n "${EXISTING_DB_PW:-}" ] && [ -n "${EXISTING_JWT:-}" ]; then
        DB_PASSWORD="$EXISTING_DB_PW"
        JWT_SECRET="$EXISTING_JWT"
        log "DB password: reusing existing"
        log "JWT secret: reusing existing"
    else
        DB_PASSWORD=$(openssl rand -hex 24)
        JWT_SECRET=$(openssl rand -hex 32)
        log "DB password: generated"
        log "JWT secret: generated"
    fi
}

# ── PostgreSQL ───────────────────────────────────────────────────────────
setup_database() {
    header "PostgreSQL Database"

    if docker ps --format '{{.Names}}' | grep -c "^${DB_CONTAINER}$" >/dev/null; then
        log "PostgreSQL container already running"
    elif docker ps -a --format '{{.Names}}' | grep -c "^${DB_CONTAINER}$" >/dev/null; then
        log "Starting existing PostgreSQL container..."
        docker start "$DB_CONTAINER" > /dev/null 2>&1
    else
        # Remove stale volume from previous failed install (PostgreSQL ignores
        # POSTGRES_PASSWORD when an existing data directory is found, causing
        # password mismatch if the password was regenerated)
        if docker volume inspect dockpanel-pgdata > /dev/null 2>&1; then
            warn "Removing stale database volume from previous install..."
            docker volume rm dockpanel-pgdata > /dev/null 2>&1 || true
        fi

        # POSTGRES_PASSWORD is passed via the environment (bare `-e` inherits),
        # so the secret never appears in the logged command line.
        POSTGRES_PASSWORD="$DB_PASSWORD" \
        run "Creating PostgreSQL 16 container (pulls the image on first install)" \
            docker run -d \
            --name "$DB_CONTAINER" \
            --restart unless-stopped \
            -e POSTGRES_DB=dockpanel \
            -e POSTGRES_USER=dockpanel \
            -e POSTGRES_PASSWORD \
            -p "127.0.0.1:${DB_PORT}:5432" \
            -v dockpanel-pgdata:/var/lib/postgresql/data \
            postgres:16-alpine
        log "PostgreSQL container created (port $DB_PORT)"
    fi

    # Wait for PostgreSQL to be ready — ON THE TRANSPORT THE PROBE BELOW USES.
    #
    # ⚠ A readiness poll that omits the host answers over the container's own
    # unix socket, and the official image runs a SOCKET-ONLY temporary server
    # for the duration of initdb (started with an empty listen_addresses) before
    # it execs the real one. So a socket poll reports the database ready while
    # nothing is listening on TCP yet — measured at ~1.0-1.1s on an idle box and
    # over 20s on a loaded one, against a 2s poll grid — and the password probe
    # directly below, which MUST use the bridge address to land on the
    # scram-sha-256 rule, is then refused at the transport layer.
    #
    # The installer cannot tell a refused connection from a rejected password, so
    # it reads that as a mismatch and takes one of two wrong branches on a
    # database that is perfectly healthy: it prints "Database rejects this
    # install's password" and reconciles for no reason, or the ALTER lands in the
    # same window, fails, and the whole install aborts telling a brand-new
    # operator to destroy their volume. Polling the same transport the consumer
    # uses closes the window by construction — the temporary server cannot answer
    # over TCP at all.
    #
    # The trailing socket check is the no-bridge-address escape hatch: a
    # container on host networking has no address for the loop to poll, and the
    # password probe below cannot run against it either (it degrades to the
    # reconcile). Reaching it costs a full minute of waiting, which is why it is
    # placed AFTER the loop rather than inside it — an in-loop fallback would
    # fire on any box where the address is momentarily absent and silently
    # restore the very race this closes.
    if run "Waiting for PostgreSQL to accept connections" bash -c \
        "for i in \$(seq 1 30); do
             h=\$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $DB_CONTAINER 2>/dev/null | awk '{print \$1}')
             [ -n \"\$h\" ] && docker exec $DB_CONTAINER pg_isready -h \"\$h\" -U dockpanel && exit 0
             sleep 2
         done
         echo 'no TCP listener after 60s — falling back to a socket check (container has no bridge address?)'
         docker exec $DB_CONTAINER pg_isready -U dockpanel && exit 0
         exit 1"; then
        log "PostgreSQL ready"
    else
        error "PostgreSQL did not become ready within 60s"
        exit 1
    fi

    # Make the database agree with the password this install is about to write.
    #
    # The container is created ONCE, here, with whatever password this run holds;
    # api.env is not written until several steps later. So an install that dies
    # in between — a transient download failure is enough, and the failure
    # message tells the operator "re-running the installer is safe" — leaves a
    # container holding password A and no api.env at all. The next run finds no
    # api.env, generates password B, finds the container already present, starts
    # it unchanged, and writes B. The panel then crash-loops for ever on
    # `password authentication failed for user "dockpanel"`, and re-running never
    # helps because each run only mints another password the container has never
    # heard of. The reuse branch above cannot catch it: it keys on api.env
    # existing, which in this window it does not.
    #
    # Probe first with the target password, so a healthy install does no work and
    # an operator who has already fixed this by hand is not second-guessed. Only
    # when the database genuinely refuses it do we recover the password the
    # container was created with — the one value guaranteed to still work — and
    # ALTER the role. Both values are hex, from `openssl rand -hex`, so neither
    # can carry a quote into the SQL.
    # ⚠ THE PROBE MUST ACTUALLY AUTHENTICATE, and the obvious way of writing it
    # does not. The official Postgres image ships a pg_hba that trusts BOTH
    # `local` and `host 127.0.0.1/32`, so `docker exec … psql -U dockpanel`
    # connects over the container's own socket and succeeds with ANY password —
    # including the wrong one this check exists to detect. Written that way, the
    # branch below never ran, and a box left with mismatched credentials by an
    # interrupted install stayed broken exactly as it did before this check was
    # added: the API crash-looping on "password authentication failed".
    #
    # Only the trailing `host all all all scram-sha-256` rule demands a password,
    # and the way to land on it from here is the container's own BRIDGE address —
    # the same rule the API's TCP connection to the published port lands on.
    # Verified as a two-cell experiment on a real box: over the local socket a
    # deliberately wrong password is ACCEPTED; over the bridge address it is
    # REJECTED while the right one succeeds.
    local db_probe_host
    db_probe_host=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$DB_CONTAINER" 2>/dev/null | awk '{print $1}')
    # No bridge address ⇒ we cannot verify, so fall through to the reconcile
    # rather than assume health. Re-setting the role to the password we are about
    # to write is idempotent when it already matches.
    if [ -z "$db_probe_host" ] || ! docker exec -e PGPASSWORD="$DB_PASSWORD" "$DB_CONTAINER" \
            psql -h "$db_probe_host" -U dockpanel -d dockpanel -c 'SELECT 1' >/dev/null 2>&1; then
        warn "Database rejects this install's password — reconciling"
        local container_pw
        container_pw=$(docker inspect "$DB_CONTAINER" \
            --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
            | sed -n 's/^POSTGRES_PASSWORD=//p' | head -1)
        if [ -n "$container_pw" ] && docker exec -e PGPASSWORD="$container_pw" "$DB_CONTAINER" \
                psql -U dockpanel -d dockpanel \
                -c "ALTER USER dockpanel WITH PASSWORD '${DB_PASSWORD}';" >/dev/null 2>&1; then
            log "Database password reconciled with $CONFIG_DIR/api.env"
        else
            error "The database will not accept this install's password, and the password"
            error "it was created with could not be recovered. The panel cannot start."
            error ""
            error "TRY THIS FIRST — re-run the installer. It is safe, it keeps your data,"
            error "and it resolves this on its own in the common case:"
            error "  bash $0"
            error ""
            # ⚠ The by-hand recovery is only actionable once api.env EXISTS, and it
            # is written by create_services — several steps AFTER this function. On a
            # first install that aborts here the file is absent, so printing it
            # unconditionally left "destroy your volume" as the only instruction a
            # brand-new operator could actually follow.
            if [ -f "$CONFIG_DIR/api.env" ]; then
                error "Or set the role's password by hand to the one the panel expects:"
                error "  docker exec -it $DB_CONTAINER psql -U dockpanel -d dockpanel"
                error "  ALTER USER dockpanel WITH PASSWORD '<the DATABASE_URL password in $CONFIG_DIR/api.env>';"
                error ""
                error "Only if neither works, and it LOSES ALL DATABASE DATA:"
            else
                error "This install had not yet written $CONFIG_DIR/api.env, so there is no"
                error "stored password to match by hand. If re-running does not help — and"
                error "this LOSES ALL DATABASE DATA, which on a first install is none:"
            fi
            error "  docker rm -f $DB_CONTAINER && docker volume rm dockpanel-pgdata"
            exit 1
        fi
    fi
}

# ── Download Pre-built Binaries ──────────────────────────────────────────
INSTALLED_VERSION=""

# fetch_asset <asset-name> <dest> — download to a QUARANTINE temp file next to
# dest, verify its sha256 against the release checksums.txt, and only move it
# onto the live path AFTER it verifies — so the live executable path never
# holds unverified bytes (a mismatch aborts without touching the old binary).
# A checksum MISMATCH is fatal; a missing manifest only warns (availability
# must not brick an install, integrity must). Sets FETCH_VERIFIED=1/0 so the
# caller can report honestly whether a checksum was actually compared.
FETCH_VERIFIED=0

# dp_fetch <url> <out> — download, retrying the failures curl's own --retry will
# not.
#
# `--retry` covers connection refusals, timeouts and some HTTP codes. It does NOT
# cover a connection dropped MID-TRANSFER, which exits 56 — and 56 is precisely
# what the release CDN has now returned on three separate installs across two
# sessions, each time aborting the install at the binary download. `curl` grew
# `--retry-all-errors` for exactly this, but it landed in 7.71 and Ubuntu 20.04,
# which this installer supports, ships 7.68 — so the loop lives in shell, where
# every supported box can run it.
#
# ⚠ `rc=$?` on the line after a bare `if` reads 0, because a false `if` with no
# `else` is itself a success — the bug that shipped inside the last fix written
# for this same failure. Capture with `|| rc=$?` on the command itself.
dp_fetch() {
    local url="$1" out="$2" attempt=1 rc=0
    while [ "$attempt" -le 3 ]; do
        rc=0
        curl --retry 3 --retry-delay 2 -sfL "$url" -o "$out" || rc=$?
        [ "$rc" -eq 0 ] && return 0
        plog "  fetch attempt ${attempt}/3 exited ${rc} — $url"
        rm -f "$out"
        attempt=$((attempt + 1))
        [ "$attempt" -le 3 ] && sleep 3
    done
    return "$rc"
}

fetch_asset() {
    local asset="$1" dest="$2"
    local tmp="${dest}.dpdl.$$"
    FETCH_VERIFIED=0
    if ! run "Downloading ${asset}" dp_fetch "${BASE_URL}/${asset}" "$tmp"; then
        rm -f "$tmp"
        error "Download failed after 3 attempts: ${asset} — see $INSTALL_LOG"
        exit 1
    fi
    if [ -s "$CHECKSUMS_FILE" ]; then
        local want got
        want=$(awk -v n="$asset" '$2 == n {print $1; exit}' "$CHECKSUMS_FILE")
        if [ -n "$want" ]; then
            got=$(sha256sum "$tmp" | awk '{print $1}')
            if [ "$want" != "$got" ]; then
                rm -f "$tmp"
                error "Checksum MISMATCH for ${asset} — refusing to install a corrupt binary"
                plog "expected $want got $got"
                exit 1
            fi
            FETCH_VERIFIED=1
        fi
    fi
    # Atomic swap into the live path (never `cp` onto a running binary).
    mv -f "$tmp" "$dest"
}

# Truthful post-download line — "verified" ONLY when a checksum was compared.
fetched_msg() {
    local what="$1" path="$2"
    if [ "$FETCH_VERIFIED" = "1" ]; then
        log "${what} downloaded + verified ($(du -h "$path" | cut -f1))"
    else
        log "${what} downloaded ($(du -h "$path" | cut -f1)) — checksum not verified"
    fi
}

download_binaries() {
    header "Downloading Pre-built Binaries"

    # Which release to install.
    #
    # install.sh already reads DOCKPANEL_VERSION and clones that ref — but this,
    # its only consumer, used to always fetch releases/latest. So
    # `DOCKPANEL_VERSION=v2.31.2 install.sh` produced a v2.31.2 tree running
    # v2.34.2 binaries and printed "Version: v2.34.2" at the end (s261). Unit
    # files, nginx templates and install-agent.sh are deployed from the tree,
    # so that skew is the same class that stranded the v2.8.13 -> v2.8.14
    # upgrade path. Honour the pin here; `main` (the default) means "latest".
    local RELEASE_TAG
    if [ -n "${DOCKPANEL_VERSION:-}" ] && [ "${DOCKPANEL_VERSION}" != "main" ]; then
        RELEASE_TAG="$DOCKPANEL_VERSION"
        case "$RELEASE_TAG" in
            [0-9]*) RELEASE_TAG="v$RELEASE_TAG" ;;
        esac
        log "Pinned release: $RELEASE_TAG (DOCKPANEL_VERSION)"
    else
        RELEASE_TAG=$(curl --retry 3 --retry-delay 2 -sf "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
        log "Latest release: $RELEASE_TAG"
    fi

    if [ -z "$RELEASE_TAG" ]; then
        error "Could not determine latest release. Check https://github.com/${GITHUB_REPO}/releases"
        exit 1
    fi
    INSTALLED_VERSION="$RELEASE_TAG"
    BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_TAG}"

    # Checksum manifest first — every later download is verified against it.
    # mktemp (root-owned, O_EXCL, unpredictable) so a local user can't pre-seed
    # a manifest that would make a tampered binary "verify".
    CHECKSUMS_FILE=$(umask 077; mktemp /tmp/dockpanel-checksums.XXXXXX 2>/dev/null || echo "")
    # Through dp_fetch like every other release download, including this file's
    # own. This line kept a bare `curl --retry` after dp_fetch was written eleven
    # lines above it, so the one fetch that decides whether ANY binary gets
    # verified was the one still exposed to a mid-transfer drop — and its failure
    # is a warning, so a transient blip silently downgraded the whole install to
    # unverified. The fail-open policy is deliberate and is unchanged: three
    # attempts, then warn and continue.
    if [ -z "$CHECKSUMS_FILE" ] || ! dp_fetch "${BASE_URL}/checksums.txt" "$CHECKSUMS_FILE" 2>/dev/null; then
        warn "checksums.txt not available — skipping integrity verification"
        : > "$CHECKSUMS_FILE" 2>/dev/null || CHECKSUMS_FILE=""
    fi

    # Stop running services before overwriting their binaries. Re-running the
    # installer with services active causes `curl -o` to fail with "Text file
    # busy" (exit 23) because Linux refuses to overwrite a running executable.
    # Stopping is a no-op if the service is inactive or missing.
    svc_stop dockpanel-api dockpanel-agent || true

    fetch_asset "dockpanel-agent-linux-${DL_ARCH}" "$AGENT_BIN"
    chmod +x "$AGENT_BIN"
    fetched_msg "Agent" "$AGENT_BIN"

    fetch_asset "dockpanel-api-linux-${DL_ARCH}" "$API_BIN"
    chmod +x "$API_BIN"
    fetched_msg "API" "$API_BIN"

    fetch_asset "dockpanel-cli-linux-${DL_ARCH}" "$CLI_BIN"
    chmod +x "$CLI_BIN"
    fetched_msg "CLI" "$CLI_BIN"

    local FE_TARBALL
    FE_TARBALL=$(umask 077; mktemp /tmp/dockpanel-frontend.XXXXXX.tar.gz 2>/dev/null || echo /tmp/dockpanel-frontend.tar.gz)
    fetch_asset "dockpanel-frontend.tar.gz" "$FE_TARBALL"

    # Extract frontend — need a target directory
    local FE_DIR="/opt/dockpanel/frontend"
    mkdir -p "$FE_DIR"
    tar xzf "$FE_TARBALL" -C "$FE_DIR"
    rm -f "$FE_TARBALL"
    [ -n "$CHECKSUMS_FILE" ] && rm -f "$CHECKSUMS_FILE"

    # If dist/ is nested inside, flatten it
    if [ -d "$FE_DIR/dist" ]; then
        FRONTEND_DIST="$FE_DIR/dist"
    else
        FRONTEND_DIST="$FE_DIR"
    fi

    log "Frontend extracted to $FRONTEND_DIST"
}

# ── Cargo Build with Progress ────────────────────────────────────────────
cargo_build_with_progress() {
    local src_dir="$1"
    local label="$2"
    local count=0
    local start_time
    start_time=$(date +%s)

    (cd "$src_dir" && $CARGO_CMD build --release 2>&1) | while IFS= read -r line; do
        if echo "$line" | grep -cE '^\s*Compiling ' >/dev/null; then
            count=$((count + 1))
            local crate_name
            crate_name=$(echo "$line" | sed 's/.*Compiling \([^ ]*\).*/\1/')
            local elapsed=$(( $(date +%s) - start_time ))
            printf "\r    ${DIM}%s: %d crates (%ds) → %s${NC}                    " "$label" "$count" "$elapsed" "$crate_name" >&2
        elif echo "$line" | grep -cE '^\s*Finished ' >/dev/null; then
            local elapsed=$(( $(date +%s) - start_time ))
            printf "\r    ${DIM}%s: %d crates compiled in %ds${NC}                              \n" "$label" "$count" "$elapsed" >&2
        fi
    done
}

# ── Build Binaries ───────────────────────────────────────────────────────
build_binaries() {
    header "Building Binaries"

    # Check for Rust toolchain
    if command -v cargo &> /dev/null; then
        CARGO_CMD="cargo"
    elif [ -f "$HOME/.cargo/bin/cargo" ]; then
        CARGO_CMD="$HOME/.cargo/bin/cargo"
    else
        log "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
        CARGO_CMD="$HOME/.cargo/bin/cargo"
    fi

    # Stop running services so cp can overwrite their binaries (see note in
    # download_binaries — same "Text file busy" trap).
    svc_stop dockpanel-api dockpanel-agent || true

    # Build agent
    log "Building agent..."
    cargo_build_with_progress "$AGENT_SRC" "Agent"
    cp "$AGENT_SRC/target/release/dockpanel-agent" "$AGENT_BIN"
    chmod +x "$AGENT_BIN"
    log "Agent built ($(du -h "$AGENT_BIN" | cut -f1))"

    # Build API
    log "Building API..."
    cargo_build_with_progress "$API_SRC" "API"
    cp "$API_SRC/target/release/dockpanel-api" "$API_BIN"
    chmod +x "$API_BIN"
    log "API built ($(du -h "$API_BIN" | cut -f1))"

    # Build CLI
    log "Building CLI..."
    cargo_build_with_progress "$CLI_SRC" "CLI"
    cp "$CLI_SRC/target/release/dockpanel" "$CLI_BIN"
    chmod +x "$CLI_BIN"
    log "CLI built ($(du -h "$CLI_BIN" | cut -f1))"

    INSTALLED_VERSION=$(git -C "$REPO_DIR" describe --tags --always 2>/dev/null || echo "")
    INSTALLED_VERSION="${INSTALLED_VERSION:+${INSTALLED_VERSION} (built from source)}"
}

# ── Build Frontend ───────────────────────────────────────────────────────
build_frontend() {
    header "Building Frontend"

    if [ ! -d "$FRONTEND_DIR" ]; then
        warn "Frontend source not found at $FRONTEND_DIR — skipping"
        return
    fi

    log "Installing npm dependencies..."
    # `npm ci` installs EXACTLY the committed package-lock.json — the tree the
    # audit gates actually scanned. `npm install` re-resolves and can pull
    # versions no scanner here has ever seen, which silently un-ships a
    # dependency patch. Keep the fallback (a box whose lock has drifted should
    # still install) but never let it happen quietly, and never discard the
    # reason: sending both streams to /dev/null is how the RHEL agent install
    # failed for a year printing nothing at all.
    if ! (cd "$FRONTEND_DIR" && npm ci --silent); then
        warn "npm ci failed (reason above) — falling back to 'npm install'"
        warn "Dependencies will be RE-RESOLVED; the tree may differ from the audited lockfile"
        if ! (cd "$FRONTEND_DIR" && npm install --silent); then
            error "npm install also failed — the frontend build below will likely fail too"
        fi
    fi

    log "Building frontend..."
    (cd "$FRONTEND_DIR" && npx vite build 2>&1 | tail -3)
    log "Frontend built at $FRONTEND_DIR/dist/"
}

# ── Services ─────────────────────────────────────────────────────────────
# The panel is two long-running processes (agent, API) and, on systemd only, an
# opt-in MCP server. Which service manager this box has decides how they are
# defined and started — see detect_init. Nothing in here names systemctl
# directly any more: the svc_* helpers above dispatch.
create_services() {
    header "Services"

    # The API environment, written before any service definition refers to it.
    # Agent: no file needed on a panel box (EnvironmentFile=- in the unit, i.e.
    # "read if it exists"); that prefix is what lets one definition serve both a
    # panel box and a fleet member.
    local API_BASE_URL=""
    if [ -n "$PANEL_DOMAIN" ]; then
        API_BASE_URL="https://${PANEL_DOMAIN}"
    fi

    cat > "$CONFIG_DIR/api.env" << EOF
DATABASE_URL=postgresql://dockpanel:${DB_PASSWORD}@127.0.0.1:${DB_PORT}/dockpanel
JWT_SECRET=${JWT_SECRET}
AGENT_SOCKET=/var/run/dockpanel/agent.sock
AGENT_TOKEN=${AGENT_TOKEN}
LISTEN_ADDR=127.0.0.1:3080
BASE_URL=${API_BASE_URL}
EOF
    chmod 600 "$CONFIG_DIR/api.env"

    case "$INIT" in
        systemd) install_systemd_units ;;
        openrc)  install_openrc_services ;;
        *)       install_no_service_manager; return 0 ;;
    esac

    # Start agent. Enable/stop are best-effort so a re-run over a running panel
    # converges rather than tripping over an already-stopped service.
    svc_enable dockpanel-agent > /dev/null 2>&1 || true
    svc_stop dockpanel-agent > /dev/null 2>&1 || true
    svc_start dockpanel-agent > /dev/null 2>&1 || true

    if wait_for_unit dockpanel-agent; then
        log "Agent service running"
    else
        error "Agent failed to start"
        service_logs dockpanel-agent
        exit 1
    fi

    # Start API
    svc_enable dockpanel-api > /dev/null 2>&1 || true
    svc_stop dockpanel-api > /dev/null 2>&1 || true
    svc_start dockpanel-api > /dev/null 2>&1 || true

    if wait_for_unit dockpanel-api; then
        log "API service running"
    else
        error "API failed to start"
        service_logs dockpanel-api
        exit 1
    fi
}

# Last lines of a service's own log, whichever manager keeps them.
service_logs() {
    case "$INIT" in
        systemd)
            journalctl -u "$1" --no-pager -n 10 2>/dev/null || true
            ;;
        openrc)
            local log="/var/log/${1}.log"
            if [ -s "$log" ]; then
                tail -n 10 "$log" 2>/dev/null || true
            else
                echo "  (no log at ${log} yet — check rc-service $1 status)"
            fi
            ;;
        *)
            echo "  (no service manager on this box — see the manual start commands in the summary)"
            ;;
    esac
    return 0
}

install_systemd_units() {
    # Agent service — deploy from repo (single source of truth: panel/agent/dockpanel-agent.service)
    cp "$AGENT_SRC/dockpanel-agent.service" /etc/systemd/system/dockpanel-agent.service
    chmod 644 /etc/systemd/system/dockpanel-agent.service

    # MCP server — deploy from repo (single source of truth: panel/mcp/dockpanel-mcp.service).
    # Installed but deliberately NOT enabled/started: v1 has no settings toggle
    # or mint-key UI yet (session 2), so a fresh install would just log
    # "no panel API key configured" forever. `systemctl enable --now
    # dockpanel-mcp` is a documented manual step once an operator has minted a
    # key at Settings → API Keys and saved it to /etc/dockpanel/mcp.token.
    if [ -f "$MCP_SRC/dockpanel-mcp.service" ]; then
        cp "$MCP_SRC/dockpanel-mcp.service" /etc/systemd/system/dockpanel-mcp.service
        chmod 644 /etc/systemd/system/dockpanel-mcp.service
    fi

    # API service
    cat > /etc/systemd/system/dockpanel-api.service << 'EOF'
[Unit]
Description=DockPanel API
After=network.target docker.service dockpanel-agent.service
Wants=dockpanel-agent.service
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/local/bin/dockpanel-api
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=/etc/dockpanel/api.env
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectSystem=no
ReadWritePaths=/var/run/dockpanel /tmp
MemoryMax=1G
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

# OpenRC services for Alpine (and any other box without systemd).
#
# The systemd units are NOT reused: OpenRC reads /etc/init.d runscripts, and a
# .service file is inert there. What is mirrored is the behaviour that matters —
# start, restart on failure, environment (api.env / agent.env), the socket's
# group and mode, and the log destination — so `rc-service dockpanel-api
# status` and `tail /var/log/dockpanel-api.log` mean what `systemctl status`
# and `journalctl -u` mean on a systemd box.
#
# supervise-daemon is OpenRC's own restarter (Restart=always's equivalent); it
# respawns the process on exit and owns the pidfile, so no start-stop-daemon
# flags have to be guessed at.
install_openrc_services() {
    cat > /etc/init.d/dockpanel-agent << 'AGENTEOF'
#!/sbin/openrc-run
# Managed by DockPanel — rewritten by scripts/setup.sh (re-run it to refresh).
name="dockpanel-agent"
description="DockPanel Agent"

command="/usr/local/bin/dockpanel-agent"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
pidfile="/run/dockpanel-agent.pid"
output_log="/var/log/dockpanel-agent.log"
error_log="/var/log/dockpanel-agent.log"

depend() {
    need net
    use dns docker nginx
}

start_pre() {
    # The panel and the agent resolve `systemctl` from PATH; on OpenRC boxes
    # that name is a compatibility shim living in /usr/local/bin (see
    # install_systemctl_shim), so PATH has to name it first.
    export PATH="/usr/local/sbin:/usr/local/bin:$PATH"
    mkdir -p /run/dockpanel /var/lib/dockpanel/git

    # agent.env is a fleet member's file; a panel box has none, which is the
    # same "read it if it exists" semantics the unit's EnvironmentFile=- has.
    if [ -r /etc/dockpanel/agent.env ]; then
        set -a
        . /etc/dockpanel/agent.env
        set +a
    fi
    export RUST_LOG="${RUST_LOG:-info}"
}

start_post() {
    sleep 1
    chgrp nginx /var/run/dockpanel/agent.sock 2>/dev/null
    chmod 660 /var/run/dockpanel/agent.sock 2>/dev/null
    return 0
}
AGENTEOF

    cat > /etc/init.d/dockpanel-api << 'APIEOF'
#!/sbin/openrc-run
# Managed by DockPanel — rewritten by scripts/setup.sh (re-run it to refresh).
name="dockpanel-api"
description="DockPanel API"

command="/usr/local/bin/dockpanel-api"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
pidfile="/run/dockpanel-api.pid"
output_log="/var/log/dockpanel-api.log"
error_log="/var/log/dockpanel-api.log"

depend() {
    need net
    after docker
    use dns
    want dockpanel-agent
}

start_pre() {
    export PATH="/usr/local/sbin:/usr/local/bin:$PATH"
    mkdir -p /run/dockpanel
    if [ -r /etc/dockpanel/api.env ]; then
        set -a
        . /etc/dockpanel/api.env
        set +a
    fi
    export RUST_LOG="${RUST_LOG:-info}"
}
APIEOF

    chmod 755 /etc/init.d/dockpanel-agent /etc/init.d/dockpanel-api
    touch /var/log/dockpanel-agent.log /var/log/dockpanel-api.log
    chmod 640 /var/log/dockpanel-agent.log /var/log/dockpanel-api.log

    install_systemctl_shim
}

# A `systemctl` compatibility shim, installed ONLY on boxes that have no systemd.
#
# The panel's own code was written against systemd and calls `systemctl` by name
# in dozens of places (panel/agent/src/services/{nginx,pkg,security,diagnostics,
# app_process,sftp_accounts,mail}.rs): reload PHP-FPM, restart fail2ban, restart
# sshd, ask whether a service is active, apply an app's unit. On an OpenRC box
# every one of those calls fails with ENOENT — the feature does not degrade, it
# reports "No such file or directory" — and the Rust code is not something this
# script can change.
#
# So OpenRC gets a translator. It covers the verbs and flags the panel actually
# passes, and translates Alpine's versioned service names (php-fpm84) to the
# Debian spelling the agent builds (php8.4-fpm). It is deliberately NOT a
# systemd implementation: unit files are not parsed, sandbox directives do not
# exist here, and `show -p ...` answers from a small fixed table. Anything the
# panel needs beyond that has to be handled in Rust.
#
# Never written over a real systemctl: the guard is the whole reason this is
# safe to call unconditionally.
install_systemctl_shim() {
    if [ "$INIT" = "systemd" ] || command -v systemctl > /dev/null 2>&1; then
        return 0
    fi

    cat > /usr/local/bin/systemctl << 'SHIMEOF'
#!/bin/sh
# DockPanel systemctl shim for OpenRC — installed by scripts/setup.sh.
# Translates the systemctl verbs the panel uses onto rc-service/rc-update.
set -u

# php8.4-fpm (the name the agent builds) → php-fpm84 (Alpine's runscript).
translate() {
    case "$1" in
        php[0-9]*-fpm)
            v=$(printf '%s' "$1" | sed -n 's/^php\([0-9]*\)\.\([0-9]*\)-fpm$/\1\2/p')
            if [ -n "$v" ] && [ -x "/etc/init.d/php-fpm$v" ]; then
                printf 'php-fpm%s' "$v"
                return
            fi
            for s in /etc/init.d/php-fpm*; do
                if [ -x "$s" ]; then
                    basename "$s"
                    return
                fi
            done
            printf '%s' "$1"
            ;;
        *.service)
            printf '%s' "${1%.service}"
            ;;
        *)
            printf '%s' "$1"
            ;;
    esac
}

if [ $# -eq 0 ]; then
    exit 1
fi

verb="$1"
shift

now=0
value_only=0
prop=""
svcs=""
while [ $# -gt 0 ]; do
    case "$1" in
        --now) now=1 ;;
        --value) value_only=1 ;;
        -p|--property) shift; prop="${1:-}" ;;
        --quiet|-q|--no-pager|--full|--force|-f|--system|--user) : ;;
        --*) : ;;
        *) svcs="$svcs $1" ;;
    esac
    shift
done

rc=0

# These two verbs take no service operands, so they are answered BEFORE the
# per-service loop below — see the note in install-agent.sh's shim. In the loop
# they would be code that never runs (`svcs` is empty for them), which is how
# `list-units` came to print nothing and how the panel came to report "No
# PHP-FPM service installed on this host" on a box where it is running.
if [ "$verb" = "list-units" ]; then
    for f in /etc/init.d/*; do
        [ -f "$f" ] || continue
        s=$(basename "$f")
        if [ -e "/run/openrc/started/$s" ]; then
            act=active; sub=running
        else
            act=inactive; sub=dead
        fi
        printf '%s.service loaded %s %s\n' "$s" "$act" "$sub"
    done
    exit 0
fi
if [ "$verb" = "list-unit-files" ]; then
    for f in /etc/init.d/*; do
        [ -f "$f" ] || continue
        s=$(basename "$f")
        if [ -e "/etc/runlevels/default/$s" ]; then
            st=enabled
        else
            st=disabled
        fi
        printf '%s.service\t%s\n' "$s" "$st"
    done
    exit 0
fi

for one in $svcs; do
    s=$(translate "$one")
    case "$verb" in
        start)    rc-service "$s" start || rc=$? ;;
        stop)     rc-service "$s" stop || rc=$? ;;
        restart)  rc-service "$s" restart || rc=$? ;;
        reload|try-reload-or-restart)
                  rc-service "$s" reload 2>/dev/null || rc-service "$s" restart || rc=$? ;;
        enable)   rc-update add "$s" default || rc=$? ;;
        disable)  rc-update del "$s" default 2>/dev/null || true ;;
        mask|unmask) : ;;
        is-active)
                  if rc-service "$s" status > /dev/null 2>&1; then
                      echo active
                  else
                      echo inactive; rc=3
                  fi ;;
        is-enabled)
                  if [ -e "/etc/runlevels/default/$s" ]; then
                      echo enabled
                  else
                      echo disabled; rc=1
                  fi ;;
        is-failed)
                  if rc-service "$s" status > /dev/null 2>&1; then echo active; else echo failed; fi ;;
        status)   rc-service "$s" status || rc=$? ;;
        show)
                  # The agent asks `show dockpanel-agent -p LoadError --value` to
                  # decide whether the unit it just wrote is loadable. There is no
                  # unit file here, so there is nothing to reject: answer with an
                  # empty LoadError, which is what "fine" looks like.
                  if [ "$prop" = "LoadError" ]; then
                      [ "$value_only" = "1" ] && : || echo "LoadError="
                  else
                      [ "$value_only" = "1" ] && : || echo "Id=$s"
                  fi ;;
        list-unit-files|list-units) : ;;
        daemon-reload|reset-failed|kill|set-property) : ;;
        *)
                  echo "systemctl (DockPanel OpenRC shim): unsupported verb '$verb'" >&2
                  exit 1 ;;
    esac
done

if [ "$verb" = "enable" ] && [ "$now" = "1" ]; then
    for one in $svcs; do
        s=$(translate "$one")
        rc-service "$s" start > /dev/null 2>&1 || true
    done
fi

exit $rc
SHIMEOF

    chmod 755 /usr/local/bin/systemctl

    # journalctl is reached for by the panel's diagnostics too; a shim that
    # drains the OpenRC logs is better than "No such file or directory".
    if [ ! -e /usr/local/bin/journalctl ]; then
        cat > /usr/local/bin/journalctl << 'JEOF'
#!/bin/sh
# DockPanel journalctl shim for OpenRC — prints the tail of the log named by -u.
set -u
unit=""
n=20
while [ $# -gt 0 ]; do
    case "$1" in
        -u|--unit) shift; unit="${1:-}" ;;
        -n|--lines) shift; n="${1:-20}" ;;
        *) : ;;
    esac
    shift
done
if [ -n "$unit" ] && [ -r "/var/log/${unit}.log" ]; then
    tail -n "$n" "/var/log/${unit}.log"
elif [ -r /var/log/messages ]; then
    tail -n "$n" /var/log/messages
fi
exit 0
JEOF
        chmod 755 /usr/local/bin/journalctl
    fi

    log "systemctl/journalctl compatibility shims installed for OpenRC"
}

# No service manager at all (bare container, chroot). Installing nothing here
# and saying so beats printing a success banner over services that were never
# started — and the operator gets the exact commands to run instead.
install_no_service_manager() {
    warn "No service manager found (no systemd, no OpenRC) — the panel will not"
    warn "start automatically on this box. Start it by hand:"
    warn "  /usr/local/bin/dockpanel-agent > /var/log/dockpanel-agent.log 2>&1 &"
    warn "  set -a; . /etc/dockpanel/api.env; set +a; /usr/local/bin/dockpanel-api > /var/log/dockpanel-api.log 2>&1 &"
    svc_fail "Service manager (start the panel by hand)"
}

# ── Panel TLS ────────────────────────────────────────────────────────────
# The panel's very first screen asks the operator to CREATE an admin password.
# Without a domain there is no Let's Encrypt certificate, and the panel used to
# serve that screen over plain HTTP — putting the credential on the wire in
# cleartext on the exact path the README advertises. A self-signed certificate
# is not a trusted certificate, but a browser warning the operator can reason
# about beats a password nobody can see leaving the machine.
# Every address this box answers on, IPv4 and IPv6, one per line.
#
# `hostname -I` is the obvious way to ask and the wrong one: BusyBox's hostname
# (Alpine, and every minimal container) has no -I at all — it prints "unrecognized
# option: I" and exits non-zero. `ip -o addr` is present wherever iproute2 is,
# which setup.sh installs, and the literal-hostname fallback covers a box with
# neither.
local_ip_addresses() {
    if command -v ip > /dev/null 2>&1; then
        ip -o addr show 2>/dev/null | awk '
            $3 == "inet" || $3 == "inet6" {
                split($4, a, "/"); if (a[1] != "127.0.0.1" && a[1] != "::1") print a[1]
            }' || true
    elif command -v hostname > /dev/null 2>&1; then
        hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true
    fi
}

# The address this box would use to reach the internet — i.e. the one on the
# default route, which is the address an operator's browser reaches it on.
interface_ip() {
    ip route get 8.8.8.8 2>/dev/null | awk '
        { for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true
}

detect_server_ip() {
    curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || \
    local_ip_addresses | head -1 || \
    echo ""
}

generate_self_signed_panel_cert() {
    local ip="$1"
    local dir="${CONFIG_DIR}/ssl"

    mkdir -p "$dir"
    chmod 700 "$dir"

    # Idempotent — never clobber a certificate the operator may have replaced
    # with their own, and never regenerate on a re-run (that would invalidate
    # the fingerprint anyone has already accepted in their browser).
    if [ -s "$dir/panel.crt" ] && [ -s "$dir/panel.key" ]; then
        return 0
    fi

    # Name every address the panel can actually be reached on, not just the
    # public one: on a NAT'd or LAN box the operator types the local address,
    # and a certificate that doesn't name it adds a second, avoidable warning
    # on top of the untrusted-issuer one.
    local san="DNS:localhost,IP:127.0.0.1"
    [ -n "$ip" ] && san="${san},IP:${ip}"
    local local_ip
    for local_ip in $(local_ip_addresses); do
        # IPv4/IPv6 literals only, and never repeat one already listed.
        case ",${san}," in
            *",IP:${local_ip},"*) continue ;;
        esac
        san="${san},IP:${local_ip}"
    done

    # -addext needs OpenSSL 1.1.1+. Every distro we support ships 3.x, but fall
    # back to a SAN-less certificate rather than dropping to plain HTTP.
    if openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -subj "/CN=${ip:-dockpanel}" -addext "subjectAltName=${san}" \
            -keyout "$dir/panel.key" -out "$dir/panel.crt" > /dev/null 2>&1 ||
       openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -subj "/CN=${ip:-dockpanel}" \
            -keyout "$dir/panel.key" -out "$dir/panel.crt" > /dev/null 2>&1; then
        chmod 600 "$dir/panel.key"
        chmod 644 "$dir/panel.crt"
        return 0
    fi

    rm -f "$dir/panel.key" "$dir/panel.crt"
    return 1
}

# ── Nginx layout ─────────────────────────────────────────────────────────
# True when this nginx's nginx.conf already pulls in /etc/nginx/sites-enabled.
nginx_reads_sites_enabled() {
    awk '/^[[:space:]]*include[[:space:]]+\/etc\/nginx\/sites-enabled\/\*\.conf;/ { found = 1 } END { exit !found }' \
        /etc/nginx/nginx.conf 2>/dev/null
}

# Insert `include /etc/nginx/sites-enabled/*.conf;` INSIDE the http block.
#
# Position is the whole point: appending at end-of-file lands the include at
# main context, and a `server {}` block is only legal inside `http`, so every
# vhost it pulled in would be a config error rather than a site. The brace count
# finds the http block's real closing brace — a nested block's `}` ends sooner,
# which is the bug that once left half a server block commented out on RHEL.
add_sites_enabled_include() {
    awk '
      { lines[NR] = $0 }
      /^[[:space:]]*http[[:space:]]*\{/ { http = NR }
      END {
        if (!http) { for (i = 1; i <= NR; i++) print lines[i]; exit 1 }
        depth = 0; close_line = 0
        for (i = http; i <= NR; i++) {
          depth += gsub(/\{/, "{", lines[i]) - gsub(/\}/, "}", lines[i])
          if (depth <= 0) { close_line = i; break }
        }
        if (!close_line) { for (i = 1; i <= NR; i++) print lines[i]; exit 1 }
        for (i = 1; i <= NR; i++) {
          if (i == close_line) print "    include /etc/nginx/sites-enabled/*.conf;"
          print lines[i]
        }
      }
    ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.dockpanel-new &&
        mv /etc/nginx/nginx.conf.dockpanel-new /etc/nginx/nginx.conf
    rm -f /etc/nginx/nginx.conf.dockpanel-new
}

# Put this box's nginx on the layout the rest of the product already speaks.
#
# Alpine's nginx puts vhosts in /etc/nginx/http.d and includes `conf.d/*.conf`
# from the MAIN context, where a `server {}` block is a syntax error — so
# neither directory this script used to write to is where a vhost belongs. The
# agent (Rust) probes for /etc/nginx/sites-enabled and, absent that, falls back
# to /etc/nginx/conf.d; both are wrong here, and patching the agent is not this
# script's job. So the box is made to look like the layout the agent already
# understands: sites-available/sites-enabled, included from the http block.
# That is Debian's convention, which means the panel's own vhost, every
# agent-written site vhost, and every parked (disabled) vhost land exactly where
# the code that reads them expects to find them.
#
# Guarded on the include actually landing: a sites-enabled directory that
# nginx.conf does not include is worse than no directory at all — the panel
# writes a vhost into it, nginx -t passes, and the site simply never exists.
prepare_nginx_layout() {
    if [ -d /etc/nginx/sites-enabled ] || [ ! -d /etc/nginx/http.d ]; then
        return 0
    fi

    mkdir -p /etc/nginx/sites-available

    if nginx_reads_sites_enabled; then
        mkdir -p /etc/nginx/sites-enabled
    elif add_sites_enabled_include; then
        mkdir -p /etc/nginx/sites-enabled
        log "nginx: now reads site vhosts from /etc/nginx/sites-enabled"
    else
        warn "Could not add the sites-enabled include to nginx.conf — writing vhosts to http.d instead"
    fi

    # Alpine ships a catch-all server on :80 in http.d that answers for every
    # unconfigured name — Debian's sites-enabled/default plays the same role.
    # Parked rather than deleted, so nothing is lost if it is wanted back.
    if [ -f /etc/nginx/http.d/default.conf ]; then
        mv -f /etc/nginx/http.d/default.conf /etc/nginx/http.d/default.conf.disabled
    fi
}

# ── Nginx for Panel ──────────────────────────────────────────────────────
configure_nginx() {
    header "Configuring Nginx"

    # Determine nginx group (www-data on Debian, nginx on RHEL)
    if id -g www-data &> /dev/null; then
        NGINX_GROUP="www-data"
    elif id -g nginx &> /dev/null; then
        NGINX_GROUP="nginx"
    else
        NGINX_GROUP="root"
    fi

    # ── Alpine's nginx layout ────────────────────────────────────────────
    prepare_nginx_layout

    # Determine config directory
    if [ -d /etc/nginx/sites-enabled ]; then
        NGINX_CONF="/etc/nginx/sites-enabled/dockpanel-panel.conf"
    elif [ -d /etc/nginx/http.d ]; then
        NGINX_CONF="/etc/nginx/http.d/dockpanel-panel.conf"
    elif [ -d /etc/nginx/conf.d ]; then
        NGINX_CONF="/etc/nginx/conf.d/dockpanel-panel.conf"
    else
        NGINX_CONF="/etc/nginx/conf.d/dockpanel-panel.conf"
        mkdir -p /etc/nginx/conf.d
    fi

    # Determine frontend dist path
    local FE_ROOT
    if [ "$INSTALL_FROM_RELEASE" = "1" ] && [ -n "${FRONTEND_DIST:-}" ]; then
        FE_ROOT="$FRONTEND_DIST"
    else
        FE_ROOT="${FRONTEND_DIR}/dist"
    fi

    # Drop install-agent.sh into FE_ROOT so the panel's SPA-fallback nginx config
    # serves it via `try_files $uri` (instead of returning the SPA index.html).
    # Backend at panel/backend/src/routes/servers.rs prints `curl … {panel_url}/install-agent.sh`
    # in the multi-server install command — this is what makes that URL resolve. (#56, v2.8.14)
    if [ -f "$REPO_DIR/scripts/install-agent.sh" ] && [ -d "$FE_ROOT" ]; then
        cp "$REPO_DIR/scripts/install-agent.sh" "$FE_ROOT/install-agent.sh"
        chmod 644 "$FE_ROOT/install-agent.sh"
    fi

    local SERVER_NAME="_"
    local LISTEN_DIRECTIVE="listen ${PANEL_PORT};"
    local PANEL_TLS_BLOCK=""
    if [ -n "$PANEL_DOMAIN" ]; then
        SERVER_NAME="$PANEL_DOMAIN"
        # Use interface IP to match agent-generated site configs (prevents nginx routing conflicts).
        # Always pair the IPv4 listen with a plain `[::]:80` IPv6 listen so the panel is
        # reachable via IPv6 too. Without it, agent-managed site vhosts (which bind
        # `[::]:443 ssl`) become the de-facto default for IPv6 traffic and serve their own
        # WP/canonical-redirect responses for the panel domain.
        local BIND_IP
        BIND_IP=$(interface_ip)
        if [ -n "$BIND_IP" ]; then
            LISTEN_DIRECTIVE="listen ${BIND_IP}:80;
    listen [::]:80;"
        else
            LISTEN_DIRECTIVE="listen 80;
    listen [::]:80;"
        fi
    else
        # No domain → certbot can't issue. Terminate TLS anyway with a
        # self-signed certificate so first-boot credentials are encrypted.
        local IP_FOR_CERT
        IP_FOR_CERT=$(detect_server_ip)
        if generate_self_signed_panel_cert "$IP_FOR_CERT"; then
            PANEL_SELF_SIGNED=1
            # Same binding as before, now with TLS. Deliberately NOT adding an
            # [::] listen here: this is the default install path, and a box with
            # IPv6 disabled would fail to bind and come up with no panel at all.
            LISTEN_DIRECTIVE="listen ${PANEL_PORT} ssl;"
            PANEL_TLS_BLOCK="
    ssl_certificate ${CONFIG_DIR}/ssl/panel.crt;
    ssl_certificate_key ${CONFIG_DIR}/ssl/panel.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:PanelSSL:1m;
    ssl_session_timeout 10m;
"
        else
            warn "Could not generate a self-signed certificate — the panel will serve plain HTTP on ${PANEL_PORT}"
            info "The admin password you create will NOT be encrypted in transit; prefer PANEL_DOMAIN=..."
        fi
    fi

    # Drop-in dir for path-mounted tool reverse-proxies (webmail in v2.8.22+, etc.)
    # Agent writes fragment files here on tool install/remove; setup.sh + update.sh
    # only ensure the include directive is present in the panel vhost.
    mkdir -p /etc/nginx/conf.d/dockpanel-panel.locations

    cat > "$NGINX_CONF" << NGINXEOF
server {
    ${LISTEN_DIRECTIVE}
    server_name ${SERVER_NAME};
${PANEL_TLS_BLOCK}
    client_max_body_size 100M;

    # API
    location /api/ {
        proxy_pass http://127.0.0.1:3080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
    }

    # Agent proxy (for frontend /agent/* calls)
    location /agent/ {
        proxy_pass http://unix:/var/run/dockpanel/agent.sock:/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    # Agent WebSocket terminal
    location /agent/terminal/ws {
        proxy_pass http://unix:/var/run/dockpanel/agent.sock:/terminal/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Agent WebSocket log stream
    location /agent/logs/stream {
        proxy_pass http://unix:/var/run/dockpanel/agent.sock:/logs/stream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # MCP server (read-only v1; opt-in, see panel/mcp) — exact match, not a
    # prefix: Streamable HTTP is one fixed endpoint, not a family of routes
    # like /api/. Not started by default (create_services() installs the unit
    # but never enables it), so this 502s until an operator opts in — expected
    # for a surface nobody has turned on yet.
    location = /mcp {
        proxy_pass http://127.0.0.1:3081;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        access_log off;
    }

    # Frontend static files
    root ${FE_ROOT};
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # The document must revalidate, or an update does not reach the operator.
    # Without a cache directive here the browser falls back to HEURISTIC
    # freshness — roughly a tenth of the age of the file — so on a panel that
    # has been running for a month, index.html is treated as fresh for about
    # three days. Its script tag names a hashed bundle under /assets/, which is
    # served immutable, and the previous bundle is still on disk because the
    # update untars over the directory rather than replacing it. So nothing
    # breaks and nothing 404s: the operator simply keeps running the OLD
    # frontend against the NEW backend, after an update that reported success.
    # A stale panel that looks healthy is harder to notice than a broken one.
    #
    # Every add_header below is a REPEAT, not an addition. A location block's
    # add_headers replace the server block's set outright rather than merging
    # with it, and this is the response that carries the CSP.
    location = /index.html {
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none';" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }

    # Hashed bundle filenames, so a year is safe. ONE Cache-Control: the expires
    # directive emits its own (max-age=31536000) on top of any add_header, and
    # the pair went out as two separate header lines saying different things.
    # Deliberately NOT "always" on the cache header — an error response must not
    # be cached, or a 404 during an update would be remembered for a year.
    #
    # The security headers below are a REPEAT, not an addition: a location
    # block's add_headers replace the server block's set outright rather than
    # merging with it, so without them every script and stylesheet this panel
    # serves goes out with NO nosniff — the one header that matters most for a
    # script response, on the only responses that are scripts.
    location /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable";
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none';" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }

    # Drop-in location blocks for path-mounted tools (webmail, etc.)
    include /etc/nginx/conf.d/dockpanel-panel.locations/*.conf;

    # Hide nginx version
    server_tokens off;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none';" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
NGINXEOF

    # Test and restart (full restart needed to release port bindings from removed default site)
    if nginx -t > /dev/null 2>&1; then
        svc_restart nginx
        log "Nginx configured — panel on port $PANEL_PORT"
    else
        error "Nginx config test failed"
        nginx -t 2>&1
        exit 1
    fi
}

# ── Health Check ─────────────────────────────────────────────────────────
wait_for_health() {
    header "Health Check"

    if run "Waiting for the API to answer on port 3080" bash -c \
        'for i in $(seq 1 15); do curl -sf http://127.0.0.1:3080/api/health && exit 0; sleep 2; done; exit 1'; then
        log "API healthy"
    else
        warn "API not responding on port 3080 yet — check: journalctl -u dockpanel-api -n 20"
    fi
}

# ── Recommended Services ─────────────────────────────────────────────────

# install_php_set <prefix> — install <prefix>-fpm + <prefix>-cli, then every
# extension metapackage this apt source actually has a candidate for.
# A fixed list would fail the whole transaction over one obsolete name:
# PHP 8.5 (Ubuntu 26.04) absorbed OPcache, so `php-opcache` no longer has an
# installation candidate there — that single dead package is what broke the
# old all-or-nothing install. Skipped names are reported, not fatal.
install_php_set() {
    local prefix="$1"
    local exts="" skipped="" e
    if ! run "Installing ${prefix}-fpm + ${prefix}-cli" apt-get install -y "${prefix}-fpm" "${prefix}-cli"; then
        return 1
    fi
    for e in mysql pgsql curl gd mbstring xml zip bcmath intl readline opcache; do
        if apt_has_candidate "${prefix}-${e}"; then
            exts="$exts ${prefix}-${e}"
        else
            skipped="$skipped $e"
        fi
    done
    if [ -n "$exts" ]; then
        # shellcheck disable=SC2086
        if ! run "Installing PHP extensions ($(echo $exts | wc -w) packages)" apt-get install -y $exts; then
            warn "Some PHP extensions failed to install — see $INSTALL_LOG"
        fi
    fi
    if [ -n "$skipped" ]; then
        info "Skipped:${skipped} (built into this PHP version or not packaged)"
    fi
    return 0
}

# cleanup_php_repo — remove a 3rd-party PHP source that turned out not to
# serve this release. Leaving it behind breaks EVERY later `apt-get update`
# on the user's box with a 404 (this exact wreckage was found on a fresh
# Ubuntu 26.04 install after the old installer's failed PPA attempt).
cleanup_php_repo() {
    rm -f /etc/apt/sources.list.d/sury-php.list \
          /etc/apt/sources.list.d/ondrej-ubuntu-php-*.sources \
          /etc/apt/sources.list.d/ondrej-ubuntu-php-*.list 2>/dev/null || true
    run "Refreshing package index" apt-get update -y || true
}

# The name of the PHP-FPM runscript on this Alpine box, e.g. php-fpm84.
#
# Alpine versions the runscript (php-fpm84) while Debian versions the unit
# (php8.4-fpm), and the agent speaks the Debian spelling. Prefer the runscript
# matching the PHP that is actually installed, then any php-fpmNN that exists
# (the unversioned `php-fpm` meta can land a runscript whose name does not match
# the `php` binary on PATH), then the bare name.
alpine_php_fpm_service() {
    local v svc
    v=$(php -r 'echo PHP_MAJOR_VERSION.PHP_MINOR_VERSION;' 2>/dev/null || true)
    if [ -n "$v" ] && [ -x "/etc/init.d/php-fpm${v}" ]; then
        printf 'php-fpm%s' "$v"
        return
    fi
    for svc in /etc/init.d/php-fpm*; do
        if [ -x "$svc" ]; then
            basename "$svc"
            return
        fi
    done
    printf 'php-fpm'
}

install_php() {
    if command -v php &> /dev/null; then
        log "PHP already installed: $(php -v | head -1 | awk '{print $2}')"
        # Present is not the same as RUNNING. On Alpine a pre-existing php84-fpm
        # arrives disabled, so a panel install over it would report PHP ready
        # and hand every PHP site a 502. Cheap and idempotent to assert.
        if [ "$INIT" != "systemd" ]; then
            svc_enable_now "$(alpine_php_fpm_service)"
        fi
        svc_ok "PHP $(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null) (FPM)"
        return
    fi

    if [ "$PKG_MGR" = "apt" ]; then
        # Re-source /etc/os-release — detect_os' copy is local to that function.
        local OS_ID="" OS_CODENAME=""
        if [ -f /etc/os-release ]; then
            OS_ID=$(. /etc/os-release && echo "${ID:-}")
            OS_CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
        fi

        # Step 1: the distro's own PHP. Covers Ubuntu 24.04 (8.3), Ubuntu
        # 26.04 (8.5), Debian 12 (8.2), Debian 13 (8.4) — modern distros ship
        # a usable PHP and need no 3rd-party repo at all.
        local PHP_VER=""
        if apt_has_candidate php-fpm && install_php_set php; then
            PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)
        fi

        # Step 2: releases without a usable distro PHP fall back to a
        # 3rd-party repo (Debian → deb.sury.org, Ubuntu → ppa:ondrej/php) —
        # but ONLY after confirming that repo actually publishes for this
        # release (brand-new releases lag), and with cleanup on failure so a
        # dead source can never poison the box's apt state.
        if [ -z "$PHP_VER" ]; then
            local FALLBACK_VER="8.3" repo_added=0
            if [ "$OS_ID" = "debian" ] && [ -n "$OS_CODENAME" ]; then
                if curl -sfI --max-time 15 "https://packages.sury.org/php/dists/${OS_CODENAME}/Release" > /dev/null 2>&1; then
                    if run "Adding deb.sury.org PHP repo (${OS_CODENAME})" bash -c "
                        apt-get install -y apt-transport-https lsb-release ca-certificates curl gnupg &&
                        curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg &&
                        echo 'deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ ${OS_CODENAME} main' > /etc/apt/sources.list.d/sury-php.list &&
                        apt-get update -y"; then
                        repo_added=1
                    fi
                else
                    warn "deb.sury.org publishes no PHP packages for Debian ${OS_CODENAME} yet"
                fi
            elif [ "$OS_ID" = "ubuntu" ] && [ -n "$OS_CODENAME" ]; then
                if curl -sfI --max-time 15 "https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/${OS_CODENAME}/Release" > /dev/null 2>&1; then
                    if run "Adding ppa:ondrej/php (${OS_CODENAME})" bash -c "
                        apt-get install -y software-properties-common &&
                        add-apt-repository -y ppa:ondrej/php &&
                        apt-get update -y"; then
                        repo_added=1
                    fi
                else
                    warn "ppa:ondrej/php publishes no packages for Ubuntu ${OS_CODENAME} yet"
                fi
            fi

            if [ "$repo_added" = "1" ] && apt_has_candidate "php${FALLBACK_VER}-fpm"; then
                if install_php_set "php${FALLBACK_VER}"; then
                    PHP_VER="$FALLBACK_VER"
                fi
            fi
            if [ -z "$PHP_VER" ] && [ "$repo_added" = "1" ]; then
                cleanup_php_repo
            fi
        fi

        if [ -n "$PHP_VER" ]; then
            svc_enable_now "php${PHP_VER}-fpm"
            log "PHP ${PHP_VER} installed with FPM"
            svc_ok "PHP ${PHP_VER} (FPM)"
        else
            warn "PHP could not be installed — WordPress/PHP sites need it; retry later from Settings → Services"
            svc_fail "PHP-FPM"
        fi
    elif [ "$PKG_MGR" = "apk" ]; then
        # Alpine's PHP lives in community as one package per version plus a
        # `php-<ext>` meta per extension. The extension list is filtered against
        # the index for exactly the reason apt_has_candidate exists on the
        # Debian side: `apk add` fails the whole transaction on a single name it
        # cannot resolve, so one retired extension would cost the entire PHP
        # install rather than just itself.
        local php_exts="" e
        for e in mysqli pgsql curl gd mbstring xml zip bcmath intl opcache session; do
            if apk_has_pkg "php-${e}"; then
                php_exts="$php_exts php-${e}"
            else
                warn "php-${e} is not in this Alpine branch's index — skipping it"
            fi
        done
        # shellcheck disable=SC2086
        if run "Installing PHP (apk: php-fpm, php-cli + extensions)" \
                pkg_install php-fpm php-cli $php_exts; then
            # The runscript is versioned (php-fpm84), and the agent asks for the
            # Debian spelling (php8.4-fpm). Both spellings are resolved here so
            # this install starts the service the box actually has, and the
            # systemctl shim resolves the agent's requests to the same one.
            local php_fpm_svc
            php_fpm_svc="$(alpine_php_fpm_service)"
            svc_enable_now "$php_fpm_svc"
            log "PHP $(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null) installed with FPM ($php_fpm_svc)"
            svc_ok "PHP $(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null) (FPM)"
        else
            warn "PHP could not be installed — retry later from Settings → Services"
            svc_fail "PHP-FPM"
        fi
    else
        # RHEL/Rocky/Fedora.
        #
        # SELECT THE MODULE STREAM FIRST. `dnf install php-fpm` with no stream
        # enabled resolves to the NON-MODULAR base package — PHP 8.0.30 on
        # Rocky 9, older than every stream the box offers (8.1/8.2/8.3) and
        # end-of-life since November 2023 — and the install summary then
        # cheerfully prints "PHP 8.0 (FPM)". Measured on a real box at s266,
        # where this installer did exactly that.
        #
        # It also made the panel's own PHP installer unreachable: it checks
        # whether PHP is already present, finds 8.0, and reports "already
        # installed", so nothing ever offers the operator a supported version.
        local php_stream
        php_stream=$(dnf -q module list php 2>/dev/null \
                     | awk '$1=="php" && $2 ~ /^[0-9]/ {print $2}' | sort -Vr | head -1)
        if [ -n "$php_stream" ]; then
            if dnf -y module enable "php:${php_stream}" > /dev/null 2>&1; then
                info "Selected PHP ${php_stream} (module stream)"
            else
                warn "Could not enable the php:${php_stream} module stream — falling back to the distro default, which may be end-of-life"
            fi
        fi

        # The extension names are passed as-is: several of them (php-curl,
        # php-zip, php-sqlite3) are VIRTUAL provides satisfied by php-common
        # rather than packages of their own, and dnf resolves those, so this
        # list is not the all-or-nothing hazard the apt side has to guard
        # against. Verified against a real dnf at s266.
        if run "Installing PHP (distro packages)" pkg_install php-fpm php-cli php-common php-mysqlnd php-pgsql php-xml php-mbstring php-curl php-zip php-gd; then
            svc_enable_now php-fpm
            log "PHP installed with FPM"
            svc_ok "PHP $(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null) (FPM)"
        else
            warn "PHP could not be installed — retry later from Settings → Services"
            svc_fail "PHP-FPM"
        fi
    fi
}

# Keep the certificate renewed, in whichever way this box schedules things.
#
# On systemd that is certbot.timer. Alpine has no systemd and Alpine's certbot
# package ships no timer, so without this an Alpine panel would silently lose
# its certificate ~90 days after install — the exact failure mode auto-renewal
# exists to prevent. OpenRC boxes get the /etc/periodic/daily hook instead,
# which crond (an OpenRC service, started at boot) picks up.
schedule_certbot_renewal() {
    if [ "$INIT" = "systemd" ]; then
        svc_enable_now certbot.timer
        log "Certbot installed with auto-renewal (certbot.timer)"
        return
    fi

    if [ -d /etc/periodic/daily ]; then
        cat > /etc/periodic/daily/dockpanel-certbot-renew << 'CRONEOF'
#!/bin/sh
# Managed by DockPanel — rewritten by scripts/setup.sh and update.sh.
# On a systemd box certbot.timer does this; this hook is the OpenRC/crond
# equivalent. `renew` is a no-op until a certificate is within 30 days of
# expiry, so running it daily costs one cheap check.
certbot renew --quiet >> /var/log/dockpanel-certbot-renew.log 2>&1
CRONEOF
        chmod +x /etc/periodic/daily/dockpanel-certbot-renew
        log "Certbot installed with auto-renewal (/etc/periodic/daily)"
    else
        warn "Certbot installed, but no renewal schedule was set up on this box"
        warn "Add a daily 'certbot renew' to your scheduler — certificates expire in 90 days"
    fi
}

install_recommended_services() {
    header "Recommended Services"

    # PHP-FPM (needed for WordPress, PHP sites)
    install_php

    # Certbot (needed for SSL certificates)
    if ! command -v certbot &> /dev/null; then
        # Alpine packages the nginx plugin separately (certbot-nginx) and has no
        # python3-certbot-nginx, which is Debian's name for the same thing.
        local certbot_pkgs="certbot python3-certbot-nginx"
        if [ "$PKG_MGR" = "apk" ]; then
            certbot_pkgs="certbot certbot-nginx"
        fi
        # shellcheck disable=SC2086
        if run "Installing Certbot" pkg_install $certbot_pkgs; then
            schedule_certbot_renewal
            svc_ok "Certbot"
        else
            warn "Certbot failed to install — SSL provisioning will not work until it is"
            svc_fail "Certbot"
        fi
    else
        log "Certbot already installed"
        svc_ok "Certbot"
    fi

    # Firewall. Install one only if the box has none — never a second one.
    #
    # s265: this used to install UFW unconditionally. On the RHEL family that
    # put UFW's iptables rules alongside the firewalld nftables rules the
    # distro already had running, and then opened 80/443 in UFW *only*. The
    # packets kept dying at firewalld, so Let's Encrypt could not reach
    # /.well-known/acme-challenge, the panel got no certificate, and it was
    # unreachable from any browser — while the installer printed
    # "installed successfully" and an https:// URL. Two firewalls is not a
    # hardening measure, it is an outage nobody can see.
    #
    # DOCKPANEL_SKIP_FIREWALL=1 leaves the firewall entirely alone. A default-deny
    # policy is only safe when the installer can see every port the operator
    # reaches the box on — a panel managed on a non-standard SSH port, or behind
    # a provider firewall, is exactly where it cannot, and enabling one anyway
    # locks the operator out of the machine that was just configured for them.
    if [ "${DOCKPANEL_SKIP_FIREWALL:-0}" = "1" ]; then
        log "Firewall: left alone (DOCKPANEL_SKIP_FIREWALL=1)"
    else
        case "$FW_MGR" in
            firewalld)
                log "Firewall: firewalld is already active — using it (not installing UFW)"
                svc_ok "firewalld"
                ;;
            ufw)
                log "UFW already installed"
                svc_ok "UFW"
                ;;
            none)
                if run "Installing UFW firewall" pkg_install ufw; then
                    ufw default deny incoming > /dev/null 2>&1
                    ufw default allow outgoing > /dev/null 2>&1
                    ufw allow 22/tcp > /dev/null 2>&1
                    ufw --force enable > /dev/null 2>&1
                    # ufw's own unit brings the rules back at boot on Debian; on
                    # an OpenRC box nothing else would, so the runscript has to be
                    # enabled or the firewall is gone after the next reboot.
                    svc_enable_now ufw
                    FW_MGR="ufw"
                    log "UFW installed and enabled"
                    svc_ok "UFW"
                else
                    warn "UFW failed to install — no firewall is active"
                    svc_fail "UFW"
                fi
                ;;
        esac

        # Ensure panel ports are open in whichever firewall is actually enforcing.
        if fw_allow 80/tcp && fw_allow 443/tcp; then
            local opened="80, 443"
            if [ -n "$PANEL_PORT" ] && [ "$PANEL_PORT" != "80" ] && [ "$PANEL_PORT" != "443" ]; then
                fw_allow "${PANEL_PORT}/tcp" && opened="$opened, $PANEL_PORT"
            fi
            fw_reload
            log "Firewall ($FW_MGR): ports $opened allowed"
        elif [ "$FW_MGR" = "none" ]; then
            log "Firewall: none active — nothing to open"
        else
            warn "Firewall ($FW_MGR): could not open 80/443 — the panel may be unreachable"
        fi
    fi

    # Fail2Ban (intrusion prevention)
    if ! command -v fail2ban-client &> /dev/null; then
        if run "Installing Fail2Ban" pkg_install fail2ban; then
            cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true
F2BEOF
            svc_enable_now fail2ban
            log "Fail2Ban installed with SSH + Nginx jails"
            svc_ok "Fail2Ban"
        else
            warn "Fail2Ban failed to install — retry later from Settings → Services"
            svc_fail "Fail2Ban"
        fi
    else
        # Already installed is not already RUNNING. Debian's package starts
        # and enables fail2ban on install, so a box that already had it was
        # assumed to have it active; Alpine's arrives stopped and unregistered,
        # which the panel's own diagnostics then reports as "fail2ban is not
        # active" over an install that claimed all recommended services ready.
        # Unlike the ufw case below this cannot lock anyone out — fail2ban bans
        # on repeated auth failures rather than denying by default.
        svc_enable_now fail2ban
        log "Fail2Ban already installed"
        svc_ok "Fail2Ban"
    fi

    # Honest section verdict — never claim "all ready" over a failure.
    if [ ${#SVC_FAIL[@]} -eq 0 ]; then
        log "All recommended services ready"
    else
        warn "$(join_comma "${SVC_FAIL[@]}") did not install — the panel still works; retry from Settings → Services"
    fi
}

# Bind the panel's TLS listener the same way its neighbours are bound.
#
# certbot --nginx writes a WILDCARD `listen 443 ssl;` onto the vhost it
# manages, but agent-generated site vhosts bind `<ip>:443 ssl`
# (agent/src/templates/nginx/https.conf). nginx treats those as two different
# listen sockets and the explicit-IP one wins every connection to that
# address, so the panel's server_name is never consulted: the FIRST site to
# get a certificate becomes the de-facto server for the panel's own domain and
# the panel goes dark from outside. configure_nginx already avoids exactly
# this on :80 by pinning it to the interface IP — certbot then reintroduces it
# on :443, which is why the guard there was not enough.
normalize_panel_listen() {
    local conf="$NGINX_CONF"
    [ -f "$conf" ] || return 0

    local bind_ip
    bind_ip=$(interface_ip)
    # No default route: every vhost falls back to wildcard, so they already agree.
    [ -n "$bind_ip" ] || return 0

    sed -i -E "s|^([[:space:]]*)listen 443 ssl;|\1listen ${bind_ip}:443 ssl;|" "$conf"
    # Site vhosts declare a plain `[::]:443 ssl`; nginx rejects mixing
    # ipv6only=on with it on the same socket.
    sed -i -E 's|^([[:space:]]*)listen \[::\]:443 ssl ipv6only=on;|\1listen [::]:443 ssl;|' "$conf"

    if ! nginx -t > /dev/null 2>&1; then
        warn "nginx config test failed after adjusting the panel listen directives"
        return 0
    fi

    # A RELOAD cannot move an already-bound listener from 0.0.0.0:443 to
    # <ip>:443 — nginx inherits the old socket and the change silently
    # no-ops, leaving a config on disk that disagrees with what is running.
    # Only a restart rebinds.
    svc_restart nginx > /dev/null 2>&1 || true

    # Trust the socket, not the restart's exit code.
    if command -v ss > /dev/null 2>&1 && ! ss -ltn "( sport = :443 )" 2>/dev/null | grep -c "${bind_ip}:443" >/dev/null; then
        warn "panel is not listening on ${bind_ip}:443 — a site vhost may shadow it"
    fi
}

provision_panel_ssl() {
    if [ -z "$PANEL_DOMAIN" ]; then
        if [ "$PANEL_SELF_SIGNED" = "1" ]; then
            log "No domain set — serving HTTPS on IP:${PANEL_PORT} with a self-signed certificate"
            info "Let's Encrypt needs a domain; re-run with PANEL_DOMAIN=... for a trusted certificate"
        else
            log "No domain set — panel on IP:${PANEL_PORT} (plain HTTP)"
        fi
        return
    fi

    header "Panel SSL Certificate"

    if ! command -v certbot &> /dev/null; then
        log "Certbot not found — skipping SSL"
        return
    fi

    if run "Provisioning Let's Encrypt certificate for ${PANEL_DOMAIN}" \
        certbot --nginx -d "$PANEL_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect; then
        log "SSL certificate provisioned for $PANEL_DOMAIN"
        PANEL_SSL_OK=1
        normalize_panel_listen
    else
        # Order these by what actually causes it. s265: a firewall the
        # installer did not configure blocked :80, so the ACME challenge could
        # never be fetched — and the old hint blamed Cloudflare, which was not
        # even in the path. Reachability first, proxies last.
        warn "SSL provisioning failed — the panel is served over plain HTTP for now"
        info "Let's Encrypt must reach http://${PANEL_DOMAIN}/.well-known/acme-challenge/ from the internet. Check, in order:"
        info "  1. ${PANEL_DOMAIN} resolves to this server's public IP"
        info "  2. ports 80 and 443 are open — in the OS firewall (${FW_MGR}) AND in any provider firewall"
        info "  3. if the domain is proxied by Cloudflare, set SSL mode to 'Full'"
        info "Then retry: certbot --nginx -d $PANEL_DOMAIN"
    fi
}

print_summary() {
    INSTALL_DONE=1

    local SERVER_IP
    SERVER_IP=$(detect_server_ip)
    SERVER_IP="${SERVER_IP:-YOUR_SERVER_IP}"

    local elapsed_total=$(( $(date +%s) - SETUP_START ))
    local mins=$((elapsed_total / 60))
    local secs=$((elapsed_total % 60))

    echo ""
    echo -e "  ${CYAN}$(progress_bar 100)${NC} ${WHITE}100%${NC} ${DIM}${mins}m ${secs}s${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║         DockPanel installed successfully!            ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    if [ -n "$INSTALLED_VERSION" ]; then
        echo -e "  ${BOLD}Version:${NC}        ${INSTALLED_VERSION}"
    fi
    if [ -n "$PANEL_DOMAIN" ] && [ "$PANEL_SSL_OK" = "1" ]; then
        echo -e "  ${BOLD}Panel URL:${NC}      https://${PANEL_DOMAIN}"
    elif [ -n "$PANEL_DOMAIN" ]; then
        # No certificate was issued. Printing https:// here sends the operator
        # to a URL that cannot answer, and it reads as if the install worked.
        echo -e "  ${BOLD}Panel URL:${NC}      http://${PANEL_DOMAIN}  ${YELLOW}(no certificate — see below)${NC}"
    elif [ "$PANEL_SELF_SIGNED" = "1" ]; then
        echo -e "  ${BOLD}Panel URL:${NC}      https://${SERVER_IP}:${PANEL_PORT}"
    else
        echo -e "  ${BOLD}Panel URL:${NC}      http://${SERVER_IP}:${PANEL_PORT}"
    fi
    echo ""
    echo -e "  ${BOLD}First step:${NC}     Open the URL and create your admin account"
    if [ "$PANEL_SELF_SIGNED" = "1" ]; then
        echo ""
        echo -e "  ${DIM}Your browser will warn once about the certificate — that is expected${NC}"
        echo -e "  ${DIM}for an IP address. It is self-signed, and it is there so the admin${NC}"
        echo -e "  ${DIM}password you are about to create is encrypted on the way to the server.${NC}"
        echo -e "  ${DIM}For a trusted certificate: point a domain here, then re-run with${NC}"
        echo -e "  ${DIM}PANEL_DOMAIN=your.domain bash /opt/dockpanel/scripts/setup.sh${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}CLI:${NC}            dockpanel status"
    echo -e "                  dockpanel diagnose"
    echo -e "                  dockpanel --help"
    echo ""
    echo -e "  ${BOLD}Service commands:${NC}"
    case "$INIT" in
        systemd)
            echo -e "    Agent status:   systemctl status dockpanel-agent"
            echo -e "    API status:     systemctl status dockpanel-api"
            echo -e "    Agent logs:     journalctl -u dockpanel-agent -f"
            echo -e "    API logs:       journalctl -u dockpanel-api -f"
            echo -e "    Restart all:    systemctl restart dockpanel-agent dockpanel-api"
            ;;
        openrc)
            echo -e "    Agent status:   rc-service dockpanel-agent status"
            echo -e "    API status:     rc-service dockpanel-api status"
            echo -e "    Agent logs:     tail -f /var/log/dockpanel-agent.log"
            echo -e "    API logs:       tail -f /var/log/dockpanel-api.log"
            echo -e "    Restart all:    rc-service dockpanel-agent restart; rc-service dockpanel-api restart"
            echo -e "    ${DIM}Both are enabled in the default runlevel, so they survive a reboot.${NC}"
            ;;
        *)
            echo -e "    No service manager on this box — start them by hand:"
            echo -e "    Agent:          /usr/local/bin/dockpanel-agent &"
            echo -e "    API:            set -a; . ${CONFIG_DIR}/api.env; set +a; /usr/local/bin/dockpanel-api &"
            ;;
    esac
    echo ""
    echo -e "  ${BOLD}Paths:${NC}"
    echo -e "    Config:         ${CONFIG_DIR}/"
    echo -e "    Agent token:    ${CONFIG_DIR}/agent.token"
    echo -e "    API env:        ${CONFIG_DIR}/api.env"
    echo -e "    Backups:        /var/backups/dockpanel/"
    echo -e "    Install log:    ${INSTALL_LOG}"
    echo ""
    echo -e "  ${BOLD}Database:${NC}"
    echo -e "    Container:      ${DB_CONTAINER} (port ${DB_PORT})"
    echo -e "    Connect:        docker exec -it ${DB_CONTAINER} psql -U dockpanel -d dockpanel"
    echo ""
    # What ACTUALLY installed — never a hardcoded wishlist.
    if [ ${#SVC_OK[@]} -gt 0 ]; then
        echo -e "  ${BOLD}Installed services:${NC}"
        echo -e "    $(join_comma "${SVC_OK[@]}")"
    fi
    if [ ${#SVC_FAIL[@]} -gt 0 ]; then
        echo ""
        echo -e "  ${YELLOW}${BOLD}⚠ Not installed:${NC}"
        echo -e "    $(join_comma "${SVC_FAIL[@]}")"
        echo -e "    ${DIM}Retry from the panel: Settings → Services · details: ${INSTALL_LOG}${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}Optional (install from panel):${NC}"
    echo -e "    Mail server:    Settings → Services or Mail page → Install"
    echo -e "    Webmail:        Apps → Deploy → Roundcube"
    echo -e "    Spam filter:    Apps → Deploy → Rspamd"
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo -e "    1. Open the panel URL and create your admin account"
    echo -e "    2. Add your first site (Sites → Create Site)"
    echo -e "    3. Provision SSL (click the lock icon on any site)"
    echo -e "    4. Run diagnostics (Diagnostics → Run Scan)"
    echo ""
    echo -e "  ${BOLD}Docs:${NC}     https://docs.dockpanel.dev"
    echo -e "  ${YELLOW}Update:${NC}   Run: bash /opt/dockpanel/scripts/update.sh"
    echo ""
}

# ── PostgreSQL Backup ────────────────────────────────────────────────────
setup_db_backup() {
    header "PostgreSQL Backup"

    local BACKUP_SCRIPT="/opt/dockpanel/scripts/db-backup.sh"
    mkdir -p /opt/dockpanel/scripts

    cat > "$BACKUP_SCRIPT" << 'BKEOF'
#!/bin/bash
# pipefail is load-bearing: the exit status of `pg_dump | gzip` is *gzip's*, and
# gzip compresses a truncated stream and exits 0. Without it a pg_dump that died
# halfway was written out as the day's backup, the retention sweep below then
# deleted a good older one to make room, and nothing anywhere said a word.
set -o pipefail
# umask is load-bearing for the same reason pipefail is: `>` creates the file
# 0666 & ~umask, so without this the day's dump — the whole panel database,
# including `servers.agent_token` in cleartext — lands 0644 on a box that also
# runs other people's PHP as www-data.
umask 077
BACKUP_DIR="/var/backups/dockpanel/db"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" /var/backups/dockpanel 2>/dev/null || true
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="$BACKUP_DIR/dockpanel_$TIMESTAMP.sql.gz"
if ! docker exec dockpanel-postgres pg_dump -U dockpanel -d dockpanel | gzip > "$OUT"; then
    echo "dockpanel db-backup: pg_dump failed, discarding $OUT" >&2
    rm -f "$OUT"
    exit 1
fi
# A zero exit is not the success condition — a whole dump is. pg_dump emits this
# marker near the end; its absence means the file is short whatever exited 0.
if ! gunzip -c "$OUT" | tail -20 | grep -c 'PostgreSQL database dump complete' >/dev/null; then
    echo "dockpanel db-backup: $OUT is incomplete, discarding" >&2
    rm -f "$OUT"
    exit 1
fi
# Keep last 7 days — only ever reached once today's backup is known good, so a
# bad run can never evict a good one.
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete
BKEOF
    chmod +x "$BACKUP_SCRIPT"

    # Install cron job (daily at 3 AM).
    #
    # Both greps are load-bearing. The first drops a previous install of THIS
    # script. The second drops the pre-v2.88.0 INLINE dump line, which never
    # contains "$BACKUP_SCRIPT" — so without it, re-running setup on an older
    # box kept the unhardened 0644 line AND added this one, giving two daily
    # dumps of the same database, one of them world-readable in mode.
    #
    # Alpine's BusyBox crontab keeps its tables in /var/spool/cron/crontabs
    # (a directory the package does not necessarily create) and its daemon is
    # an OpenRC service rather than a timer — so the directory is made and
    # crond is started, or the job is written and never runs.
    mkdir -p /var/spool/cron/crontabs 2>/dev/null || true
    svc_enable_now crond
    (crontab -l 2>/dev/null \
        | grep -v "$BACKUP_SCRIPT" \
        | grep -v 'pg_dump -U dockpanel.*/var/backups/dockpanel/db'; \
     echo "0 3 * * * $BACKUP_SCRIPT") | crontab -

    log "Database backup script installed ($BACKUP_SCRIPT)"
    log "Cron job: daily at 3:00 AM, 7-day retention"
}

# ── Main ─────────────────────────────────────────────────────────────────
main() {
    SETUP_START=$(date +%s)
    print_banner
    check_root

    # Start the install log. Prefer /var/log; if it's read-only (hardened /
    # containerized host) fall back to a root-owned, unpredictable, O_EXCL temp
    # file via mktemp — never a fixed /tmp path a local user could pre-create
    # or symlink (the installer runs as root and logs config paths).
    if : > "$INSTALL_LOG" 2>/dev/null; then
        chmod 600 "$INSTALL_LOG" 2>/dev/null || true
    else
        INSTALL_LOG=$(umask 077; mktemp /tmp/dockpanel-install.XXXXXX 2>/dev/null || echo /dev/null)
    fi
    plog "DockPanel installer started: $(date 2>/dev/null || true)"

    # No apt/debconf prompt may ever block a piped installer
    export DEBIAN_FRONTEND=noninteractive

    detect_pkg_manager
    detect_firewall
    detect_init

    # Auto-detect: if no source available, use release binaries
    if [ "$INSTALL_FROM_RELEASE" != "1" ] && [ ! -d "$AGENT_SRC/src" ]; then
        INSTALL_FROM_RELEASE=1
    fi

    # Ask for the domain UP FRONT — all input happens before the first step,
    # so the install never stops to wait for a human once it starts moving.
    if [ -z "$PANEL_DOMAIN" ]; then
        echo ""
        echo -e "${BOLD}Enter your panel domain (e.g. panel.example.com)${NC}"
        echo -e "Leave blank to use IP:${PANEL_PORT} with a self-signed certificate instead"
        echo -e "${BOLD}Tip:${NC} set PANEL_DOMAIN=... in the environment to skip this prompt"
        echo -n "> "
        if [ -t 0 ]; then
            read -r PANEL_DOMAIN
        # `[ -r /dev/tty ]` returns true on Linux even when the process has no
        # controlling tty. Probe with an actual open so we don't print a confusing
        # "No such device or address" error to stderr.
        elif { : </dev/tty; } 2>/dev/null; then
            # Piped via curl but an interactive terminal is reachable
            read -r PANEL_DOMAIN < /dev/tty || PANEL_DOMAIN=""
        else
            # Fully non-interactive (e.g. piped through SSH without tty).
            # Skip the prompt — caller should have set PANEL_DOMAIN already.
            echo "(no tty — continuing without a panel domain; set PANEL_DOMAIN to configure)"
            PANEL_DOMAIN=""
        fi
        PANEL_DOMAIN=$(echo "$PANEL_DOMAIN" | tr -d ' ')
    fi

    if [ -n "$PANEL_DOMAIN" ]; then
        log "Panel domain: $PANEL_DOMAIN"
        PANEL_PORT="80"  # Will be upgraded to 443 by certbot
    fi

    # Every conditional step is now known — size the progress bar so it hits
    # 100% exactly at the end (no phantom steps, no 93% → 100% jump).
    TOTAL_STEPS=14
    if [ "$INSTALL_FROM_RELEASE" != "1" ]; then
        TOTAL_STEPS=$((TOTAL_STEPS + 1))   # build binaries + frontend = 2 steps vs 1 download step
    fi
    if [ -n "$PANEL_DOMAIN" ]; then
        TOTAL_STEPS=$((TOTAL_STEPS + 1))   # panel SSL certificate step
    fi

    detect_os
    preflight_checks
    check_source
    install_dependencies
    ensure_www_data_user
    install_docker
    install_nginx
    install_node
    create_directories
    generate_secrets
    setup_database

    if [ "$INSTALL_FROM_RELEASE" = "1" ]; then
        download_binaries
    else
        build_binaries
        build_frontend
    fi

    # Remove default server block that conflicts
    if [ -f /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    # RHEL: comment out the default server block in nginx.conf, which binds :80
    # and would fight the panel vhost.
    #
    # This used to be a sed range — `/server {/,/^[[:space:]]*}/` — and that range
    # ends at the FIRST line that is just a closing brace, which inside a server
    # block is the end of its first nested `location`, not the end of the server.
    # So it commented the opening third of the block and left the remainder at
    # http level, and nginx -t died with `"location" directive is not allowed
    # here in /etc/nginx/nginx.conf:52`. Every RHEL-family install failed there.
    # Counting braces is the only way to find the block's real end.
    if [ "$PKG_MGR" != "apt" ] && [ -f /etc/nginx/nginx.conf ]; then
        awk '
          # Only an UNcommented top-level server block; an already-commented one
          # starts with # and must not match, so re-running stays a no-op.
          !c && /^[[:space:]]*server[[:space:]]*\{/ { c = 1; d = 0 }
          c {
            d += gsub(/\{/, "{") - gsub(/\}/, "}")
            print "#" $0
            if (d <= 0) c = 0
            next
          }
          { print }
        ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.dockpanel-new 2>/dev/null &&
          mv /etc/nginx/nginx.conf.dockpanel-new /etc/nginx/nginx.conf
        rm -f /etc/nginx/nginx.conf.dockpanel-new
    fi

    # These steps should continue even if one fails
    set +e
    # Before nginx is asked to proxy anything: on Enforcing SELinux it may not
    # open the socket to the API at all, and the denial is silent.
    configure_selinux
    configure_nginx
    create_services

    # Wait for services to start
    sleep 3

    # Start services (may already be started by create_services)
    svc_start dockpanel-agent > /dev/null 2>&1 || true
    svc_start dockpanel-api > /dev/null 2>&1 || true
    sleep 2

    install_recommended_services
    provision_panel_ssl
    wait_for_health
    setup_db_backup
    set -e

    print_summary
}

main "$@"
