#!/usr/bin/env bash
# DockPanel Remote Agent Installer
# Usage: curl -sSL https://panel.example.com/install-agent.sh | sudo bash -s -- \
#   --panel-url https://panel.example.com \
#   --token <agent_token> \
#   --server-id <server_uuid>
#
# This installs ONLY the DockPanel agent binary (no database, no API, no frontend).
# The agent connects back to the panel via HTTPS on port 9443.

set -euo pipefail

PANEL_URL=""
TOKEN=""
SERVER_ID=""
AGENT_PORT="9443"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --panel-url) PANEL_URL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --server-id) SERVER_ID="$2"; shift 2 ;;
        --port) AGENT_PORT="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TOKEN" ]]; then
    echo "Error: --token is required"
    echo "Usage: $0 --panel-url <url> --token <token> --server-id <uuid>"
    exit 1
fi

# An agent with no central URL never phones home, so the panel never records a
# `last_seen_at` for it — and the fleet rolling update only considers servers
# seen in the last 5 minutes. The box would install fine and then be invisible
# to every fleet operation, with nothing anywhere saying why. Fail loudly here
# instead. (The panel used to hand out a copy-paste command with an empty
# --panel-url whenever it was installed without a domain; that is fixed too.)
if [[ -z "$PANEL_URL" || -z "$SERVER_ID" ]]; then
    echo "Error: --panel-url and --server-id are required"
    echo "  Without them the agent cannot check in, and a server that never"
    echo "  checks in can never be selected by a fleet update."
    echo "Usage: $0 --panel-url <url> --token <token> --server-id <uuid>"
    exit 1
fi
if [[ "$PANEL_URL" == --* || "$TOKEN" == --* || "$SERVER_ID" == --* ]]; then
    echo "Error: an option value looks like another flag (--panel-url '$PANEL_URL',"
    echo "  --server-id '$SERVER_ID'). One of the values is probably missing."
    exit 1
fi

echo "======================================"
echo "  DockPanel Agent Installer (Remote)"
echo "======================================"
echo ""

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_LABEL="amd64" ;;
    aarch64) ARCH_LABEL="arm64" ;;
    arm64)   ARCH_LABEL="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
echo "[1/7] Architecture: $ARCH_LABEL"

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MGR="apt"
        # Both of these exist on the panel box via setup.sh, and a fleet member
        # runs exactly the same agent-driven apt operations, so it needs them
        # too — this function had neither.
        #
        # Lock timeout: without it, any agent install/update racing
        # unattended-upgrades dies on "Could not get lock /var/lib/dpkg/lock-frontend".
        mkdir -p /etc/apt/apt.conf.d
        cat > /etc/apt/apt.conf.d/99-dockpanel-lock-wait.conf << 'APT_EOF'
DPkg::Lock::Timeout "300";
APT_EOF
        # needrestart: the agent links libc, so a plain libc6 upgrade puts
        # dockpanel-agent.service on needrestart's restart list — killing the
        # process that is streaming that very update's progress back to the
        # panel, which then reports a clean update as failed. Exclude only the
        # agent; every other service still restarts.
        if [ -d /etc/needrestart ]; then
            mkdir -p /etc/needrestart/conf.d
            cat > /etc/needrestart/conf.d/99-dockpanel.conf << 'NR_EOF'
# Managed by DockPanel — do not edit; rewritten by setup.sh/update.sh.
$nrconf{override_rc}{qr(^dockpanel-agent)} = 0;
1;
NR_EOF
        fi
    elif command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
    elif command -v apk &> /dev/null; then
        # Alpine. bash/shadow ride along for the same reason setup.sh installs
        # them: BusyBox ash cannot run the update path, and BusyBox has adduser
        # but not the useradd/usermod the agent shells out to.
        PKG_MGR="apk"
    else
        echo "Error: No supported package manager found (apt/dnf/yum/apk)"
        exit 1
    fi
}

pkg_install() {
    case "$PKG_MGR" in
        apt)
            apt-get update -qq > /dev/null 2>&1
            apt-get install -y -qq "$@" > /dev/null 2>&1
            ;;
        dnf) dnf install -y -q "$@" > /dev/null 2>&1 ;;
        yum) yum install -y -q "$@" > /dev/null 2>&1 ;;
        apk) apk add "$@" > /dev/null 2>&1 ;;
    esac
}

# Which manager runs services on this box: systemd, OpenRC, or neither.
# The agent is installed as a service either way, and the systemctl shim below
# is what lets the agent's own systemctl calls work on an OpenRC box.
INIT_MGR="systemd"
if ! command -v systemctl > /dev/null 2>&1; then
    if command -v rc-service > /dev/null 2>&1 && command -v rc-update > /dev/null 2>&1; then
        INIT_MGR="openrc"
    else
        INIT_MGR="none"
    fi
fi

# Install dependencies
echo "[2/7] Installing dependencies..."
detect_pkg_manager

# Install Docker.
#
# `get.docker.com` points the RHEL clones at
# download.docker.com/linux/<id>/… — and `linux/rocky` carries no `docker-ce`
# at all, while there is no `almalinux` branch to point at. So on those
# families the script adds a repo, refreshes the cache, and ends with
# `Error: Unable to find a match: docker-ce docker-ce-cli`. s264 found this and
# fixed it in setup.sh (v2.37.0) with an el-clone repo aimed at `linux/centos`;
# the fix never reached THIS installer, so adding a remote RHEL server has been
# impossible the whole time — measured on a stock Rocky 9, s271.
#
# The panel's own installer is the source of the shape below; keep them the same.
if ! command -v docker &> /dev/null; then
    DOCKER_OS_ID=""
    [ -f /etc/os-release ] && DOCKER_OS_ID=$(. /etc/os-release && echo "${ID:-}")
    case "$DOCKER_OS_ID" in
        rocky|almalinux|centos|rhel|ol)
            cat > /etc/yum.repos.d/docker-ce.repo << 'REPOEOF'
[docker-ce-stable]
name=Docker CE Stable - $basearch
baseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://download.docker.com/linux/centos/gpg
REPOEOF
            # --allowerasing because RHEL-family cloud images commonly preinstall
            # podman/runc, which containerd.io obsoletes, and dnf aborts the whole
            # transaction on a conflict rather than substituting.
            dnf install -y -q --allowerasing docker-ce docker-ce-cli containerd.io \
                docker-buildx-plugin docker-compose-plugin
            ;;
        *)
            if [ "$PKG_MGR" = "apk" ]; then
                # get.docker.com has no Alpine support and there is no
                # docker-ce repo for it: the packages come from community.
                pkg_install docker docker-cli-compose
            else
                curl -fsSL https://get.docker.com | sh > /dev/null 2>&1
            fi
            ;;
    esac
fi
if [ "$INIT_MGR" = "systemd" ]; then
    systemctl enable --now docker > /dev/null 2>&1 || true
else
    rc-update add docker default > /dev/null 2>&1 || true
    rc-service docker start > /dev/null 2>&1 || true
fi

# Say so, rather than dying at "[2/7] Installing dependencies..." with every
# stream sent to /dev/null. That is exactly how the RHEL failure above stayed
# invisible: `set -e` aborted the script mid-step and printed nothing at all.
if ! command -v docker &> /dev/null; then
    echo "Error: Docker could not be installed on this server (${DOCKER_OS_ID:-unknown})."
    echo "  The agent manages containers, so the install cannot continue without it."
    echo "  Install Docker by hand and re-run this script."
    exit 1
fi

# Install curl and openssl if missing.
#
# `sshpass` rides along because a managed server is a backup SOURCE as often as
# the panel host is, and password-authenticated SFTP destinations shell out to
# it. `setup.sh` has installed it on the panel host since v2.48.6; a server added
# through this script never got it, so the same destination worked from one box
# and failed from another with no difference the operator could see. Issue #93.
pkg_install curl openssl sshpass

# Alpine ships BusyBox ash only, and this script is bash (arrays, [[ ]],
# case-in-string). Nothing below works without it.
if [ "$PKG_MGR" = "apk" ] && ! command -v bash &> /dev/null; then
    pkg_install bash
fi

# Create directories
echo "[3/7] Creating directories..."
mkdir -p /etc/dockpanel/ssl
mkdir -p /var/run/dockpanel
mkdir -p /var/www
mkdir -p /var/backups/dockpanel
mkdir -p /var/lib/dockpanel/git

# Ensure socket directory persists across reboots
# mkdir -p first: /etc/tmpfiles.d is a systemd path and does not exist on an
# OpenRC box, where writing it would fail the whole script under `set -e` for a
# file nothing reads. The runscript written below recreates the directory.
mkdir -p /etc/tmpfiles.d
echo "d /run/dockpanel 0755 root root -" > /etc/tmpfiles.d/dockpanel.conf

# Save agent token and server ID
echo "[4/7] Saving configuration..."
echo "$TOKEN" > /etc/dockpanel/agent.token
chmod 600 /etc/dockpanel/agent.token

# Persist agent configuration
# AGENT_TOKEN + AGENT_LISTEN_TCP = direct multi-server TCP access
# DOCKPANEL_* vars = phone-home mode (agent checks in with central panel)
cat > /etc/dockpanel/agent.env << ENVEOF
AGENT_TOKEN=$TOKEN
AGENT_LISTEN_TCP=0.0.0.0:$AGENT_PORT
DOCKPANEL_SERVER_TOKEN=$TOKEN
DOCKPANEL_SERVER_ID=$SERVER_ID
DOCKPANEL_CENTRAL_URL=$PANEL_URL
ENVEOF
chmod 600 /etc/dockpanel/agent.env

# Download agent binary (naming matches GitHub release assets)
#
# Until s336 this was the ONE path that put a DockPanel binary on a machine
# without checking it: no checksum, no signature, and the bytes went straight
# onto /usr/local/bin/dockpanel-agent. Its three siblings all verify sha256
# against the release's checksums.txt and all quarantine first — setup.sh's own
# comment states the contract, "so the live executable path never holds
# unverified bytes". This is the installer the Add-Server dialog tells an
# operator to pipe into `sudo bash`, so it was the least verified path and the
# most exposed one.
#
# Writing to the live path also meant that on a box where the agent is already
# running the kernel refuses the open with ETXTBSY, curl reports a write failure,
# and the branch below blamed the network. Quarantine + rename fixes that too:
# rename over a running executable is allowed, writing to it is not.
ASSET="dockpanel-agent-linux-${ARCH_LABEL}"
BASE_URL="https://github.com/ovexro/dockpanel/releases/latest/download"
DOWNLOAD_URL="$BASE_URL/$ASSET"
AGENT_TMP="/usr/local/bin/.dockpanel-agent.dl.$$"
echo "[5/7] Downloading agent binary..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$AGENT_TMP"; then
    rm -f "$AGENT_TMP"
    echo "Error: Could not download the agent binary from $DOWNLOAD_URL"
    echo "  Check connectivity to github.com and that a release asset exists for arch '${ARCH_LABEL}'."
    exit 1
fi

# Integrity: a MISMATCH is fatal, a missing manifest only warns. That is
# setup.sh's policy for a fresh install rather than update.sh's fail-closed one,
# and deliberately so — availability must not brick a first install, but a
# corrupt or substituted binary must never be installed.
if curl -fsSL "$BASE_URL/checksums.txt" -o "$AGENT_TMP.sums" 2>/dev/null; then
    WANT=$(awk -v n="$ASSET" '$2 == n {print $1; exit}' "$AGENT_TMP.sums")
    if [ -n "$WANT" ]; then
        GOT=$(sha256sum "$AGENT_TMP" | awk '{print $1}')
        if [ "$WANT" != "$GOT" ]; then
            rm -f "$AGENT_TMP" "$AGENT_TMP.sums"
            echo "Error: sha256 mismatch for $ASSET — refusing to install."
            echo "  expected $WANT"
            echo "  got      $GOT"
            exit 1
        fi
        echo "  sha256 verified against the release checksums.txt"
    else
        echo "  WARNING: checksums.txt has no entry for $ASSET — installing unverified"
    fi
else
    echo "  WARNING: could not fetch checksums.txt — installing unverified"
fi
rm -f "$AGENT_TMP.sums"

chmod +x "$AGENT_TMP"
mv -f "$AGENT_TMP" /usr/local/bin/dockpanel-agent

# Generate self-signed TLS cert for agent HTTPS
echo "[6/7] Generating TLS certificate..."
if [[ ! -f /etc/dockpanel/ssl/agent.crt ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout /etc/dockpanel/ssl/agent.key \
        -out /etc/dockpanel/ssl/agent.crt -days 3650 -nodes \
        -subj "/CN=dockpanel-agent" > /dev/null 2>&1
    chmod 600 /etc/dockpanel/ssl/agent.key
fi

# Install the systemd unit — TAKEN FROM THE BINARY, not written here.
#
# This step used to hand-write a third copy of the unit into a heredoc, and that
# copy switched every one of systemd's protection directives off, listed no
# writable paths at all, and omitted eight more hardening directives the real
# unit sets — under a comment claiming it matched the local agent's hardening.
# It matched nothing: every server the panel manages remotely ran the agent with
# no sandbox, from s253 to s271. The directives are deliberately not spelled out
# in this comment: tests/sandbox-paths-pin-e2e.sh greps this file for them, and
# a pin that matches its own explanation cannot fail.
#
# The panel's own installers (setup.sh, update.sh) deploy
# panel/agent/dockpanel-agent.service by copying that file. This script has no
# repo tree — it is fetched from the panel and downloads a release binary — so
# it asks the binary it just downloaded, which carries the unit via include_str!
# for exactly the reason agent-self-update.sh does: it cannot then drift from
# the binary that runs it. One unit, three installers, no mirrors.
#
# The `timeout` is load-bearing, not caution. A binary that predates the flag
# does not reject it — it ignores every argument and starts the DAEMON, which
# binds the agent socket and never returns. Without the bound, this installer
# hangs for ever at "[7/7]" against an older release instead of refusing, which
# is what it did when first driven on a real box (s271).
echo "[7/7] Installing service ($INIT_MGR)..."
if ! timeout 15 /usr/local/bin/dockpanel-agent --print-unit > /tmp/dockpanel-agent.service.$$ 2>/dev/null \
   || ! grep -q '^ExecStart=/usr/local/bin/dockpanel-agent' /tmp/dockpanel-agent.service.$$; then
    rm -f /tmp/dockpanel-agent.service.$$
    echo "Error: the downloaded agent could not emit its systemd unit."
    echo "  '/usr/local/bin/dockpanel-agent --print-unit' produced nothing usable, which"
    echo "  means the release binary predates this installer. Writing a unit here instead"
    echo "  is what shipped an unsandboxed agent to every remote server for eighteen"
    echo "  releases, so this installer refuses to guess one."
    exit 1
fi
install -m 644 /tmp/dockpanel-agent.service.$$ /etc/systemd/system/dockpanel-agent.service
rm -f /tmp/dockpanel-agent.service.$$

# Every directory the unit's ReadWritePaths names, DERIVED FROM THE UNIT.
#
# An UNPREFIXED entry that does not exist fails the namespace mount and the
# agent does not start at all — /etc/apt did this to every RPM-family box
# (s264), and /etc/nginx would do it here, because an agent-only server has no
# nginx and nothing above creates that path. A `-`-prefixed entry is worse when
# missing, not better: systemd skips it silently, the unit starts, reports
# success, and every write beneath it fails read-only until the next restart
# (s269). So both halves are created, and the `-` is stripped rather than
# filtered on.
AGENT_RWP="$(sed -n 's/^ReadWritePaths=//p' /etc/systemd/system/dockpanel-agent.service \
             | tr ' ' '\n' | sed 's/^-//' | { grep '^/' || true; })"
for d in $AGENT_RWP; do
    [ -d "$d" ] || mkdir -p "$d" 2>/dev/null || true
done

# On a box with no systemd the unit above is inert — OpenRC reads
# /etc/init.d runscripts — and the agent's OWN service calls (`systemctl restart
# nginx`, reload PHP-FPM, is-active checks, the diagnostics page) fail with
# ENOENT, because that is the name the Rust code calls. So an OpenRC member gets
# a runscript here and a systemctl shim in /usr/local/bin.
#
# The unit file is still written (and still fetched from the binary): its
# ReadWritePaths list above is the single source of truth for which directories
# must exist, and that list is worth having even where nothing reads the unit.
if [ "$INIT_MGR" != "systemd" ]; then
    cat > /etc/init.d/dockpanel-agent << 'AGENTEOF'
#!/sbin/openrc-run
# Managed by DockPanel — written by scripts/install-agent.sh.
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
    # The agent resolves `systemctl` from PATH; that name is the shim below.
    export PATH="/usr/local/sbin:/usr/local/bin:$PATH"
    mkdir -p /run/dockpanel /var/lib/dockpanel/git
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
    chmod 755 /etc/init.d/dockpanel-agent
    touch /var/log/dockpanel-agent.log
    chmod 640 /var/log/dockpanel-agent.log

    if [ ! -e /usr/local/bin/systemctl ]; then
        cat > /usr/local/bin/systemctl << 'SHIMEOF'
#!/bin/sh
# DockPanel systemctl shim for OpenRC — installed by scripts/install-agent.sh.
# Translates the systemctl verbs the agent uses onto rc-service/rc-update. Not a
# systemd implementation: unit files are not read and `show -p …` answers from a
# fixed table. scripts/setup.sh installs the same shim on a panel box.
set -u
[ $# -eq 0 ] && exit 1
verb="$1"; shift

translate() {
    case "$1" in
        php[0-9]*-fpm)
            v=$(printf '%s' "$1" | sed -n 's/^php\([0-9]*\)\.\([0-9]*\)-fpm$/\1\2/p')
            if [ -n "$v" ] && [ -x "/etc/init.d/php-fpm$v" ]; then printf 'php-fpm%s' "$v"; return; fi
            for s in /etc/init.d/php-fpm*; do [ -x "$s" ] && { basename "$s"; return; }; done
            printf '%s' "$1"
            ;;
        *.service) printf '%s' "${1%.service}" ;;
        *) printf '%s' "$1" ;;
    esac
}

now=0; value_only=0; prop=""; svcs=""
while [ $# -gt 0 ]; do
    case "$1" in
        --now) now=1 ;;
        --value) value_only=1 ;;
        -p|--property) shift; prop="${1:-}" ;;
        --quiet|-q|--no-pager|--full|--force|-f) : ;;
        --*) : ;;
        *) svcs="$svcs $1" ;;
    esac
    shift
done

rc=0

# These two verbs take no service operands, so they are answered BEFORE the
# per-service loop below: inside it they would be code that never runs (the
# `svcs` list is empty for them), which is how `list-units` came to print
# nothing at all — and how the panel came to report "No PHP-FPM service
# installed on this host" on a box where PHP-FPM is running.
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
        is-active)
                  if rc-service "$s" status > /dev/null 2>&1; then echo active; else echo inactive; rc=3; fi ;;
        is-enabled)
                  if [ -e "/etc/runlevels/default/$s" ]; then echo enabled; else echo disabled; rc=1; fi ;;
        status)   rc-service "$s" status || rc=$? ;;
        show)
                  if [ "$prop" = "LoadError" ]; then
                      [ "$value_only" = "1" ] && : || echo "LoadError="
                  else
                      [ "$value_only" = "1" ] && : || echo "Id=$s"
                  fi ;;
        list-unit-files|list-units|daemon-reload|reset-failed|kill|mask|unmask) : ;;
        *) echo "systemctl (DockPanel OpenRC shim): unsupported verb '$verb'" >&2; exit 1 ;;
    esac
done

if [ "$verb" = "enable" ] && [ "$now" = "1" ]; then
    for one in $svcs; do
        rc-service "$(translate "$one")" start > /dev/null 2>&1 || true
    done
fi

exit $rc
SHIMEOF
        chmod 755 /usr/local/bin/systemctl
    fi

    if [ ! -e /usr/local/bin/journalctl ]; then
        cat > /usr/local/bin/journalctl << 'JEOF'
#!/bin/sh
# DockPanel journalctl shim for OpenRC — prints the tail of the agent's log.
set -u
n=20
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--lines) shift; n="${1:-20}" ;;
        *) : ;;
    esac
    shift
done
[ -r /var/log/dockpanel-agent.log ] && tail -n "$n" /var/log/dockpanel-agent.log
exit 0
JEOF
        chmod 755 /usr/local/bin/journalctl
    fi

    echo "  OpenRC service + systemctl shim installed"
fi

# Allow agent port through firewall. Check what is ACTUALLY ENFORCING first
# (firewall-cmd --state, not just "is the binary installed") — the same
# split setup.sh's detect_firewall() already guards against (s265): a box can
# have ufw installed but not running while firewalld is the one actually
# enforcing, and checking `command -v ufw` first would silently configure the
# firewall nobody is using.
if command -v firewall-cmd &> /dev/null && firewall-cmd --state &> /dev/null; then
    firewall-cmd --permanent --add-port=${AGENT_PORT}/tcp > /dev/null 2>&1 || true
    firewall-cmd --reload > /dev/null 2>&1 || true
elif command -v ufw &> /dev/null; then
    ufw allow ${AGENT_PORT}/tcp > /dev/null 2>&1 || true
fi

# Start agent. "The command ran" is not the success condition — "the service is
# active" is. install_powerdns ended in `let _ = systemctl restart` and hid three
# separate bugs behind that silence for two releases (lesson #45), so this
# installer polls and shows the failing log line rather than printing a success
# banner over a crash loop. A service caught mid-restart is tolerated, because a
# restarting service reports no state for a moment either way.
if [ "$INIT_MGR" = "systemd" ]; then
    systemctl daemon-reload
    systemctl enable dockpanel-agent >/dev/null 2>&1 || true
    systemctl start dockpanel-agent || true

    AGENT_OK=0
    for _ in $(seq 1 15); do
        STATE=$(systemctl is-active dockpanel-agent 2>/dev/null || true)
        if [[ "$STATE" == "active" ]]; then AGENT_OK=1; break; fi
        [[ "$STATE" == "failed" ]] && break
        sleep 1
    done

    if [[ "$AGENT_OK" != "1" ]]; then
        echo ""
        echo "Error: dockpanel-agent did not start (systemctl is-active: $(systemctl is-active dockpanel-agent 2>/dev/null || echo unknown))"
        echo "Last journal lines:"
        journalctl -u dockpanel-agent -n 15 --no-pager 2>/dev/null || true
        exit 1
    fi
else
    rc-update add dockpanel-agent default >/dev/null 2>&1 || true
    rc-service dockpanel-agent restart >/dev/null 2>&1 \
        || rc-service dockpanel-agent start >/dev/null 2>&1 || true

    AGENT_OK=0
    for _ in $(seq 1 15); do
        if rc-service dockpanel-agent status >/dev/null 2>&1; then AGENT_OK=1; break; fi
        sleep 1
    done

    if [[ "$AGENT_OK" != "1" ]]; then
        echo ""
        echo "Error: dockpanel-agent did not start (rc-service dockpanel-agent status: stopped)"
        echo "Last log lines (/var/log/dockpanel-agent.log):"
        tail -n 15 /var/log/dockpanel-agent.log 2>/dev/null || true
        exit 1
    fi
fi

echo ""
echo "======================================"
echo "  DockPanel Agent installed!"
echo "======================================"
echo ""
echo "  Agent listening on: 0.0.0.0:${AGENT_PORT}"
echo "  Token: ${TOKEN:0:12}..."
echo "  Server ID: ${SERVER_ID}"
echo "  Config: /etc/dockpanel/agent.env"
echo ""
echo "  Return to your DockPanel and click"
echo "  'Test Connection' to verify."
echo ""
