//! The service manager this box actually runs, and the translation layer that
//! lets the panel's systemd-shaped code drive OpenRC natively.
//!
//! # Why this module exists
//!
//! Every service operation in the agent — start, stop, enable, `is-active`,
//! `daemon-reload`, and the journal reads that back the Logs page — was written
//! against `systemctl`/`journalctl`. On Debian and the RHEL family that is
//! correct. On Alpine Linux the init system is **OpenRC**: there is no
//! `systemctl` binary, no units, no journal. Saying "Alpine is supported"
//! therefore means one of two things:
//!
//! 1. Ship a `/usr/local/bin/systemctl` shell script and hope every call site,
//!    including the ones inside `sh -c "systemctl …"` pipelines, goes through
//!    `PATH`. That is a compatibility shim, not support: it is invisible to
//!    the compiler, it is not tested by `cargo test`, and it silently rots.
//! 2. Teach the binary itself what OpenRC is.
//!
//! This module is (2). It has three parts:
//!
//! * **Detection** — [`init_system`] answers systemd vs OpenRC vs neither,
//!   once per process. Detection looks for systemd's *runtime* marker
//!   (`/run/systemd/system`), not merely the binary: a container can ship
//!   `systemctl` without systemd as PID 1, and treating that as systemd is
//!   how a "works on my machine" box starts every unit it is asked for.
//!
//! * **A re-entry point** — [`dispatch_if_requested`]. [`crate::safe_cmd`]
//!   rewrites `safe_command("systemctl")`/`safe_command("journalctl")` into
//!   `dockpanel-agent __dockpanel-initctl systemctl …` on an OpenRC box. The
//!   arguments a caller appends afterwards are *unchanged*, so all ~150 call
//!   sites keep writing systemd-shaped argv and get OpenRC behaviour. Doing
//!   the translation at the one place every child process is built (rather
//!   than at every call site) is what makes this complete: a call site that
//!   was never audited — and there are many, in the mail, SFTP, IAC and
//!   installer paths — is translated too.
//!
//! * **Name translation** — [`service_name`]. A package name, a systemd unit
//!   name and an OpenRC service name are three different strings. The RHEL
//!   port learned this the expensive way (see [`crate::services::pkg`]);
//!   Alpine repeats it: `redis-server` is `redis`, `cron` is `crond`, and the
//!   versioned `php8.4-fpm` unit is the unversioned `php-fpm83` runscript.
//!
//! # What this deliberately does NOT do
//!
//! It does not try to make `systemd-run` work, and it does not pretend a
//! transient unit exists. There is nothing to escape *from* on OpenRC: the
//! runscripts this panel installs do not run under `ProtectSystem=strict`, so
//! a privileged command simply cannot be sandboxed in the first place. See
//! [`crate::safe_cmd::UnsandboxedCommand`], which runs the inner binary
//! directly when there is no systemd.
//!
//! It also does not emulate systemd's *scheduling*: `systemd-run --on-active=`
//! style timers have no OpenRC equivalent, so the panel's own renewal work
//! uses an `/etc/periodic/daily` hook instead (installed by `setup.sh`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

/// The `argv[1]` this binary answers to when re-entered as its own dispatcher.
///
/// Double-underscore-prefixed, so it can never collide with a real option —
/// `main` rejects every other `--` argument outright.
pub const DISPATCH_ARG: &str = "__dockpanel-initctl";

/// The three answers to "what starts services on this box".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InitSystem {
    /// systemd is PID 1 (or, at least, the runtime directory is present).
    Systemd,
    /// OpenRC — Alpine Linux, and Gentoo. `rc-service`/`rc-update`.
    OpenRc,
    /// Neither. Containers, mostly, and then nothing here can work; callers
    /// get honest failures rather than a mangled command.
    None,
}

/// Which init system this process is running under. Detected once.
pub fn init_system() -> InitSystem {
    static DETECTED: OnceLock<InitSystem> = OnceLock::new();
    *DETECTED.get_or_init(|| {
        // The runtime marker, not the binary. `systemctl` exists in plenty of
        // containers whose PID 1 is not systemd, and there it answers
        // "System has not been booted with systemd" while exiting non-zero —
        // which every `is-active` check in this codebase would read as
        // "service is down".
        if Path::new("/run/systemd/system").is_dir() && on_path("systemctl") {
            InitSystem::Systemd
        } else if Path::new("/run/openrc").is_dir() || on_path("rc-service") {
            InitSystem::OpenRc
        } else {
            InitSystem::None
        }
    })
}

/// True when systemd is the service manager here.
pub fn has_systemd() -> bool {
    init_system() == InitSystem::Systemd
}

/// True when OpenRC is the service manager here.
pub fn has_openrc() -> bool {
    init_system() == InitSystem::OpenRc
}

/// Whether a binary is executable, searching the same `PATH` every child gets.
///
/// Deliberately not `which(1)`: the agent is frequently *the* thing that would
/// have to spawn it, and the answer is needed before that is safe.
pub fn on_path(binary: &str) -> bool {
    const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    SAFE_PATH
        .split(':')
        .any(|dir| Path::new(dir).join(binary).is_file())
}

/// The program to spawn, plus arguments to prepend, when `binary` names a
/// service manager this box does not have natively.
///
/// `None` means "spawn it as written" — the normal case on systemd boxes, and
/// the case for every binary that is not `systemctl`/`journalctl`.
pub fn dispatch_target(binary: &str) -> Option<(PathBuf, Vec<OsString>)> {
    if !has_openrc() {
        return None;
    }
    if binary != "systemctl" && binary != "journalctl" {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    Some((
        exe,
        vec![
            OsString::from(DISPATCH_ARG),
            OsString::from(binary),
        ],
    ))
}

/// Handle `dockpanel-agent __dockpanel-initctl <target> <args…>` and return the
/// exit code to use, or `None` when this process was not invoked that way.
///
/// Called at the very top of `main`, before the runtime is used, so a caller
/// that spawned us with `.output()` gets the service manager's output and
/// status verbatim.
pub fn dispatch_if_requested() -> Option<i32> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(DISPATCH_ARG)) {
        return None;
    }
    let target = args
        .next()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let rest: Vec<String> = args.map(|a| a.to_string_lossy().into_owned()).collect();
    Some(match target.as_str() {
        "systemctl" => systemctl(&rest),
        "journalctl" => journalctl(&rest),
        other => {
            eprintln!("dockpanel-agent: unrecognised initctl target '{other}'");
            2
        }
    })
}

/// Install the `/usr/local/bin` `systemctl`/`journalctl` entry points.
///
/// [`dispatch_target`] covers every child the agent itself spawns, but two
/// paths do not go through it: a call site that shells out
/// (`sh -c "systemctl list-units …"`), and the panel's own shell scripts run
/// as children (`update.sh`). Both resolve `systemctl` from `PATH`, so on an
/// OpenRC box the binary installs entry points that re-enter it in
/// [`DISPATCH_ARG`] mode. Written every start, and idempotent, so an
/// upgraded binary cannot leave an older emulator behind.
///
/// Never touches a box that has systemd, and never overwrites a file that
/// does not already look like one of ours.
pub fn install_shim() {
    if !has_openrc() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    for target in ["systemctl", "journalctl"] {
        let path = Path::new("/usr/local/bin").join(target);
        if let Ok(existing) = std::fs::read_to_string(&path) {
            if !existing.contains("dockpanel") {
                continue;
            }
        }
        let body = format!(
            "#!/bin/sh\n\
             # DockPanel compatibility entry point — installed by the agent on\n\
             # OpenRC boxes, which have no systemd. Do not edit: the agent\n\
             # rewrites this file from its own binary at every start.\n\
             exec \"{}\" {DISPATCH_ARG} {target} \"$@\"\n",
            exe.display()
        );
        let _ = std::fs::create_dir_all("/usr/local/bin");
        if std::fs::write(&path, body).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
        }
    }
}

/// The unprivileged identity sites, PHP-FPM pools and terminals run as.
///
/// `www-data` on Debian and on any Alpine box this panel installed (setup.sh
/// creates the account, matching the group Alpine already ships). Falling back
/// to `nobody` matters because PHP-FPM **refuses to start a pool whose user
/// does not exist** — a pool written as `user = www-data` on a box without
/// that account is not a degraded site, it is a dead PHP-FPM for every site on
/// the box.
pub fn web_user() -> String {
    if has_web_user() {
        "www-data".to_string()
    } else {
        "nobody".to_string()
    }
}

/// Whether the `www-data` account exists at all.
///
/// Distinct from the *group*, which exists on every Alpine box (gid 82, with
/// `nginx` in it) and makes `id nginx` look like the account is there. PHP-FPM
/// wants the user.
pub fn has_web_user() -> bool {
    entry_present("/etc/passwd", "www-data")
}

/// The group side of [`web_user`].
pub fn web_group() -> String {
    if entry_present("/etc/group", "www-data") {
        "www-data".to_string()
    } else {
        "nobody".to_string()
    }
}

/// Create the `www-data` account on Alpine when it is missing.
///
/// Debian ships the user; Alpine ships only the **group** (gid 82, with
/// `nginx` as a member), which is why `chown www-data:www-data` and
/// `runuser -u www-data` — both used across the site, terminal, WP-CLI and
/// ownership paths — fail on a stock Alpine box while the group lookups
/// succeed. Rather than teach every one of those call sites a second identity,
/// the panel creates the account once, so one name means one thing on every
/// family. Idempotent, best-effort, and only on OpenRC; if it fails,
/// [`web_user`] keeps reporting `nobody` and only the PHP pool writer is
/// affected.
pub fn ensure_web_user() {
    if !has_openrc() || has_web_user() {
        return;
    }
    if !entry_present("/etc/group", "www-data") {
        let _ = crate::safe_cmd::safe_command_sync("addgroup")
            .args(["-S", "www-data"])
            .status();
    }
    let created = crate::safe_cmd::safe_command_sync("adduser")
        .args([
            "-S",
            "-D",
            "-H",
            "-G",
            "www-data",
            "-s",
            "/sbin/nologin",
            "www-data",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if created {
        tracing::info!("created the www-data account (Alpine ships the group only)");
    } else {
        tracing::warn!(
            "could not create the www-data account; PHP-FPM pools will run as nobody"
        );
    }
}

/// Whether `/etc/passwd`-style `file` has an entry named `name`.
fn entry_present(file: &str, name: &str) -> bool {
    std::fs::read_to_string(file)
        .map(|body| body.lines().any(|l| l.starts_with(&format!("{name}:"))))
        .unwrap_or(false)
}

// ── Service names ────────────────────────────────────────────────────────────

/// The OpenRC service name for a service the Debian-side code names.
///
/// On systemd boxes this is the identity function. On Alpine it is the map the
/// panel needs to reach the same daemon: the names differ because they come
/// from different packaging, not because the panel means something else.
///
/// Kept a pure function of its inputs (no filesystem probing) so it can be
/// tested and reasoned about; the PHP case, which genuinely needs to look at
/// what is installed, goes through [`php_fpm_service`].
pub fn service_name(unit: &str) -> String {
    if has_systemd() {
        return unit.to_string();
    }
    let base = unit
        .strip_suffix(".service")
        .unwrap_or(unit)
        .strip_suffix(".timer")
        .unwrap_or(unit.strip_suffix(".service").unwrap_or(unit));

    match base {
        // Alpine ships `redis`, Debian `redis-server`.
        "redis-server" => "redis".into(),
        // Debian uses `cron`; Alpine's runscript is `crond`.
        "cron" | "crond" => "crond".into(),
        // Alpine's MariaDB runscript is `mariadb`, and `mysql` is an alias
        // provided by the same package.
        "mysql" | "mysqld" => "mariadb".into(),
        // One runscript for the whole Dovecot suite.
        "dovecot-imapd" | "dovecot-pop3d" | "dovecot-lmtpd" | "dovecot-core" => "dovecot".into(),
        // OpenSSH's unit is `ssh.service` on Debian, `sshd` on Alpine.
        "ssh" => "sshd".into(),
        // The RHEL family's single unversioned FPM service is also Alpine's
        // shape, but Alpine *does* version it (`php-fpm83`).
        other if is_php_fpm(other) => php_fpm_service(other),
        other => other.into(),
    }
}

/// True for `php-fpm` and `php<digits>[.<digits>]-fpm`.
fn is_php_fpm(name: &str) -> bool {
    name == "php-fpm"
        || name
            .strip_prefix("php")
            .and_then(|r| r.strip_suffix("-fpm"))
            .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// True when a service name is PHP-FPM under **any** family's spelling.
///
/// Three shapes mean the same daemon: Debian's `php8.3-fpm`, the RHEL family's
/// unversioned `php-fpm`, and Alpine's `php-fpm83` — which is what a listing of
/// this box's services actually contains (`init::list_units`). The panel
/// enumerates services to expand the version-less `restart-service:php-fpm`
/// alias it sends, and a matcher that knows only the first two shapes finds
/// nothing on Alpine, so the fix answers "No PHP-FPM service installed on this
/// host" on a box where PHP-FPM is running and the panel prints an opaque
/// "Operation failed. Reference: …". Putting the knowledge here keeps the one
/// list of spellings in the one module that owns the translation.
pub fn is_php_fpm_service(name: &str) -> bool {
    let name = name.trim_end_matches(".service");
    if is_php_fpm(name) {
        return true;
    }
    // Alpine's shape: `php-fpm` + the digits of the version.
    name.strip_prefix("php-fpm")
        .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()))
}

/// Resolve the PHP-FPM runscript this box actually has.
///
/// Alpine packages PHP-FPM per minor version and names the runscript
/// `php-fpm<XY>` — `php-fpm83`, never the Debian-shaped `php8.3-fpm`. Asked
/// for a specific version, that version is preferred (the digit form maps
/// `8.3` to `83`); asked for the bare `php-fpm`, the highest installed
/// version is used, which is also what `apk` would have installed last.
fn php_fpm_service(base: &str) -> String {
    // A distribution that ships the unversioned runscript (or the panel's own
    // `php-fpm` naming) wins outright.
    if Path::new("/etc/init.d/php-fpm").exists() {
        return "php-fpm".into();
    }
    let want = base
        .trim_start_matches("php")
        .trim_end_matches("-fpm")
        .replace('.', "");
    let mut best: Option<String> = None;
    if let Ok(entries) = std::fs::read_dir("/etc/init.d") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(version) = name.strip_prefix("php-fpm") else {
                continue;
            };
            if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if !want.is_empty() && version == want {
                return name;
            }
            if best.as_deref().is_none_or(|b| name.as_str() > b) {
                best = Some(name);
            }
        }
    }
    best.unwrap_or_else(|| base.to_string())
}

/// The runscript path OpenRC would use for a service name.
pub fn runscript(name: &str) -> PathBuf {
    Path::new("/etc/init.d").join(name)
}

/// True when OpenRC could start this service at all.
pub fn service_exists(name: &str) -> bool {
    runscript(&service_name(name)).is_file()
}

/// True when the service is running right now.
///
/// `/run/openrc/started/<name>` is OpenRC's own state marker and is the
/// authoritative answer; the fallback covers a runscript that manages a
/// daemon outside OpenRC's supervision.
pub fn is_active(name: &str) -> bool {
    let svc = service_name(name);
    if Path::new("/run/openrc/started").join(&svc).exists() {
        return true;
    }
    quiet_rc_service(&svc, "status") == 0
}

/// `Some(true)` when the service is in a runlevel (starts at boot),
/// `Some(false)` when its runscript exists but it is not, `None` when there is
/// no such service. Mirrors `systemctl is-enabled`'s three answers.
pub fn is_enabled(name: &str) -> Option<bool> {
    let svc = service_name(name);
    if !runscript(&svc).is_file() {
        return None;
    }
    let Ok(runlevels) = std::fs::read_dir("/etc/runlevels") else {
        return Some(false);
    };
    let linked = runlevels.flatten().any(|level| {
        level
            .path()
            .join(&svc)
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    });
    Some(linked)
}

/// Every service OpenRC knows about, by runscript name.
pub fn list_units() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/etc/init.d")
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    (e.path().is_file() && !name.contains('.')).then_some(name)
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

// ── The `systemctl` emulator ─────────────────────────────────────────────────

/// What a systemd verb means on this box. Pure, so the mapping is testable
/// without a running service manager.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Plan {
    /// Nothing to do, and success is the right answer (`daemon-reload`,
    /// `reset-failed` — systemd bookkeeping with no OpenRC counterpart).
    Noop,
    /// `rc-service <name> <verb>`, e.g. `start`, `stop`, `reload`.
    Service(&'static str),
    /// `rc-update add <name> default`, plus a start when `--now` was given.
    Enable,
    /// `rc-update del <name>`, plus a stop when `--now` was given.
    Disable,
    IsActive,
    IsEnabled,
    /// `show -p <property> --value`.
    Show,
    /// `list-units`/`list-unit-files`.
    List,
    /// A verb with no meaning here; exit non-zero and say so.
    Unsupported,
}

fn plan(verb: &str) -> Plan {
    match verb {
        "daemon-reload" | "reset-failed" | "preset" | "mask" | "unmask" | "kill" => Plan::Noop,
        "start" => Plan::Service("start"),
        "stop" => Plan::Service("stop"),
        "restart" | "try-restart" | "condrestart" => Plan::Service("restart"),
        "reload" | "force-reload" | "try-reload-or-restart" | "reload-or-restart" => {
            Plan::Service("reload")
        }
        "status" => Plan::Service("status"),
        "enable" => Plan::Enable,
        "disable" => Plan::Disable,
        "is-active" => Plan::IsActive,
        "is-enabled" => Plan::IsEnabled,
        "show" => Plan::Show,
        "list-units" | "list-unit-files" => Plan::List,
        _ => Plan::Unsupported,
    }
}

/// Parsed `systemctl` command line. Flags with no OpenRC meaning are accepted
/// and dropped rather than treated as errors: a caller passing `--no-block`
/// wants the stop to happen, not a usage message.
#[derive(Default)]
struct SystemctlArgs {
    quiet: bool,
    now: bool,
    value_only: bool,
    properties: Vec<String>,
    verb: String,
    operands: Vec<String>,
}

fn parse_systemctl(args: &[String]) -> SystemctlArgs {
    let mut out = SystemctlArgs::default();
    let mut i = 0;
    let mut only_operands = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if !only_operands && arg == "--" {
            only_operands = true;
        } else if !only_operands && (arg == "-q" || arg == "--quiet") {
            out.quiet = true;
        } else if !only_operands && arg == "--now" {
            out.now = true;
        } else if !only_operands && arg == "--value" {
            out.value_only = true;
        } else if !only_operands && (arg == "-p" || arg == "--property") {
            i += 1;
            if let Some(v) = args.get(i) {
                out.properties.push(v.clone());
            }
        } else if !only_operands {
            if let Some(v) = arg
                .strip_prefix("--property=")
                .or_else(|| arg.strip_prefix("-p"))
                .filter(|_| arg.starts_with("--property=") || arg.starts_with("-p"))
            {
                out.properties.push(v.to_string());
            } else if arg.starts_with('-') {
                // --no-block, --no-pager, --type=service, --system, --all,
                // --plain, --no-legend, --full, --runtime, --force, …
                // None of them change which daemon OpenRC starts.
            } else if out.verb.is_empty() {
                out.verb = arg.to_string();
            } else {
                out.operands.push(arg.to_string());
            }
        } else {
            out.operands.push(arg.to_string());
        }
        i += 1;
    }
    out
}

fn systemctl(args: &[String]) -> i32 {
    let parsed = parse_systemctl(args);
    if parsed.verb.is_empty() {
        eprintln!("systemctl: a verb is required");
        return 1;
    }

    match plan(&parsed.verb) {
        Plan::Noop => 0,
        Plan::Service(verb) => {
            let mut code = 0;
            for unit in &parsed.operands {
                let svc = service_name(unit);
                if !service_exists(&svc) {
                    // No runscript. rc-service would answer a bare exit 1 and
                    // one generic stderr line; naming the service and where it
                    // was looked for is what the caller's log needs, and the
                    // exit code stays what callers already handle.
                    eprintln!("dockpanel: {svc}: service not found in /etc/init.d");
                    code = 1;
                    continue;
                }
                code = rc_service(&svc, verb);
                // OpenRC runscripts only support `reload` when they declare
                // it. A caller that asked for a reload wants the new
                // configuration live; restarting is the honest fallback, and
                // is what an operator would do by hand.
                if code != 0 && verb == "reload" {
                    eprintln!("dockpanel: {svc} has no reload command — restarting it instead");
                    code = rc_service(&svc, "restart");
                }
            }
            code
        }
        Plan::Enable => enable(&parsed.operands, parsed.now),
        Plan::Disable => disable(&parsed.operands, parsed.now),
        Plan::IsActive => {
            let mut code = 0;
            for unit in &parsed.operands {
                let svc = service_name(unit);
                let active = is_active(&svc);
                if !parsed.quiet {
                    println!("{}", if active { "active" } else { "inactive" });
                }
                if !active {
                    code = 3;
                }
            }
            code
        }
        Plan::IsEnabled => {
            let mut code = 0;
            for unit in &parsed.operands {
                let svc = service_name(unit);
                match is_enabled(&svc) {
                    Some(true) => println!("enabled"),
                    Some(false) => {
                        println!("disabled");
                        code = 1;
                    }
                    None => {
                        // systemd prints nothing and exits 1 for an unknown
                        // unit; callers distinguish "not installed" from
                        // "disabled" on exactly this difference.
                        code = 1;
                    }
                }
            }
            code
        }
        Plan::Show => {
            // The one property the agent reads is `LoadError`, and an empty
            // value is the "systemd accepted the unit" answer it expects.
            // Nothing on OpenRC can fail to load, so every property is empty.
            for _ in &parsed.properties {
                if parsed.value_only {
                    println!();
                }
            }
            0
        }
        Plan::List => {
            for name in list_units() {
                let state = if is_active(&name) { "active" } else { "inactive" };
                let enabled = match is_enabled(&name) {
                    Some(true) => "enabled",
                    _ => "disabled",
                };
                println!("{name}.service loaded {state} {enabled}");
            }
            0
        }
        Plan::Unsupported => {
            eprintln!(
                "systemctl: '{}' is not available on this OpenRC system \
                 (DockPanel compatibility layer)",
                parsed.verb
            );
            1
        }
    }
}

fn enable(units: &[String], now: bool) -> i32 {
    let mut code = 0;
    for unit in units {
        let svc = service_name(unit);
        if !runscript(&svc).is_file() {
            eprintln!("systemctl: service '{svc}' does not exist");
            code = 1;
            continue;
        }
        let added = rc_update("add", &svc, "default");
        if added != 0 {
            code = added;
            continue;
        }
        if now {
            code = rc_service(&svc, "start");
        }
    }
    code
}

fn disable(units: &[String], now: bool) -> i32 {
    let mut code = 0;
    for unit in units {
        let svc = service_name(unit);
        if !runscript(&svc).is_file() {
            eprintln!("systemctl: service '{svc}' does not exist");
            code = 1;
            continue;
        }
        if now {
            code = rc_service(&svc, "stop");
        }
        let removed = rc_update("del", &svc, "");
        if removed != 0 {
            code = removed;
        }
    }
    code
}

fn rc_service(service: &str, verb: &str) -> i32 {
    // Never hand the caller's stdout/stderr down to the daemon. `rc-service`
    // starts the service, and a daemon that keeps its inherited descriptors —
    // Dovecot among them (its master leaves stderr pointing at whatever it
    // inherited) — holds open the capture pipe a caller like
    // `Command::output()` reads until EOF, so a perfectly successful start
    // blocks the caller forever. The exit code is the contract; the
    // runscript's chatter is not, and daemon logs go to the system log anyway.
    status_of(
        crate::safe_cmd::safe_command_sync("rc-service")
            .args([service, verb])
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

fn quiet_rc_service(service: &str, verb: &str) -> i32 {
    status_of(
        crate::safe_cmd::safe_command_sync("rc-service")
            .args([service, verb])
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

/// `rc-update <verb> <service> <runlevel>`. An empty runlevel is omitted, which
/// is what `del` wants.
fn rc_update(verb: &str, service: &str, runlevel: &str) -> i32 {
    let mut cmd = crate::safe_cmd::safe_command_sync("rc-update");
    cmd.arg(verb).arg(service);
    if !runlevel.is_empty() {
        cmd.arg(runlevel);
    }
    status_of(&mut cmd)
}

fn status_of(cmd: &mut std::process::Command) -> i32 {
    match cmd.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("dockpanel: could not run {:?}: {e}", cmd.get_program());
            127
        }
    }
}

// ── The `journalctl` emulator ────────────────────────────────────────────────

/// Parsed `journalctl` command line; only the parts that can be answered from
/// a log file matter here.
#[derive(Default)]
struct JournalArgs {
    units: Vec<String>,
    lines: usize,
    vacuum: bool,
}

fn parse_journalctl(args: &[String]) -> JournalArgs {
    let mut out = JournalArgs {
        lines: 200,
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "-u" || arg == "--unit" {
            i += 1;
            if let Some(v) = args.get(i) {
                out.units.push(v.clone());
            }
        } else if let Some(v) = arg.strip_prefix("--unit=") {
            out.units.push(v.to_string());
        } else if arg == "-n" || arg == "--lines" {
            i += 1;
            if let Some(v) = args.get(i).and_then(|v| v.parse::<usize>().ok()) {
                out.lines = v;
            }
        } else if let Some(v) = arg
            .strip_prefix("--lines=")
            .and_then(|v| v.parse::<usize>().ok())
        {
            out.lines = v;
        } else if arg.starts_with("--vacuum-") {
            out.vacuum = true;
        }
        // `-o short-iso`, `--no-pager`, `--since`, `-q`, `-f`, `-p`, `-b`:
        // presentation and filtering choices that a file read cannot honour.
        // Ignoring them returns the lines rather than nothing, which is what
        // the caller is asking for.
        i += 1;
    }
    out
}

fn journalctl(args: &[String]) -> i32 {
    let parsed = parse_journalctl(args);
    if parsed.vacuum {
        // No journal to vacuum. Answering success is the truthful "there is
        // nothing here to clean up" and stops the cleanup task reporting an
        // error for work it cannot do.
        return 0;
    }

    if parsed.units.is_empty() {
        for line in read_last_lines(Path::new("/var/log/messages"), parsed.lines) {
            println!("{line}");
        }
        return 0;
    }

    for unit in &parsed.units {
        let svc = service_name(unit);
        let mut emitted = false;
        for path in log_paths(&svc) {
            if !path.is_file() || path == Path::new("/var/log/messages") {
                continue;
            }
            for line in read_last_lines(&path, parsed.lines) {
                println!("{line}");
                emitted = true;
            }
            break;
        }
        if emitted {
            continue;
        }
        // No per-service log: Alpine's syslog daemon writes everything to
        // /var/log/messages, tagged with the daemon's name.
        let wanted = read_last_lines(Path::new("/var/log/messages"), 4000)
            .into_iter()
            .filter(|l| l.to_ascii_lowercase().contains(&svc.to_ascii_lowercase()))
            .collect::<Vec<_>>();
        let lines = if wanted.is_empty() {
            read_last_lines(Path::new("/var/log/messages"), parsed.lines)
        } else {
            wanted
                .into_iter()
                .rev()
                .take(parsed.lines)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect()
        };
        for line in lines {
            println!("{line}");
        }
    }
    0
}

/// Where a service's output could be, most specific first.
fn log_paths(svc: &str) -> Vec<PathBuf> {
    vec![
        PathBuf::from(format!("/var/log/{svc}.log")),
        PathBuf::from(format!("/var/log/{svc}/current")),
        PathBuf::from("/var/log/messages"),
    ]
}

/// The last `n` lines of a file, reading at most 512 KiB from its end so a
/// multi-gigabyte log cannot be loaded to print its tail.
fn read_last_lines(path: &Path, n: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(512 * 1024);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if start > 0 && !lines.is_empty() {
        // The first line is almost certainly cut in half.
        lines.remove(0);
    }
    if lines.len() > n {
        lines.drain(..lines.len() - n);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verbs every call site in the agent actually uses, and what each one
    /// must become. A verb added later shows up here as `Unsupported`, which
    /// is a failing test rather than a silent no-op on Alpine.
    #[test]
    fn every_verb_the_agent_uses_is_planned() {
        for verb in ["start", "stop", "restart", "reload", "status"] {
            assert!(
                matches!(plan(verb), Plan::Service(_)),
                "{verb} must map onto rc-service"
            );
        }
        for verb in ["daemon-reload", "reset-failed"] {
            assert_eq!(plan(verb), Plan::Noop, "{verb} has no OpenRC counterpart");
        }
        assert_eq!(plan("enable"), Plan::Enable);
        assert_eq!(plan("disable"), Plan::Disable);
        assert_eq!(plan("is-active"), Plan::IsActive);
        assert_eq!(plan("is-enabled"), Plan::IsEnabled);
        assert_eq!(plan("show"), Plan::Show);
        assert_eq!(plan("list-units"), Plan::List);
        assert_eq!(plan("nonsense"), Plan::Unsupported);
    }

    /// The restart-instead-of-reload fallback keys off the verb, so the verbs
    /// that mean "reload" must all reach `reload`.
    #[test]
    fn reload_is_reload_and_not_a_restart_by_default() {
        assert_eq!(plan("reload"), Plan::Service("reload"));
        assert_eq!(plan("try-reload-or-restart"), Plan::Service("reload"));
    }

    #[test]
    fn args_are_split_into_verb_and_operands() {
        let parsed = parse_systemctl(&[
            "restart".into(),
            "fail2ban".into(),
            "sshd".into(),
        ]);
        assert_eq!(parsed.verb, "restart");
        assert_eq!(parsed.operands, ["fail2ban", "sshd"]);
        assert!(!parsed.quiet && !parsed.now);

        // The two shapes `check_systemd_service` uses.
        let parsed = parse_systemctl(&["is-active".into(), "--quiet".into(), "nginx".into()]);
        assert_eq!(parsed.verb, "is-active");
        assert!(parsed.quiet);
        assert_eq!(parsed.operands, ["nginx"]);
    }

    /// `systemctl stop --no-block <unit>`: an unknown flag must not be read as
    /// the verb, or the timeout cleanup in `safe_cmd.rs` stops nothing.
    #[test]
    fn unknown_flags_are_dropped_not_taken_as_the_verb() {
        let parsed = parse_systemctl(&[
            "stop".into(),
            "--no-block".into(),
            "dockpanel-op-abc".into(),
        ]);
        assert_eq!(parsed.verb, "stop");
        assert_eq!(parsed.operands, ["dockpanel-op-abc"]);
    }

    #[test]
    fn show_reads_its_property() {
        let parsed = parse_systemctl(&[
            "show".into(),
            "dockpanel-agent".into(),
            "-p".into(),
            "LoadError".into(),
            "--value".into(),
        ]);
        assert_eq!(parsed.verb, "show");
        assert_eq!(parsed.properties, ["LoadError"]);
        assert!(parsed.value_only);

        let parsed = parse_systemctl(&[
            "show".into(),
            "-p".into(),
            "ActiveState".into(),
            "nginx".into(),
        ]);
        assert_eq!(parsed.properties, ["ActiveState"]);
        assert_eq!(parsed.operands, ["nginx"]);
    }

    #[test]
    fn journal_flags_the_panel_passes_are_understood() {
        let parsed = parse_journalctl(&[
            "-u".into(),
            "pdns".into(),
            "--no-pager".into(),
            "-n".into(),
            "40".into(),
            "-o".into(),
            "cat".into(),
        ]);
        assert_eq!(parsed.units, ["pdns"]);
        assert_eq!(parsed.lines, 40);
        assert!(!parsed.vacuum);

        assert!(parse_journalctl(&["--vacuum-size=100M".into()]).vacuum);
        assert!(parse_journalctl(&["--vacuum-time=3d".into()]).vacuum);
        // `--since 1 hour ago` must not be mistaken for a unit.
        let parsed = parse_journalctl(&[
            "--since".into(),
            "1 hour ago".into(),
            "--no-pager".into(),
        ]);
        assert!(parsed.units.is_empty());
        assert_eq!(parsed.lines, 200);
    }

    #[test]
    fn is_php_fpm_service_knows_all_three_spellings() {
        // Debian, RHEL, Alpine — and the `.service` suffix the enumeration
        // hands over before it is trimmed.
        for name in [
            "php-fpm",
            "php8.3-fpm",
            "php-fpm83",
            "php-fpm83.service",
            "php8.4-fpm.service",
        ] {
            assert!(is_php_fpm_service(name), "{name} should be PHP-FPM");
        }
        // Near-misses must not be: this decides which services the panel's
        // "restart PHP-FPM" button restarts.
        for name in ["php-fpmfoo", "php-fpm-", "php83", "nginx", "php"] {
            assert!(!is_php_fpm_service(name), "{name} should not be PHP-FPM");
        }
    }

    #[test]
    fn read_last_lines_takes_the_tail() {
        let path = std::env::temp_dir().join(format!(
            "dockpanel-init-log-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        assert_eq!(read_last_lines(&path, 2), ["two", "three"]);
        assert_eq!(read_last_lines(&path, 10), ["one", "two", "three"]);
        let _ = std::fs::remove_file(&path);
    }
}
