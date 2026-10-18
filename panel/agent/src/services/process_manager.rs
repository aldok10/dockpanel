//! Service inventory and lifecycle control for the Process Manager page.
//!
//! OxMgr answers one question on one screen — "what is running, for how long,
//! how much CPU/RAM, how many restarts, and can I restart it" — for the
//! processes it supervises. DockPanel supervises its own stack with **systemd**
//! (or OpenRC), so this module reports that accounting rather than reimplementing
//! a supervisor: the daemons the panel itself runs on (`dockpanel-agent`,
//! `dockpanel-api`, `dockpanel-mailapi`, `dockpanel-mcp`), the stack it installs
//! (nginx, PHP-FPM, the databases, the MTA, the DNS and security daemons), and
//! the per-site `dockpanel-app-*.service` units `app_process.rs` writes.
//!
//! # Where the numbers come from
//!
//! On systemd, `systemctl show` already exposes the cgroup counters — the
//! *whole* service, not just its main PID, which is the difference between a
//! meaningful figure for a forking daemon like PHP-FPM or PostgreSQL and a
//! misleading one. This module reads:
//!
//! * `MemoryCurrent` — the cgroup's resident memory.
//! * `CPUUsageNSec` — cumulative CPU time. A single reading is not a
//!   percentage, so two are taken ~250 ms apart and differenced against the
//!   number of CPUs, exactly the way the process table measures its own rows.
//! * `NRestarts` — systemd's own restart counter (the `↺` column).
//! * `ActiveState`/`SubState`/`UnitFileState`/`MainPID`/`LoadState`.
//!
//! Uptime is not a `systemctl` property in a form worth parsing (the human
//! timestamps are locale-flavoured strings), so it comes from the main PID's
//! `run_time()` in `sysinfo` — the same clock `ps` uses.
//!
//! # OpenRC
//!
//! `systemctl show` is translated to empty output on an OpenRC box (see
//! [`crate::services::init`]), and there are no cgroups to read. So this module
//! branches on [`init::init_system`] and takes the OpenRC answers from OpenRC's
//! own state — `rc-service <svc> status`, `/run/<svc>.pid`, and `sysinfo` for
//! the counters. `NRestarts` has no OpenRC equivalent and is reported as `null`
//! rather than a fabricated zero.

use crate::safe_cmd::safe_command;
use crate::services::init::{self, InitSystem};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use sysinfo::{ProcessesToUpdate, System};

/// A unit DockPanel always knows about, whether or not it is installed.
struct Catalogue {
    unit: &'static str,
    label: &'static str,
    category: &'static str,
}

/// The units the panel itself runs on. These are reported even when `systemctl`
/// says `not-found`, because "the mail API is not installed" is a fact an
/// operator wants to see on the process screen, not a row that silently
/// disappears.
const PANEL_UNITS: &[&str] = &["dockpanel-agent", "dockpanel-api", "dockpanel-mailapi", "dockpanel-mcp"];

/// Everything else the panel may install, with the category it sorts under.
/// A candidate whose unit does not exist is dropped on the floor (except the
/// panel units above) so the page reflects the box rather than the catalogue.
const CATALOGUE: &[Catalogue] = &[
    Catalogue { unit: "dockpanel-agent", label: "DockPanel Agent", category: "panel" },
    Catalogue { unit: "dockpanel-api", label: "DockPanel API", category: "panel" },
    Catalogue { unit: "dockpanel-mailapi", label: "DockPanel Mail API", category: "panel" },
    Catalogue { unit: "dockpanel-mcp", label: "DockPanel MCP", category: "panel" },
    Catalogue { unit: "nginx", label: "nginx", category: "web" },
    Catalogue { unit: "docker", label: "Docker", category: "web" },
    Catalogue { unit: "php-fpm", label: "PHP-FPM", category: "web" },
    Catalogue { unit: "php8.5-fpm", label: "PHP 8.5 FPM", category: "web" },
    Catalogue { unit: "php8.4-fpm", label: "PHP 8.4 FPM", category: "web" },
    Catalogue { unit: "php8.3-fpm", label: "PHP 8.3 FPM", category: "web" },
    Catalogue { unit: "php8.2-fpm", label: "PHP 8.2 FPM", category: "web" },
    Catalogue { unit: "php8.1-fpm", label: "PHP 8.1 FPM", category: "web" },
    Catalogue { unit: "postgresql", label: "PostgreSQL", category: "data" },
    Catalogue { unit: "mariadb", label: "MariaDB", category: "data" },
    Catalogue { unit: "mysql", label: "MySQL", category: "data" },
    Catalogue { unit: "redis-server", label: "Redis", category: "data" },
    Catalogue { unit: "postfix", label: "Postfix", category: "mail" },
    Catalogue { unit: "dovecot", label: "Dovecot", category: "mail" },
    Catalogue { unit: "opendkim", label: "OpenDKIM", category: "mail" },
    Catalogue { unit: "pdns", label: "PowerDNS", category: "dns" },
    Catalogue { unit: "fail2ban", label: "Fail2Ban", category: "security" },
    Catalogue { unit: "cloudflared", label: "Cloudflare Tunnel", category: "security" },
    Catalogue { unit: "cron", label: "Cron", category: "system" },
    Catalogue { unit: "crond", label: "Cron", category: "system" },
];

/// One row of the Process Manager's Services tab.
#[derive(Serialize)]
pub struct ServiceEntry {
    /// The unit name without its type suffix (`nginx`, `dockpanel-api`).
    pub unit: String,
    pub label: String,
    pub category: String,
    pub description: String,
    /// systemd `LoadState` — `loaded`, `not-found`, `masked`, …
    pub load_state: String,
    /// `active`, `inactive`, `failed`, `activating`, `deactivating`.
    pub active_state: String,
    /// `running`, `exited`, `dead`, `failed`, …
    pub sub_state: String,
    /// Whether the unit starts at boot, when the answer is knowable.
    pub enabled: Option<bool>,
    pub main_pid: Option<u32>,
    pub memory_mb: Option<f64>,
    pub cpu_pct: Option<f32>,
    pub uptime_secs: Option<u64>,
    pub restarts: Option<u64>,
}

/// The catalogue plus any per-site app units on disk, deduplicated, in
/// catalogue order with site units last.
fn candidates() -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = CATALOGUE
        .iter()
        .map(|c| (c.unit.to_string(), c.label.to_string(), c.category.to_string()))
        .collect();

    // Site app units are named by `app_process::service_name`; enumerate what
    // is actually on disk rather than inventing names, so a unit that was
    // deleted stops appearing here at the same moment systemd forgets it.
    if let Ok(entries) = std::fs::read_dir("/etc/systemd/system") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(domain) = name.strip_prefix("dockpanel-app-") {
                if let Some(domain) = domain.strip_suffix(".service") {
                    let unit = format!("dockpanel-app-{domain}");
                    out.push((unit, format!("App: {domain}"), "site".into()));
                }
            }
        }
    }

    out
}

/// True when `unit` is one the panel is willing to start, stop or restart.
/// Recomputed per request against the same catalogue the collector uses, so a
/// caller cannot name a unit the screen never showed.
pub fn is_controllable(unit: &str) -> bool {
    candidates().iter().any(|(u, _, _)| u == unit)
}

/// The two units whose own restart tears down the process answering the
/// request. They are still controllable, but the action has to be handed to
/// PID1 to run later (see [`perform_action`]) instead of being run inline.
fn is_self_hosting(unit: &str) -> bool {
    matches!(unit, "dockpanel-agent" | "dockpanel-api")
}

fn strip_suffix(id: &str) -> String {
    id.trim_end_matches(".service")
        .trim_end_matches(".timer")
        .to_string()
}

/// Collect one row per candidate. Never fails: a box with no init system
/// returns an empty list rather than an error, because "nothing to show" is a
/// legitimate answer and a 500 is not.
pub async fn collect() -> Vec<ServiceEntry> {
    match init::init_system() {
        InitSystem::Systemd => collect_systemd().await,
        InitSystem::OpenRc => collect_openrc().await,
        InitSystem::None => Vec::new(),
    }
}

const SHOW_PROPS: &[&str] = &[
    "Id",
    "Description",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "MainPID",
    "NRestarts",
    "MemoryCurrent",
    "CPUUsageNSec",
];

/// Run `systemctl show` for every unit and return the parsed per-unit property
/// blocks, keyed by the bare unit name.
async fn systemctl_show(
    units: &[String],
    props: &[&str],
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    let mut cmd = safe_command("systemctl");
    cmd.arg("show");
    cmd.args(units);
    for p in props {
        cmd.arg("-p").arg(p);
    }
    let out = cmd.output().await.map_err(|e| format!("systemctl show: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl show exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_show(&text))
}

/// Parse `systemctl show` output. Each unit is a block of `Key=Value` lines
/// separated by a blank line; the block is keyed by its `Id` (suffix stripped).
fn parse_show(stdout: &str) -> HashMap<String, HashMap<String, String>> {
    let mut result = HashMap::new();
    let mut current: HashMap<String, String> = HashMap::new();
    let flush = |block: &mut HashMap<String, String>, result: &mut HashMap<String, HashMap<String, String>>| {
        if block.is_empty() {
            return;
        }
        if let Some(id) = block.get("Id") {
            result.insert(strip_suffix(id), std::mem::take(block));
        } else {
            block.clear();
        }
    };
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            flush(&mut current, &mut result);
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            current.insert(k.trim().to_string(), v.to_string());
        }
    }
    flush(&mut current, &mut result);
    result
}

fn parse_u64(props: &HashMap<String, String>, key: &str) -> Option<u64> {
    props.get(key).and_then(|v| v.trim().parse::<u64>().ok())
}

fn parse_enabled(props: &HashMap<String, String>) -> Option<bool> {
    match props.get("UnitFileState").map(|s| s.as_str()) {
        Some("enabled") | Some("enabled-runtime") | Some("static") | Some("alias")
        | Some("indirect") | Some("generated") => Some(true),
        Some("disabled") | Some("masked") | Some("masked-runtime") => Some(false),
        _ => None,
    }
}

/// systemd's `[not set]` and the `u64::MAX` it prints for "unlimited" are both
/// "no number", not a memory figure.
fn parse_memory_mb(props: &HashMap<String, String>) -> Option<f64> {
    let raw = props.get("MemoryCurrent")?.trim();
    let bytes: u64 = raw.parse().ok()?;
    if bytes >= (1u64 << 60) {
        return None;
    }
    Some(bytes as f64 / 1_048_576.0)
}

async fn collect_systemd() -> Vec<ServiceEntry> {
    let list = candidates();
    let units: Vec<String> = list.iter().map(|(u, _, _)| u.clone()).collect();

    let first = match systemctl_show(&units, SHOW_PROPS).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Process Manager: {e}");
            return Vec::new();
        }
    };

    // CPU needs a delta: `CPUUsageNSec` is cumulative service CPU time, and one
    // reading of a monotonic counter measures "since boot", not "now".
    let t0 = Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let second = systemctl_show(&units, &["Id", "CPUUsageNSec"]).await.unwrap_or_default();
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;

    // Main-PID uptimes. One refresh is enough: `run_time()` is an absolute
    // age, not a rate.
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut out = Vec::with_capacity(list.len());
    for (unit, label, category) in list {
        let props = match first.get(&unit) {
            Some(p) => p,
            None => continue,
        };
        let load_state = props.get("LoadState").cloned().unwrap_or_default();
        // A catalogue entry that is not installed on this box is not a row.
        // Panel units stay, so "the agent is not installed" is still visible.
        if load_state == "not-found" && !PANEL_UNITS.contains(&unit.as_str()) {
            continue;
        }

        let cpu_pct = cpu_delta_pct(
            parse_u64(second.get(&unit).unwrap_or(&HashMap::new()), "CPUUsageNSec"),
            parse_u64(props, "CPUUsageNSec"),
            elapsed,
            ncpu,
        );

        let main_pid = parse_u64(props, "MainPID")
            .filter(|p| *p > 1)
            .map(|p| p as u32);

        let uptime_secs = main_pid.and_then(|pid| {
            sys.process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.run_time())
        });

        out.push(ServiceEntry {
            unit: unit.clone(),
            label,
            category,
            description: props.get("Description").cloned().unwrap_or_default(),
            load_state,
            active_state: props.get("ActiveState").cloned().unwrap_or_else(|| "unknown".into()),
            sub_state: props.get("SubState").cloned().unwrap_or_else(|| "unknown".into()),
            enabled: parse_enabled(props),
            main_pid,
            memory_mb: parse_memory_mb(props),
            cpu_pct,
            uptime_secs,
            restarts: parse_u64(props, "NRestarts"),
        });
    }
    out
}

/// Percentage of one CPU consumed across the sample window, consistent with how
/// the process table reports a single process (so `100%` means one full core).
fn cpu_delta_pct(after: Option<u64>, before: Option<u64>, elapsed_secs: f64, ncpu: f64) -> Option<f32> {
    let (a, b) = (after?, before?);
    if a < b {
        // The service restarted between samples; a negative delta is not a rate.
        return Some(0.0);
    }
    let delta_ns = (a - b) as f64;
    let pct = delta_ns / 1e9 / elapsed_secs / ncpu * 100.0;
    Some(pct.clamp(0.0, 100.0) as f32)
}

async fn collect_openrc() -> Vec<ServiceEntry> {
    let list = candidates();

    // Same two-sample pattern as the systemd branch, but the counters come from
    // the process table because OpenRC has no cgroup accounting.
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(list.len());
    for (unit, label, category) in list {
        if unit.starts_with("dockpanel-app-") {
            // Site app units are systemd-only; `app_process.rs` writes a
            // `.service` file that OpenRC never reads.
            continue;
        }
        let is_panel = PANEL_UNITS.contains(&unit.as_str());
        let strict = openrc_runscript(&unit);
        if strict.is_none() && !is_panel {
            continue;
        }
        // The resolved runscript, not the catalogue name, is the identity:
        // `cron` and `crond` are one runscript on Alpine, and a fuzzy PHP
        // lookup would let `php8.5-fpm` claim the installed `php-fpm84`.
        let svc = strict.unwrap_or_else(|| init::service_name(&unit));
        if !seen.insert(svc.clone()) {
            continue;
        }
        let exists = init::runscript(&svc).is_file();
        let active = exists && init::is_active(&svc);

        // Metrics only for a service that is actually running. A stale pidfile
        // from a stopped daemon would otherwise reattribute an unrelated PID's
        // memory and uptime to it.
        let pid = if active {
            read_pidfile(&svc).or_else(|| running_pid(&sys, &svc))
        } else {
            None
        };
        let (cpu_pct, memory_mb, uptime_secs, main_pid) = match pid {
            Some(pid) => {
                let proc = sys.process(sysinfo::Pid::from_u32(pid));
                (
                    proc.map(|p| p.cpu_usage()),
                    proc.map(|p| p.memory() as f64 / 1_048_576.0),
                    proc.map(|p| p.run_time()),
                    Some(pid),
                )
            }
            None => (None, None, None, None),
        };
        let enabled = init::is_enabled(&svc);

        out.push(ServiceEntry {
            unit,
            label,
            category,
            description: String::new(),
            load_state: if exists { "loaded".into() } else { "not-found".into() },
            active_state: if active { "active".into() } else { "inactive".into() },
            sub_state: if active { "running".into() } else { "dead".into() },
            enabled,
            main_pid,
            memory_mb,
            cpu_pct,
            uptime_secs,
            // supervise-daemon does not count respawns; null is the honest answer.
            restarts: None,
        });
    }
    out
}

/// Resolve a catalogue unit to the OpenRC runscript that is *exactly* it.
///
/// `init::service_name` is deliberately forgiving — it answers "which runscript
/// would serve this request" — and for a versioned PHP-FPM unit that means the
/// highest installed one, so `php8.5-fpm` and `php8.1-fpm` both resolve to the
/// single `php-fpm84` this box has. Correct for `restart php8.5-fpm` (some FPM
/// should come back), wrong for a per-service table (four versions would all
/// read "active"). This asks the stricter question: which runscript is this
/// unit, and only returns it when it exists.
fn openrc_runscript(unit: &str) -> Option<String> {
    let name = openrc_runscript_name(unit);
    init::runscript(&name).is_file().then_some(name)
}

/// The exact runscript name `openrc_runscript` looks for, split out so the
/// version mapping can be tested without a filesystem.
fn openrc_runscript_name(unit: &str) -> String {
    if init::is_php_fpm_service(unit) {
        if unit == "php-fpm" {
            "php-fpm".to_string()
        } else {
            // `php8.4-fpm` → Alpine's `php-fpm84`.
            let version = unit
                .trim_start_matches("php")
                .trim_end_matches("-fpm")
                .replace('.', "");
            format!("php-fpm{version}")
        }
    } else {
        init::service_name(unit)
    }
}

/// The PID OpenRC records for a service, if its runscript wrote a pidfile.
///
/// There is no single convention to read: DockPanel's own runscripts write
/// `/run/<svc>.pid`, a few daemons nest theirs under a directory, and Alpine's
/// `php-fpmXY` writes `/run/php-fpmXY/php-fpm.pid` — a fixed filename inside a
/// versioned directory. All three shapes are tried, and the contents must parse
/// as a PID: a socket path or an empty file is not one.
fn read_pidfile(svc: &str) -> Option<u32> {
    for path in [format!("/run/{svc}.pid"), format!("/run/{svc}")] {
        if let Some(pid) = parse_pid_file(&path) {
            return Some(pid);
        }
    }
    if let Ok(entries) = std::fs::read_dir(format!("/run/{svc}")) {
        let mut pids: Vec<u32> = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".pid"))
            .filter_map(|e| parse_pid_file(&e.path().to_string_lossy()))
            .collect();
        pids.sort_unstable();
        if let Some(pid) = pids.first() {
            return Some(*pid);
        }
    }
    None
}

/// A file's contents as a PID, rejecting 0 and 1 (never a service's own PID).
fn parse_pid_file(path: &str) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    let pid = text.trim().parse::<u32>().ok()?;
    (pid > 1).then_some(pid)
}

/// Fallback for a runscript that manages a daemon without a pidfile: the
/// process whose name is the service name, or the service name followed by a
/// `:`/space (`nginx: master process`). A bare prefix is not enough — it would
/// let `redis` claim `redis-sentinel`.
fn running_pid(sys: &System, svc: &str) -> Option<u32> {
    sys.processes().values().find_map(|p| {
        let name = p.name().to_string_lossy();
        let matched = name
            .strip_prefix(svc)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', ' ']));
        matched.then(|| p.pid().as_u32())
    })
}

/// Start, stop or restart one unit.
///
/// `action` is matched against a fixed set; `unit` is matched against
/// [`is_controllable`]'s recomputed catalogue. Both checks are here, in the
/// agent, because the agent is the only process with `systemctl` access — a
/// caller that reaches it directly with a hand-written payload must be refused
/// by the same wall the panel is held to.
pub async fn perform_action(unit: &str, action: &str) -> Result<(), String> {
    if !matches!(action, "start" | "stop" | "restart") {
        return Err(format!("unsupported action '{action}'"));
    }
    if !is_controllable(unit) {
        return Err(format!("'{unit}' is not a DockPanel-managed service"));
    }

    // Restarting the agent or the API from inside a request that those same
    // processes are serving would kill the response before it is written. Hand
    // those two to PID1 to fire a moment later instead of running them inline.
    if is_self_hosting(unit) {
        return schedule_detached(unit, action).await;
    }

    run_systemctl(unit, action).await
}

async fn run_systemctl(unit: &str, action: &str) -> Result<(), String> {
    let out = safe_command("systemctl")
        .args([action, unit])
        .output()
        .await
        .map_err(|e| format!("systemctl {action} {unit}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {action} {unit} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Run an action a couple of seconds from now, outside this process's cgroup.
///
/// On systemd that is a transient timer unit created by PID1, so it is not a
/// child of the agent and survives the restart it triggers. OpenRC has no
/// transient units, so the scheduler is detached into its own session instead —
/// OpenRC does not cgroup-kill, so that is enough for it to outlive the daemon
/// it is restarting.
async fn schedule_detached(unit: &str, action: &str) -> Result<(), String> {
    let script = format!("sleep 2; exec systemctl {action} {unit}");

    if init::init_system() == InitSystem::Systemd {
        let unit_name = format!(
            "dockpanel-svcaction-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
        let out = safe_command("systemd-run")
            .args([
                "--collect",
                "--on-active=2",
                &format!("--unit={unit_name}"),
                "/bin/sh",
                "-c",
                &script,
            ])
            .output()
            .await
            .map_err(|e| format!("systemd-run: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "could not schedule {action} for {unit}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    } else {
        let mut cmd = safe_command("sh");
        cmd.args(["-c", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd.process_group(0);
        cmd.spawn()
            .map(|_| ())
            .map_err(|e| format!("could not schedule {action} for {unit}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_property_blocks_keyed_by_id() {
        let text = "Id=nginx.service\nActiveState=active\nSubState=running\n\
                    \nId=dockpanel-api.service\nActiveState=active\nSubState=running\n";
        let parsed = parse_show(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["nginx"]["ActiveState"], "active");
        assert_eq!(parsed["dockpanel-api"]["SubState"], "running");
    }

    #[test]
    fn ignores_unkeyed_blocks() {
        let text = "ActiveState=active\n\nId=nginx.service\nActiveState=inactive\n";
        let parsed = parse_show(text);
        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains_key("nginx"));
    }

    #[test]
    fn cpu_delta_is_per_cpu_and_clamped() {
        // 1e9 ns of CPU over 1s on a 4-CPU box is 25% of one CPU.
        let pct = cpu_delta_pct(Some(2_000_000_000), Some(1_000_000_000), 1.0, 4.0).unwrap();
        assert!((pct - 25.0).abs() < 0.01);
        // A reset counter (restart between samples) reads as zero, not negative.
        assert_eq!(cpu_delta_pct(Some(10), Some(1_000), 1.0, 1.0), Some(0.0));
        // Missing readings are "unknown", not zero.
        assert_eq!(cpu_delta_pct(None, Some(1), 1.0, 1.0), None);
    }

    #[test]
    fn memory_rejects_unset_and_unlimited() {
        let mut p = HashMap::new();
        p.insert("MemoryCurrent".to_string(), "[not set]".to_string());
        assert_eq!(parse_memory_mb(&p), None);
        p.insert("MemoryCurrent".to_string(), u64::MAX.to_string());
        assert_eq!(parse_memory_mb(&p), None);
        p.insert("MemoryCurrent".to_string(), (10 * 1_048_576).to_string());
        assert_eq!(parse_memory_mb(&p), Some(10.0));
    }

    #[test]
    fn enabled_maps_systemd_states() {
        let mut p = HashMap::new();
        for (value, expected) in [
            ("enabled", Some(true)),
            ("static", Some(true)),
            ("disabled", Some(false)),
            ("masked", Some(false)),
            ("weird", None),
        ] {
            p.insert("UnitFileState".to_string(), value.to_string());
            assert_eq!(parse_enabled(&p), expected, "UnitFileState={value}");
        }
    }

    #[test]
    fn self_hosting_units_are_the_two_the_request_runs_on() {
        assert!(is_self_hosting("dockpanel-agent"));
        assert!(is_self_hosting("dockpanel-api"));
        assert!(!is_self_hosting("dockpanel-mailapi"));
        assert!(!is_self_hosting("nginx"));
    }

    #[test]
    fn catalogue_lists_the_panel_daemons() {
        let list = candidates();
        for unit in PANEL_UNITS {
            assert!(list.iter().any(|(u, _, _)| u == unit), "{unit} missing");
        }
    }

    #[test]
    fn php_units_map_to_their_own_runscript_not_the_highest_installed() {
        // The fuzzy `init::service_name` picks the highest installed version;
        // the strict mapper must keep each unit on its own runscript, or a
        // per-service table reports every version as active.
        assert_eq!(openrc_runscript_name("php8.4-fpm"), "php-fpm84");
        assert_eq!(openrc_runscript_name("php8.1-fpm"), "php-fpm81");
        assert_eq!(openrc_runscript_name("php-fpm"), "php-fpm");
        assert_eq!(openrc_runscript_name("nginx"), "nginx");
    }
}
