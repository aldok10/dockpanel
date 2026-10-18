//! Per-site SFTP accounts (GH #108).
//!
//! Each SFTP-enabled site gets its own Linux uid/gid (allocated by the panel,
//! `sites.sftp_uid`/`sftp_gid`), which becomes the REAL owner of
//! `/var/www/{domain}` — the actual per-tenant isolation. A separate jail tree
//! under `/var/dockpanel-sftp/{domain}` is the OpenSSH `ChrootDirectory`
//! (root-owned, as OpenSSH requires); its one `content/` subdirectory is
//! bind-mounted (a dedicated systemd `.mount` unit, not `/etc/fstab`) onto the
//! real, UNMOVED `/var/www/{domain}` — no nginx/PHP-FPM/WP-CLI/CMS-installer
//! path anywhere else in the codebase ever needs to change. Membership in the
//! shared `SFTP_GROUP` is what scopes sshd's one `Match` block to these users;
//! it is created once and never touched again after the first site enables.
//!
//! `useradd`/`groupadd`/`chown`/`usermod` all run via `safe_command_unsandboxed`
//! (the `systemd-run` escape, same as the `vmail` user in `routes/mail.rs`) —
//! `/etc/passwd`/`shadow`/`group` sit outside the agent's own `ReadWritePaths`.

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use sha_crypt::{PasswordHasher, ShaCrypt};

/// The shared secondary group every per-site SFTP user is a member of.
/// `Match Group` in the sshd drop-in scopes the chroot to exactly this group —
/// created once, by name (no fixed gid needed; useradd/sshd both accept names).
pub const SFTP_GROUP: &str = "sftp_sites";

/// The shared secondary group whose members get a jailed *interactive* shell in
/// their site's jail.
///
/// Deliberately a SECOND group rather than the same one: sshd applies only the
/// first value it obtains for a keyword, and `Match Group sftp_sites` (below)
/// carries `ForceCommand internal-sftp`. A user left in `SFTP_GROUP` would be
/// caught by that keyword and pinned to the SFTP subsystem for ever, never
/// reaching a shell. A shell user is therefore a member of this group and NOT of
/// `SFTP_GROUP`; SFTP still works for them, because `internal-sftp` also runs as
/// the `Subsystem sftp` handler when nothing forces it.
pub const SHELL_GROUP: &str = "ssh_shell_sites";

/// The sshd drop-in that scopes the chroot to the two groups above.
const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/99-dockpanel-sftp.conf";

/// Utilities made available inside a jailed shell by symlinking them at
/// BusyBox. BusyBox is one small binary that answers to every one of these
/// names, so a whole userland needs one copy + one library, not one per tool.
/// Anything not here (e.g. `git`, `php`) the tenant does not get, which is the
/// point of a jail rather than a full desktop.
const BUSYBOX_APPLETS: &[&str] = &[
    "sh", "ash", "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "ln", "chmod",
    "touch", "echo", "pwd", "env", "grep", "egrep", "fgrep", "sed", "awk", "find",
    "xargs", "sort", "uniq", "head", "tail", "wc", "cut", "tr", "tee", "less",
    "vi", "tar", "gzip", "gunzip", "zip", "unzip", "ps", "top", "kill", "sleep",
    "date", "id", "whoami", "uname", "hostname", "stat", "df", "du", "which",
    "wget", "curl", "diff", "make", "nohup", "true", "false",
];

/// Directories the shell runtime owns inside the jail. Removed together when
/// shell access is turned off. `content/` is NOT among them: it is the tenant's
/// real files (a bind mount) and outlives the shell.
const RUNTIME_DIRS: &[&str] = &["bin", "dev", "etc", "lib", "lib64", "usr", "tmp"];

/// Where the panel records which domain owns an allocated uid — read by
/// [`crate::services::ownership::sftp_user`] before any teardown touches a
/// real Linux account. Kept outside both the chroot jail and `/var/www` so
/// the SFTP user's own session can never reach or edit it.
pub const OWNER_MARKER_DIR: &str = "/etc/dockpanel/sftp-owners";

/// The first uid `sftp_id_seq` hands out. Site uids are allocated from here
/// upward so they can never collide with a system account — which is exactly
/// what makes the uid a poor thing to put in a login name.
const SFTP_UID_BASE: i32 = 30000;

/// The login name behind `uid`: `usr` plus the account's own 1-based number,
/// zero-padded to five digits — `usr00001`, `usr00002`, …
///
/// The number is DERIVED from the uid rather than stored, so a name can never
/// drift from the identity it names: [`SFTP_UID_BASE`] is the sequence's start,
/// so uid 30000 is account 1. Restated verbatim in the backend
/// (`routes::sites::site_account_name`) — the two crates share no library, so
/// `tests/sftp-accounts-pin-e2e.sh` pins that both spell this exact expression.
pub fn sftp_username(uid: i32) -> String {
    format!("usr{:05}", uid - SFTP_UID_BASE + 1)
}

pub fn sftp_groupname(gid: i32) -> String {
    format!("sftpg{gid}")
}

/// The login currently holding `uid` in `/etc/passwd`, if any.
///
/// Identity is resolved by UID, never by name: the name is a label this panel
/// chooses, and a label from an older scheme (`sftp<uid>`) still names a real
/// account until it is cleaned up. Resolving by uid is what lets a teardown or
/// a provision find that account instead of failing to recognise it.
async fn passwd_entry_for_uid(uid: i32) -> Result<Option<String>, String> {
    let passwd = tokio::fs::read_to_string("/etc/passwd")
        .await
        .map_err(|e| format!("cannot read /etc/passwd: {e}"))?;
    Ok(passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        let _pw = f.next()?;
        let id: i32 = f.next()?.parse().ok()?;
        (id == uid).then(|| name.to_string())
    }))
}

/// The group currently holding `gid` in `/etc/group`, if any. See
/// [`passwd_entry_for_uid`] for why this resolves by id.
async fn group_entry_for_gid(gid: i32) -> Result<Option<String>, String> {
    let group = tokio::fs::read_to_string("/etc/group")
        .await
        .map_err(|e| format!("cannot read /etc/group: {e}"))?;
    Ok(group.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        let _pw = f.next()?;
        let id: i32 = f.next()?.parse().ok()?;
        (id == gid).then(|| name.to_string())
    }))
}

fn jail_root(domain: &str) -> String {
    format!("/var/dockpanel-sftp/{domain}")
}

fn jail_content_dir(domain: &str) -> String {
    format!("{}/content", jail_root(domain))
}

pub fn owner_marker_path(uid: i32) -> String {
    format!("{OWNER_MARKER_DIR}/{uid}.owner")
}

/// Compute the systemd unit name for `content_dir`'s bind mount via
/// `systemd-escape`, rather than hand-rolling systemd's path-escaping rules
/// (`-` -> `\x2d` etc.) — a `.mount` unit's filename MUST exactly match the
/// escaped `Where=` path or systemd will not track the mount against it.
async fn mount_unit_name(content_dir: &str) -> Result<String, String> {
    let output = safe_command("systemd-escape")
        .args(["--path", "--suffix=mount", content_dir])
        .output()
        .await
        .map_err(|e| format!("systemd-escape failed to run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemd-escape failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Provision the SFTP account for `domain`: shared group (once), per-site
/// user+group, the jail tree, the bind-mount unit, and re-owns the site's real
/// content directory. Idempotent on the shared-group and per-site id steps: a
/// site whose uid is already held by its own account reuses it, and a uid held
/// by a retired (`sftp<uid>`) account is reclaimed — see the claim step below.
/// NOT idempotent on the mount-unit step (`enable_sftp` on the backend already
/// no-ops when `sftp_enabled` is already true, so this only ever runs once per
/// site).
pub async fn provision(domain: &str, uid: i32, gid: i32) -> Result<(), String> {
    let username = sftp_username(uid);
    let groupname = sftp_groupname(gid);
    let site_dir = format!("/var/www/{domain}");
    if !std::path::Path::new(&site_dir).exists() {
        return Err(format!("{site_dir} does not exist — cannot enable SFTP"));
    }

    // 1. Shared secondary groups — idempotent, ignore "already exists". Both are
    // created up front so the sshd drop-in, which references both in its Match
    // blocks, never names a group sshd cannot resolve (sshd would refuse to
    // start with an invalid Match group).
    let _ = safe_command_unsandboxed("groupadd", &[])
        .args([SFTP_GROUP])
        .output()
        .await;
    let _ = safe_command_unsandboxed("groupadd", &[])
        .args([SHELL_GROUP])
        .output()
        .await;

    // 2. Claim this uid/gid for the CURRENT name, then create what is missing.
    //
    // Both halves exist because of real states the caller can hand us:
    //
    // - An account created under the retired name (`sftp<uid>`) still holds
    //   exactly this uid until its site is re-enabled. `useradd -u` would fail
    //   with "UID already in use" and that site could never come back, so the
    //   leftover goes first — looked up BY UID, never by a wildcard over
    //   `sftp*`, which would take out a different site's live account. Its
    //   processes go first for the same reason `deprovision()` kills them:
    //   userdel refuses a uid that is still running (a PHP-FPM pool pointed at
    //   this identity will have workers under it).
    // - A previous teardown whose userdel/groupdel failed left OUR OWN
    //   identity behind. That is not an error to report, it is the account to
    //   reuse: a disable/enable cycle must not fail because cleanup was
    //   incomplete.
    if let Some(holder) = passwd_entry_for_uid(uid).await? {
        if holder != username {
            tracing::info!(
                "removing retired account {holder} that holds uid {uid} before provisioning {username}"
            );
            let _ = safe_command_unsandboxed("pkill", &[])
                .args(["-9", "-u", &uid.to_string()])
                .output()
                .await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            match safe_command_unsandboxed("userdel", &[]).args([&holder]).output().await {
                Ok(o) if !o.status.success() => tracing::warn!(
                    "userdel {holder} failed (retired account may still exist): {}",
                    String::from_utf8_lossy(&o.stderr)
                ),
                Err(e) => tracing::warn!("userdel {holder} failed to run: {e}"),
                Ok(_) => {}
            }
        }
    }
    if let Some(holder) = group_entry_for_gid(gid).await? {
        if holder != groupname {
            tracing::info!(
                "removing stale group {holder} that holds gid {gid} before provisioning {groupname}"
            );
            let _ = safe_command_unsandboxed("groupdel", &[]).args([&holder]).output().await;
        }
    }

    // 2b. Per-site primary group, then the user itself — created only when the
    // id is genuinely free, so a repeat enable reuses an identity that
    // survived an incomplete teardown instead of erroring on "already exists".
    // A failure here is a real error, not swallowed.
    if group_entry_for_gid(gid).await? != Some(groupname.clone()) {
        let out = safe_command_unsandboxed("groupadd", &[])
            .args(["-g", &gid.to_string(), &groupname])
            .output()
            .await
            .map_err(|e| format!("groupadd failed to run: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "groupadd {groupname} (gid {gid}) failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }

    let jail = jail_root(domain);
    if passwd_entry_for_uid(uid).await? != Some(username.clone()) {
        let out = safe_command_unsandboxed("useradd", &[])
            .args([
                "-u",
                &uid.to_string(),
                "-g",
                &groupname,
                "-G",
                SFTP_GROUP,
                "-d",
                &jail,
                "-s",
                "/usr/sbin/nologin",
                &username,
            ])
            .output()
            .await
            .map_err(|e| format!("useradd failed to run: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            // Roll back the group we just created — a half-provisioned site
            // (group present, no user) is worse than none, since a retry's
            // groupadd would then fail on "already exists" and mask the real
            // problem.
            let _ = safe_command_unsandboxed("groupdel", &[]).args([&groupname]).output().await;
            return Err(format!("useradd {username} (uid {uid}) failed: {stderr}"));
        }
    }

    // 3. Jail tree: root-owned boundary (OpenSSH requires this, not
    // configurable), empty content/ mountpoint. `/var/dockpanel-sftp` is a
    // brand-new top-level directory this feature creates on first use, so a
    // plain `std::fs::create_dir_all` here hits the same EROFS the vmail
    // directory does in `routes/mail.rs`: ProtectSystem=strict namespaces the
    // agent's writable set at unit START, and a path that did not exist then
    // is not in it regardless of what ReadWritePaths later gets updated to
    // say — only the systemd-run escape can create it live. (Live-verified on
    // a fresh VPS: the plain std::fs call failed with exactly this error
    // before this fix.)
    let content_dir = jail_content_dir(domain);
    let out = safe_command_unsandboxed("mkdir", &[])
        .args(["-p", &content_dir])
        .output()
        .await
        .map_err(|e| format!("mkdir failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Failed to create jail tree {content_dir}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let _ = safe_command_unsandboxed("chown", &[]).args(["root:root", &jail]).output().await;
    let _ = safe_command_unsandboxed("chmod", &[]).args(["0755", &jail]).output().await;

    // 4. Bind-mount content/ onto the REAL, unmoved site directory. Described
    // by `ensure_content_mount`, which knows the two init-system shapes.
    ensure_content_mount(domain, &site_dir, &content_dir).await?;

    // 5. The actual isolation: re-own the real site directory. PHP-FPM's pool
    // is re-pointed at this same identity by the caller (`put_site`, driven by
    // `pool_user`/`pool_group` on the next vhost rebuild — the backend sends
    // those the moment `sftp_enabled` flips true).
    let out = safe_command_unsandboxed("chown", &[])
        .args(["-R", &format!("{username}:{groupname}"), &site_dir])
        .output()
        .await
        .map_err(|e| format!("chown failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chown -R {username}:{groupname} {site_dir} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // 6. Owner marker — written last, only once every step above has actually
    // succeeded, so a marker on disk is never a promise this function did not
    // keep.
    if let Err(e) = std::fs::create_dir_all(OWNER_MARKER_DIR) {
        return Err(format!("Failed to create {OWNER_MARKER_DIR}: {e}"));
    }
    if let Err(e) = std::fs::write(owner_marker_path(uid), format!("Domain={domain}\n")) {
        return Err(format!("Failed to write owner marker for uid {uid}: {e}"));
    }

    ensure_sshd_dropin().await?;

    tracing::info!("SFTP provisioned for {domain}: user={username} uid={uid} gid={gid}");
    Ok(())
}

/// Tear down everything [`provision`] created. `last_sftp_site` tells us
/// whether to also remove the shared sshd drop-in — the caller (the backend)
/// derives this from the `sites` table, not from re-scanning this box, since
/// the DB is the source of truth for how many sites still have SFTP enabled.
pub async fn deprovision(domain: &str, uid: i32, gid: i32, last_sftp_site: bool) -> Result<(), String> {
    if !crate::services::ownership::sftp_user(uid, domain).may_delete() {
        return Err(format!(
            "uid {uid} does not carry an owner marker naming {domain} — refusing to tear down \
             an account this agent cannot prove belongs to this site"
        ));
    }

    let username = sftp_username(uid);
    let groupname = sftp_groupname(gid);
    let site_dir = format!("/var/www/{domain}");

    // 1. Detach the bind mount FIRST — a chown while the site dir is still
    // mounted into the jail is safe either way (the mount is transparent to
    // path-based tools), but tearing down in this order means a failure here
    // leaves the account still enabled rather than half-disabled.
    let content_dir = jail_content_dir(domain);
    remove_content_mount(&content_dir).await;

    // 2. Revert the real content back to the shared identity every other site
    // uses. The caller updates `sftp_enabled = false` and rebuilds the vhost
    // (reverting the PHP-FPM pool) in the SAME transition — order between
    // this and that rebuild does not matter, since both converge on
    // `www-data` and neither reads the other's intermediate state.
    if std::path::Path::new(&site_dir).exists() {
        let _ = safe_command_unsandboxed("chown", &[])
            .args(["-R", "www-data:www-data", &site_dir])
            .output()
            .await;
    }

    // 3. Remove the jail scaffolding — this is agent-created infrastructure,
    // never site data (the real content lived at `site_dir` the whole time).
    // Same unsandboxed-escape requirement as creation (see provision()).
    let jail = jail_root(domain);
    let out = safe_command_unsandboxed("rm", &[]).args(["-rf", &jail]).output().await;
    match out {
        Ok(o) if !o.status.success() => tracing::warn!(
            "Failed to remove jail tree {jail}: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("Failed to remove jail tree {jail}: {e}"),
        Ok(_) => {}
    }

    // 3.5. Stop this domain's PHP-FPM pool entirely — removed, not merely
    // reverted, and RELOADED before any process is killed.
    //
    // Live-verified this is the actual fix step 4's `pkill` alone is not:
    // killing the pool's workers does not stop the php-fpm MASTER (running
    // as root, unaffected by `pkill -u <uid>`) from immediately respawning
    // new ones under the same uid per `pm.start_servers`/`pm.min_spare_
    // servers` in the pool config that is STILL ON DISK — a pkill-then-
    // userdel sequence lost this race every time, new worker PIDs appearing
    // between the two calls. Only removing the pool file itself and
    // reloading stops the master from wanting workers under this identity
    // at all. Every caller converges on this domain having NO SFTP-owned
    // pool afterward regardless of what it separately does next: `disable`'s
    // vhost rebuild recreates a fresh www-data pool moments later; site
    // deletion's own later pool-file removal (`nginx.rs::delete_site`) finds
    // nothing left and is a no-op, exactly like every other `if path.exists()`
    // step there already tolerates.
    for version in ["8.1", "8.2", "8.3", "8.4", "8.5"] {
        let pool_path = format!("/etc/php/{version}/fpm/pool.d/{}.conf", domain.replace('.', "_"));
        if std::path::Path::new(&pool_path).exists() {
            if let Err(e) = std::fs::remove_file(&pool_path) {
                tracing::warn!("Failed to remove PHP-FPM pool {pool_path} before SFTP teardown: {e}");
            }
            if let Err(e) = crate::services::nginx::reload_php_fpm(version).await {
                tracing::warn!("Failed to reload php{version}-fpm before SFTP teardown: {e}");
            }
        }
    }

    // 4. Kill anything still running as this uid, THEN remove the account.
    //
    // Live-verified twice, via two DIFFERENT callers: `userdel` refuses to
    // remove a uid with a running process, and the PHP-FPM pool's own
    // workers are still alive under it at this point unless the caller
    // happened to revert+reload the pool first. The `disable` path does that
    // (as a necessary step in its own right — the pool must go back to
    // www-data regardless), which was enough to unblock userdel there. Site
    // DELETION's teardown only ever *removes the pool config file*
    // (`nginx.rs::delete_site`, no reload) — deleting the file does not stop
    // an already-running worker, so the exact same "account still exists
    // after teardown reports success" failure reproduced through that path
    // with no shared code to have fixed it in one place. Rather than adding
    // a third caller-side ordering requirement (or trusting a fourth one
    // later gets it right), this function no longer depends on the caller
    // having cleared the uid's processes at all: `pkill -9 -u` first, THEN
    // userdel, makes deprovision() correct on its own regardless of what
    // else is or isn't still running under this identity.
    let _ = safe_command_unsandboxed("pkill", &[]).args(["-9", "-u", &uid.to_string()]).output().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Best-effort (matching every other cleanup step above), but LOGGED — a
    // swallowed failure here previously meant "disabled"/"deleted" could
    // report success while the OS account and its group were still present.
    match safe_command_unsandboxed("userdel", &[]).args([&username]).output().await {
        Ok(o) if !o.status.success() => tracing::warn!(
            "userdel {username} failed (account may still exist): {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("userdel {username} failed to run: {e}"),
        Ok(_) => {}
    }
    match safe_command_unsandboxed("groupdel", &[]).args([&groupname]).output().await {
        Ok(o) if !o.status.success() => tracing::warn!(
            "groupdel {groupname} failed (group may still exist): {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("groupdel {groupname} failed to run: {e}"),
        Ok(_) => {}
    }
    let _ = std::fs::remove_file(owner_marker_path(uid));

    if last_sftp_site {
        let _ = std::fs::remove_file(SSHD_DROPIN);
        let _ = reload_sshd_validated().await;
        // The shell group only ever holds members of these accounts, so the
        // last teardown is also when it should go. Best-effort: a leftover
        // empty group is harmless and the next provision re-creates it.
        let _ = safe_command_unsandboxed("groupdel", &[]).args([SHELL_GROUP]).output().await;
    }

    tracing::info!("SFTP deprovisioned for {domain}: user={username}");
    Ok(())
}

/// Remove site accounts this panel created under the retired `sftp<uid>` name.
///
/// The login scheme is now `usr#####` (see [`sftp_username`]), so an account
/// still called `sftp<uid>` is one the panel will never reference again:
/// migration `20261018040000` marks every site carrying one as needing
/// re-enable, and the next Enable re-creates the account under the current
/// name, reclaiming the same uid (see [`provision`]).
///
/// Deliberately narrow rather than a sweep for "any name starting with sftp":
/// only `sftp` + digits, only for a uid inside the range this panel allocates
/// from. An account matching that is ours by construction — no admin hands
/// themselves `sftp` + digits inside 30000+ — while a prefix sweep would also
/// match whatever an operator named `sftp-backup` or `sftp_old`. Runs at every
/// startup and is a no-op once they are gone.
pub async fn purge_retired_accounts() {
    let passwd = match tokio::fs::read_to_string("/etc/passwd").await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("retired site-account cleanup skipped, cannot read /etc/passwd: {e}");
            return;
        }
    };
    for line in passwd.lines() {
        let mut f = line.split(':');
        let (Some(name), Some(_pw), Some(id)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let Ok(uid) = id.parse::<i32>() else { continue };
        if uid < SFTP_UID_BASE || !is_retired_name(name) {
            continue;
        }

        tracing::info!("removing retired site account {name} (uid {uid})");
        // Same order `deprovision()` uses, for the same reason: userdel refuses
        // a uid that still has processes, and a PHP-FPM pool pointed at this
        // identity will have workers under it.
        let _ = safe_command_unsandboxed("pkill", &[])
            .args(["-9", "-u", id])
            .output()
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        match safe_command_unsandboxed("userdel", &[]).args([name]).output().await {
            Ok(o) if !o.status.success() => tracing::warn!(
                "userdel {name} failed (retired account may still exist): {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => tracing::warn!("userdel {name} failed to run: {e}"),
            Ok(_) => {}
        }
    }
}

/// `sftp` followed by nothing but digits — the shape of the retired
/// site-account name, and of nothing this panel creates today.
fn is_retired_name(name: &str) -> bool {
    name.strip_prefix("sftp")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Set (or reset) `domain`'s SFTP password. Hashes in-process (glibc
/// SHA-512-crypt via `sha-crypt`) rather than piping plaintext through
/// `chpasswd`'s stdin — the shared `UnsandboxedCommand` primitive every
/// privileged call here goes through has no stdin support today, and a hash
/// (unlike plaintext) is not sensitive to pass as a `usermod -p` argument;
/// that is the entire reason hashing exists.
pub async fn set_password(uid: i32, plaintext: &str) -> Result<(), String> {
    apply_password(&sftp_username(uid), plaintext).await
}

/// Make sure `uid`'s login is not locked, so public-key auth can succeed.
///
/// `provision` leaves the account locked (`useradd` without `-p`), which is
/// correct for a password-less account — but sshd refuses a LOCKED account for
/// every auth method, publickey included, so a site that has been given a key
/// but no password could not use that key at all until this ran. Installing a
/// key therefore unlocks first. Idempotent: [`ensure_unlocked`] only sets a
/// password when the shadow field is actually locked, so an existing password
/// (a reset the owner already did by hand) is never overwritten by this path.
pub async fn unlock(uid: i32) -> Result<(), String> {
    ensure_unlocked(&sftp_username(uid)).await
}

/// Hash `plaintext` and store it on `username`.
///
/// Shared by the SFTP password route and the jailed-shell unlock below, which
/// has no caller-supplied password to store and generates one.
async fn apply_password(username: &str, plaintext: &str) -> Result<(), String> {
    // NOT `ShaCrypt::hash_password()` — its auto-generated salt is
    // `password_hash`'s generic RECOMMENDED_SALT_LEN (16 RAW BYTES), which
    // base64-encodes to 22 characters. SHA-crypt's own spec caps the salt at
    // 16 base64 CHARACTERS; glibc's crypt() (what PAM actually calls to
    // verify a login) truncates an over-long salt to that limit when
    // recomputing the hash, so it silently computes a DIFFERENT digest than
    // the one stored — authentication then fails for every correct password,
    // forever. Live-verified on a fresh VPS: a hash made with the default
    // 16-byte/22-char salt round-tripped through Rust's own crypt.crypt()
    // check as WRONG. 12 raw bytes base64-encodes to exactly 16 characters
    // (12*8/6 = 16, no truncation needed by any spec-compliant verifier).
    let salt: [u8; 12] = {
        use rand::Rng;
        rand::rng().random()
    };
    let hash = ShaCrypt::default()
        .hash_password_with_salt(plaintext.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {e}"))?;
    let out = safe_command_unsandboxed("usermod", &[])
        .args(["-p", hash.as_str(), &username])
        .output()
        .await
        .map_err(|e| format!("usermod failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "usermod -p failed for {username}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// The drop-in's exact contents. Two `Match` blocks, shell first: sshd takes the
/// first value it obtains for each keyword, so for the (never-produced, but
/// cheap to defend) case of a user in both groups the shell block wins over the
/// SFTP block's `ForceCommand internal-sftp`.
///
/// Written and reloaded — behind `sshd -t`, never the bare `restart_sshd` /
/// no-validation path `services::security`'s SSH-hardening functions use, since
/// a malformed Match block would otherwise lock out SSH on reload with no
/// warning — by [`write_sshd_dropin`].
fn sshd_dropin_body() -> String {
    format!(
        "# Managed by DockPanel — per-site SFTP jails and jailed shells (GH #108).\n\
         # Do not edit by hand; regenerated when a site's account changes.\n\
         Match Group {SHELL_GROUP}\n\
         \tChrootDirectory %h\n\
         \tAllowTcpForwarding no\n\
         \tX11Forwarding no\n\
         Match Group {SFTP_GROUP}\n\
         \tChrootDirectory %h\n\
         \tForceCommand internal-sftp\n\
         \tAllowTcpForwarding no\n\
         \tX11Forwarding no\n"
    )
}

/// Write the drop-in and reload sshd behind `sshd -t`. On a failed validation
/// the file is removed again so the box is never left with a config sshd would
/// refuse on the next restart.
async fn write_sshd_dropin() -> Result<(), String> {
    if let Err(e) = std::fs::write(SSHD_DROPIN, sshd_dropin_body()) {
        return Err(format!("Failed to write {SSHD_DROPIN}: {e}"));
    }
    if let Err(e) = reload_sshd_validated().await {
        let _ = std::fs::remove_file(SSHD_DROPIN);
        return Err(e);
    }
    Ok(())
}

/// Write the drop-in if it is missing or predates jailed shells.
async fn ensure_sshd_dropin() -> Result<(), String> {
    let refresh = match std::fs::read_to_string(SSHD_DROPIN) {
        Ok(existing) => !existing.contains(SHELL_GROUP),
        Err(_) => true,
    };
    if refresh {
        // The Match block names the shell group, so it must exist before sshd is
        // asked to validate a config that references it.
        let _ = safe_command_unsandboxed("groupadd", &[])
            .args([SHELL_GROUP])
            .output()
            .await;
        write_sshd_dropin().await?;
    }
    Ok(())
}

/// `sshd -t` then `systemctl reload sshd` — reload, not restart, so an
/// unrelated config change never drops a live SSH session. On a failed
/// validation the caller is responsible for removing whatever it just wrote;
/// this function only ever validates the config CURRENTLY on disk.
async fn reload_sshd_validated() -> Result<(), String> {
    let test = safe_command("sshd").args(["-t"]).output().await
        .map_err(|e| format!("sshd -t failed to run: {e}"))?;
    if !test.status.success() {
        return Err(format!(
            "sshd config invalid after SFTP drop-in change: {}",
            String::from_utf8_lossy(&test.stderr)
        ));
    }
    let out = safe_command("systemctl").args(["reload", "sshd"]).output().await
        .map_err(|e| format!("systemctl reload sshd failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl reload sshd failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

// ── Jailed interactive shells ───────────────────────────────────────────────
//
// A jailed shell is the SFTP account with a userland inside the same jail and a
// real login shell instead of `ForceCommand internal-sftp`. Enable/disable only
// swaps the group membership and writes/removes the runtime below; the account,
// the uid/gid and the bind-mounted `content/` are untouched, so a tenant keeps
// their files whether or not the shell is on.

/// Run `cmd` OUTSIDE the agent's sandbox. Every shell-runtime write targets the
/// jail, which lives outside the agent's `ReadWritePaths` on a systemd box, so
/// nothing below can use the sandboxed [`safe_command`].
async fn run_un(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = safe_command_unsandboxed(cmd, &[])
        .args(args.iter().copied())
        .output()
        .await
        .map_err(|e| format!("{cmd} failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

const FSTAB: &str = "/etc/fstab";

/// Ensure `content_dir` is a bind mount of the real, unmoved `site_dir`.
///
/// systemd gets the generated `.mount` unit this feature shipped with. OpenRC
/// has no `.mount` equivalent — and the agent's `systemctl` shim explicitly has
/// no `.mount` support — so the systemd path would fail here with "service not
/// found". There the mount is made directly and recorded in `/etc/fstab`, which
/// OpenRC's `localmount` service replays at boot; without that line the tenant's
/// files would silently vanish from the jail on the next reboot while the mount
/// still looked healthy in the running system.
async fn ensure_content_mount(
    domain: &str,
    site_dir: &str,
    content_dir: &str,
) -> Result<(), String> {
    if crate::services::init::has_systemd() {
        let unit_name = mount_unit_name(content_dir).await?;
        let unit = format!(
            "[Unit]\n\
             Description=DockPanel SFTP jail content mount: {domain}\n\
             \n\
             [Mount]\n\
             What={site_dir}\n\
             Where={content_dir}\n\
             Type=none\n\
             Options=bind\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
        let unit_path = format!("/etc/systemd/system/{unit_name}");
        std::fs::write(&unit_path, &unit)
            .map_err(|e| format!("Failed to write mount unit {unit_path}: {e}"))?;
        let _ = safe_command("systemctl").args(["daemon-reload"]).output().await;
        let out = safe_command("systemctl")
            .args(["enable", "--now", &unit_name])
            .output()
            .await
            .map_err(|e| format!("Failed to start {unit_name}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "Failed to start {unit_name}: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(());
    }

    run_un("mkdir", &["-p", content_dir]).await?;
    run_un("mount", &["--bind", site_dir, content_dir]).await?;
    write_fstab_bind(site_dir, content_dir).await?;
    Ok(())
}

/// Undo [`ensure_content_mount`]. Best-effort: a leftover bind mount keeps the
/// tenant's files reachable but is not a reason to leave the account half-gone.
async fn remove_content_mount(content_dir: &str) {
    if crate::services::init::has_systemd() {
        if let Ok(unit_name) = mount_unit_name(content_dir).await {
            let unit_path = format!("/etc/systemd/system/{unit_name}");
            if std::path::Path::new(&unit_path).exists() {
                let _ = safe_command("systemctl").args(["stop", &unit_name]).output().await;
                let _ = safe_command("systemctl")
                    .args(["disable", &unit_name])
                    .output()
                    .await;
                let _ = std::fs::remove_file(&unit_path);
                let _ = safe_command("systemctl").args(["daemon-reload"]).output().await;
            }
        }
        return;
    }
    let _ = safe_command_unsandboxed("umount", &[])
        .args([content_dir])
        .output()
        .await;
    remove_fstab_bind(content_dir).await;
}

/// Append `src dst none bind,nofail 0 0` to `/etc/fstab` unless a line already
/// mounts `dst`. `/etc` is writable here because the OpenRC branch is only
/// reached on a box that is not sandboxed.
/// Replace the whole of `/etc/fstab`, through the unsandboxed escape.
///
/// A plain `std::fs::write` to `/etc` would fail under the agent's
/// `ProtectSystem=strict` namespace — the exact ReadWritePaths omission
/// `tests/agent-sandbox-paths-pin-e2e.sh` exists to catch — so the new contents
/// are staged under the agent's own writable tree and copied into place by the
/// escape, matching every other write this module makes outside the namespace.
async fn write_fstab(contents: &str) -> Result<(), String> {
    let staging = format!("/var/lib/dockpanel/.fstab.{}", uuid::Uuid::new_v4());
    std::fs::write(&staging, contents).map_err(|e| format!("could not stage {FSTAB}: {e}"))?;
    let result = run_un("cp", &["-f", &staging, FSTAB]).await;
    let _ = std::fs::remove_file(&staging);
    result
}

/// Append `src dst none bind,nofail 0 0` to `/etc/fstab` unless a line already
/// mounts `dst`.
async fn write_fstab_bind(src: &str, dst: &str) -> Result<(), String> {
    let current = tokio::fs::read_to_string(FSTAB).await.unwrap_or_default();
    if fstab_has_mount(&current, dst) {
        return Ok(());
    }
    let mut next = current;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(&format!("{src} {dst} none bind,nofail 0 0\n"));
    write_fstab(&next).await
}

async fn remove_fstab_bind(dst: &str) {
    let Ok(current) = tokio::fs::read_to_string(FSTAB).await else {
        return;
    };
    let kept: String = current
        .lines()
        .filter(|l| !line_mounts(l, dst))
        .map(|l| format!("{l}\n"))
        .collect();
    let _ = write_fstab(&kept).await;
}

fn fstab_has_mount(content: &str, dst: &str) -> bool {
    content.lines().any(|l| line_mounts(l, dst))
}

/// True when an fstab line's second field (the mount point) is `dst`.
fn line_mounts(line: &str, dst: &str) -> bool {
    let mut fields = line.split_whitespace();
    let _src = fields.next();
    fields.next() == Some(dst)
}

/// The login shell handed to a jailed account — the path INSIDE the jail.
/// `/bin/bash` where the host ships it (its libraries are copied in by
/// [`copy_into_jail`]), otherwise BusyBox's `/bin/sh`.
fn jail_shell() -> &'static str {
    if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    }
}

/// Copy a host binary (resolving symlinks) into the jail at the same path, with
/// every shared library `ldd` reports. A static binary yields no libraries and
/// is copied whole.
async fn copy_into_jail(host_path: &str, jail: &str) -> Result<(), String> {
    let real = tokio::fs::canonicalize(host_path)
        .await
        .map_err(|e| format!("cannot resolve {host_path}: {e}"))?
        .to_string_lossy()
        .into_owned();
    let dest = format!("{jail}{host_path}");
    if let Some((dir, _)) = dest.rsplit_once('/') {
        run_un("mkdir", &["-p", dir]).await?;
    }
    run_un("cp", &["-f", &real, &dest]).await?;
    let _ = run_un("chmod", &["755", &dest]).await;
    for lib in dynamic_deps(&real).await {
        let lib_dest = format!("{jail}{lib}");
        if let Some((dir, _)) = lib_dest.rsplit_once('/') {
            run_un("mkdir", &["-p", dir]).await?;
        }
        let _ = run_un("cp", &["-f", &lib, &lib_dest]).await;
    }
    Ok(())
}

/// The shared libraries `binary` loads, parsed from `ldd`. A binary whose `ldd`
/// cannot run (e.g. already static) yields an empty list — the copy then either
/// needs nothing or fails loudly at exec, never a silent half-copy.
async fn dynamic_deps(binary: &str) -> Vec<String> {
    let Ok(out) = safe_command("ldd").arg(binary).output().await else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            // "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x…)" — or, for the
            // loader, a bare "/lib/ld-musl-x86_64.so.1 (0x…)".
            let path = match line.split_once("=> ") {
                Some((_, rest)) => rest.split_whitespace().next(),
                None => line.split_whitespace().next(),
            }?;
            (path.starts_with('/')
                && !path.contains("linux-vdso")
                && std::path::Path::new(path).is_file())
            .then(|| path.to_string())
        })
        .collect()
}

/// Write `body` to `{jail}/{rel}` through a staged file: the jail is outside the
/// agent's writable namespace on a systemd box, so the write goes through
/// `install`, which the unsandboxed escape can reach.
async fn write_jail_file(jail: &str, rel: &str, body: &str) -> Result<(), String> {
    let staging = format!("/var/lib/dockpanel/.jail.{}", uuid::Uuid::new_v4());
    std::fs::write(&staging, body).map_err(|e| format!("could not stage {rel}: {e}"))?;
    let result = run_un(
        "install",
        &["-D", "-m", "644", &staging, &format!("{jail}/{rel}")],
    )
    .await;
    let _ = std::fs::remove_file(&staging);
    result
}

/// Lay down the whole userland a jailed login needs: a shell, its libraries, the
/// BusyBox applets, the device nodes, and a minimal `/etc`.
async fn build_shell_runtime(
    jail: &str,
    username: &str,
    uid: i32,
    gid: i32,
) -> Result<(), String> {
    for dir in RUNTIME_DIRS {
        run_un("mkdir", &["-p", &format!("{jail}/{dir}")]).await?;
    }

    let shell = jail_shell();
    copy_into_jail(shell, jail).await?;
    if std::path::Path::new("/bin/busybox").exists() {
        copy_into_jail("/bin/busybox", jail).await?;
        for applet in BUSYBOX_APPLETS {
            let _ = run_un("ln", &["-sf", "busybox", &format!("{jail}/bin/{applet}")]).await;
        }
    }
    if shell != "/bin/sh" {
        let name = shell.rsplit('/').next().unwrap_or("sh");
        let _ = run_un("ln", &["-sf", name, &format!("{jail}/bin/sh")]).await;
    }

    // Device nodes. `/dev/null` is load-bearing for anything that redirects,
    // `/dev/tty` for interactive programs, `/dev/urandom` for key material.
    for (node, major, minor) in [
        ("null", "1", "3"),
        ("zero", "1", "5"),
        ("random", "1", "8"),
        ("urandom", "1", "9"),
        ("tty", "5", "0"),
    ] {
        let dev = format!("{jail}/dev/{node}");
        let _ = run_un("mknod", &[&dev, "c", major, minor]).await;
        let _ = run_un("chmod", &["666", &dev]).await;
    }
    run_un("chmod", &["1777", &format!("{jail}/tmp")]).await?;

    // A minimal /etc: `whoami`/`ls -l` need the passwd/group entries, and
    // /etc/profile drops the tenant straight into their files at /content.
    write_jail_file(
        jail,
        "etc/passwd",
        &format!("root:x:0:0:root:/root:{shell}\n{username}:x:{uid}:{gid}:{username}:/:/bin/sh\n"),
    )
    .await?;
    write_jail_file(jail, "etc/group", &format!("root:x:0:\n{username}:x:{gid}:\n")).await?;
    write_jail_file(jail, "etc/shells", &format!("/bin/sh\n{shell}\n")).await?;
    write_jail_file(
        jail,
        "etc/profile",
        "export PATH=/bin:/usr/bin\nexport HOME=/\ncd /content 2>/dev/null || true\n",
    )
    .await?;
    write_jail_file(
        jail,
        "etc/motd",
        "DockPanel jailed shell — your files are in /content.\n",
    )
    .await?;
    if let Ok(resolv) = tokio::fs::read_to_string("/etc/resolv.conf").await {
        let _ = write_jail_file(jail, "etc/resolv.conf", &resolv).await;
    }
    Ok(())
}

/// Give `domain`'s account a jailed interactive shell. The account and jail must
/// already exist — the caller enables file (SFTP) access first.
pub async fn enable_shell(domain: &str, uid: i32, gid: i32) -> Result<(), String> {
    let jail = jail_root(domain);
    if !std::path::Path::new(&jail).exists() {
        return Err(format!(
            "the jail for {domain} does not exist yet — enable file (SFTP) access first"
        ));
    }
    let username = sftp_username(uid);
    let _ = safe_command_unsandboxed("groupadd", &[])
        .args([SHELL_GROUP])
        .output()
        .await;
    build_shell_runtime(&jail, &username, uid, gid).await?;
    // sshd refuses a locked account even for publickey auth ("account is
    // locked"), so a shell account must be unlocked. If no password is set yet,
    // set a random one: the account becomes usable by key immediately, and a
    // password login stays impossible until the owner resets it to a known value.
    ensure_unlocked(&username).await?;
    run_un("usermod", &["-s", jail_shell(), &username]).await?;
    run_un("usermod", &["-aG", SHELL_GROUP, &username]).await?;
    // NOT left in the SFTP group: its `ForceCommand` would pin the login to
    // internal-sftp for ever (see `SHELL_GROUP`).
    let _ = run_un("gpasswd", &["-d", &username, SFTP_GROUP]).await;
    write_sshd_dropin().await?;
    tracing::info!("jailed shell enabled for {domain}: user={username}");
    Ok(())
}

/// Turn the jailed shell back into SFTP-only, keeping the account and files.
pub async fn disable_shell(domain: &str, uid: i32) -> Result<(), String> {
    let jail = jail_root(domain);
    let username = sftp_username(uid);
    let _ = run_un("usermod", &["-s", "/usr/sbin/nologin", &username]).await;
    let _ = run_un("gpasswd", &["-d", &username, SHELL_GROUP]).await;
    let _ = run_un("usermod", &["-aG", SFTP_GROUP, &username]).await;
    // Remove only the runtime; content/ is the tenant's files and stays.
    for dir in RUNTIME_DIRS {
        let _ = run_un("rm", &["-rf", &format!("{jail}/{dir}")]).await;
    }
    tracing::info!("jailed shell disabled for {domain}: user={username}");
    Ok(())
}

/// Ensure `username`'s password is not locked, setting a random one if it is.
async fn ensure_unlocked(username: &str) -> Result<(), String> {
    let shadow = tokio::fs::read_to_string("/etc/shadow")
        .await
        .map_err(|e| format!("could not read /etc/shadow: {e}"))?;
    let locked = shadow
        .lines()
        .find(|l| l.starts_with(&format!("{username}:")))
        .map(|l| {
            let field = l.split(':').nth(1).unwrap_or("");
            field.is_empty() || field.starts_with('!') || field.starts_with('*')
        })
        .unwrap_or(true);
    if !locked {
        return Ok(());
    }
    let mut buf = [0u8; 24];
    {
        use rand::Rng as _;
        rand::rng().fill(&mut buf);
    }
    apply_password(username, &hex::encode(buf)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha_crypt::PasswordVerifier;

    /// The live-verified bug this pins: `$6$rounds=5000$8mwPPcuR8m7wfnYuiMKDK.$...`
    /// (a real hash this code produced before the fix) has a 22-character
    /// salt field. glibc's crypt() — what PAM actually calls to check a
    /// login — truncates a SHA-crypt salt to 16 characters when recomputing
    /// the hash to verify against, so an over-long salt makes EVERY future
    /// login attempt recompute a different digest than the one stored: not a
    /// crash, not an error anywhere, just permanent, silent authentication
    /// failure for a password that is actually correct. `hash_password()`'s
    /// auto-generated salt is `password_hash`'s generic
    /// `RECOMMENDED_SALT_LEN` (16 RAW bytes -> 22 base64 characters); this
    /// must never be used for a SHA-crypt hash a real `usermod -p` is going
    /// to store.
    #[test]
    fn the_generated_salt_is_at_most_sixteen_characters() {
        let salt: [u8; 12] = {
            use rand::Rng;
            rand::rng().random()
        };
        let hash = ShaCrypt::default()
            .hash_password_with_salt(b"irrelevant-test-password", &salt)
            .expect("hashing a test password must succeed");
        let fields: Vec<&str> = hash.as_str().split('$').collect();
        // ["", "6", ("rounds=N" |) salt, digest] — salt is always the
        // second-to-last field regardless of whether rounds= is present.
        let salt_field = fields[fields.len() - 2];
        assert!(
            salt_field.len() <= 16,
            "salt field '{salt_field}' is {} characters — glibc's crypt() will \
             truncate it on verify and every login will fail",
            salt_field.len()
        );
    }

    /// The actual property that matters: a hash this code produces must
    /// verify correctly via the SAME crate used to produce it (a necessary
    /// but not sufficient check — the salt-length assertion above is what
    /// catches the specific cross-implementation gap with glibc, since this
    /// crate happily verifies its OWN over-long-salt hashes without
    /// truncating, which is exactly why the bug was invisible to this check
    /// alone).
    #[test]
    fn a_produced_hash_verifies_against_the_password_that_made_it() {
        let salt: [u8; 12] = {
            use rand::Rng;
            rand::rng().random()
        };
        let hash = ShaCrypt::default()
            .hash_password_with_salt(b"a-real-looking-password-123", &salt)
            .expect("hashing must succeed");
        ShaCrypt::default()
            .verify_password(b"a-real-looking-password-123", &hash)
            .expect("the password that produced this hash must verify against it");
        assert!(
            ShaCrypt::default()
                .verify_password(b"a-different-password", &hash)
                .is_err(),
            "a wrong password must not verify"
        );
    }

    /// The fstab bookkeeping that makes an OpenRC bind mount survive a reboot:
    /// the mount point is the SECOND field, and a comment or an unrelated mount
    /// must never be mistaken for it.
    #[test]
    fn fstab_mount_lookup_matches_only_the_mount_point_field() {
        let fstab = "# /etc/fstab\n\
                     /dev/sda1 / ext4 defaults 0 1\n\
                     /var/www/example.com /var/dockpanel-sftp/example.com/content none bind,nofail 0 0\n";
        assert!(fstab_has_mount(fstab, "/var/dockpanel-sftp/example.com/content"));
        assert!(!fstab_has_mount(fstab, "/var/www/example.com"));
        assert!(!fstab_has_mount(fstab, "# /var/dockpanel-sftp/example.com/content"));
        assert!(!line_mounts("# a comment", "/anything"));
        assert!(!line_mounts("", "/anything"));
    }
}
