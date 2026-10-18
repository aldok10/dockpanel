//! Per-user OS (SSH) login accounts.
//!
//! An administrator who creates a panel user may give it a login name, and this
//! module provisions the matching Linux account on the box so the person can log
//! in over SSH with the same credentials they use for the panel. It is the
//! deliberately plain sibling of [`crate::services::sftp_accounts`]: no uid/gid
//! allocation, no chroot jail, no bind mount — an ordinary `useradd -m` account
//! whose shell is a real login shell.
//!
//! Two properties the panel's policy depends on are enforced HERE rather than
//! left to a caller, because a caller that forgets them grants a capability:
//!
//! * **No privilege.** The account is never added to `sudo`/`wheel`. DockPanel's
//!   panel roles are a panel concept; a `user`-role person with an OS account can
//!   read and write only what the filesystem already lets an unprivileged login
//!   touch. Escalation stays a deliberate, separate operator act.
//! * **No name collision.** The login name is validated as POSIX-safe and refused
//!   outright when it is a system/service account or already exists on the box —
//!   so a user can never be handed `root`, `www-data`, `dockpanel`, the `vmail`
//!   mail account, or one of the per-site `sftp<uid>` accounts.
//!
//! `useradd`/`usermod`/`userdel` are run through [`safe_command_unsandboxed`]
//! (the `systemd-run` escape, same rationale as `sftp_accounts`): `/etc/passwd`,
//! `/etc/shadow` and `/etc/group` live outside the agent unit's `ReadWritePaths`,
//! so a sandboxed child gets `Read-only file system` and the account is never
//! created.

use crate::safe_cmd::safe_command_unsandboxed;
use sha_crypt::{PasswordHasher, ShaCrypt};

/// Longest login name Linux accepts in practice (`useradd`'s own cap is 32).
const MAX_USERNAME_LEN: usize = 32;

/// Names this module refuses even though they are syntactically valid. They are
/// either system/service accounts the panel itself relies on, or the fixed
/// identities the mail and SFTP subsystems create. Handing a panel user one of
/// these would misfile a login as infrastructure; the `id` check in
/// [`validate_username`] catches the ones already present on a given box, and
/// this list catches the rest before they are ever attempted.
///
/// It is deliberately a deny-list of the KNOWN infrastructure identities plus a
/// blanket refusal of anything already on the box — not an allow-list of
/// "normal-looking" names, which would drift from what a given distro ships.
pub const RESERVED_USERNAMES: [&str; 33] = [
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
    "systemd-network", "systemd-resolve", "systemd-timesync", "messagebus",
    "sshd", "docker", "postgres", "mysql", "redis", "nginx", "vmail",
    "dockpanel", "sftp_sites", "admin", "nologin",
];

/// True when `name` is a syntactically valid, lower-case POSIX login name.
///
/// `useradd` accepts more than this (it permits a trailing `$` and, on some
/// systems, upper case), but the narrower set is what an operator should be
/// typing and what every downstream tool — `id`, `chown`, `su` — handles
/// without quoting. First character must be a lower-case letter or underscore;
/// the rest lower-case letters, digits, underscore or hyphen.
pub fn is_valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_USERNAME_LEN {
        return false;
    }
    if !(bytes[0].is_ascii_lowercase() || bytes[0] == b'_') {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// True when `name` is one of the reserved infrastructure identities.
pub fn is_reserved_username(name: &str) -> bool {
    RESERVED_USERNAMES.contains(&name)
        // The per-site SFTP accounts are `sftp<uid>` (see
        // `sftp_accounts::sftp_username`). Refuse the whole shape rather than a
        // fixed list of the ids that happen to exist today.
        || (name.len() > 4
            && name.starts_with("sftp")
            && name[4..].chars().all(|c| c.is_ascii_digit()))
}

/// Full validation: syntax, reservation, and "does this account already exist".
///
/// The existence check subsumes the reserved list on any real box (root, the
/// service accounts and vmail all exist), but it is kept as a separate, explicit
/// refusal so the error names *why* rather than surfacing `useradd`'s terse
/// "already exists". It also closes the inverse gap: a name that is not on the
/// list but is nonetheless already taken (an operator's own hand-made account)
/// must not be silently adopted as if the panel had created it.
pub async fn validate_username(name: &str) -> Result<(), String> {
    if !is_valid_username(name) {
        return Err(format!(
            "'{name}' is not a valid login name: use 1-32 characters, start with a \
             lower-case letter or underscore, then lower-case letters, digits, \
             underscores or hyphens"
        ));
    }
    if is_reserved_username(name) {
        return Err(format!(
            "'{name}' is a reserved system or service account and cannot be used \
             for a person's login"
        ));
    }
    if account_exists(name).await {
        return Err(format!(
            "the account '{name}' already exists on this server; choose a different \
             login name"
        ));
    }
    Ok(())
}

/// Whether an account named `name` exists on this box (`id -u <name>`).
async fn account_exists(name: &str) -> bool {
    match safe_command_unsandboxed("id", &[]).args(["-u", name]).output().await {
        Ok(out) => out.status.success(),
        // If `id` cannot even run we cannot prove the name is free; treat it as
        // taken so we never `useradd` over an existing account.
        Err(_) => true,
    }
}

/// The login shell new accounts get.
///
/// `/bin/bash` where it exists (Debian, Ubuntu, RHEL, Fedora), `/bin/ash` on a
/// stock Alpine, and `/bin/sh` as the last resort. Never `/usr/sbin/nologin` —
/// the whole point of this account is interactive SSH, and a nologin shell is
/// exactly the SFTP-only shape this module is not.
async fn login_shell() -> String {
    for candidate in ["/bin/bash", "/bin/ash", "/bin/sh"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    // Nothing matched: every POSIX box has one of the three above, so this is
    // unreachable in practice, but `useradd` with a missing shell fails loudly
    // rather than silently, which is the right outcome.
    "/bin/sh".to_string()
}

/// Hash `plaintext` as glibc SHA-512-crypt, with the 12-byte salt `sftp_accounts`
/// documents at length: `password_hash`'s generic 16-byte salt base64-encodes to
/// 22 characters, glibc's crypt() truncates to 16 on verify, and every correct
/// password then fails forever. Shared reasoning, duplicated here rather than
/// imported so the two subsystems can evolve independently.
fn sha512_crypt(plaintext: &str) -> Result<String, String> {
    use rand::Rng;
    let salt: [u8; 12] = rand::rng().random();
    ShaCrypt::default()
        .hash_password_with_salt(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Failed to hash password: {e}"))
}

/// Create the OS account `username` with `password`, and nothing else.
///
/// Idempotency is deliberately NOT offered: [`validate_username`] refuses an
/// account that already exists, so a retry after a partial failure is the
/// operator's explicit act (delete the half-made account, then retry) rather
/// than this function guessing whether an existing account is "theirs".
pub async fn provision(username: &str, password: &str) -> Result<(), String> {
    validate_username(username).await?;

    let shell = login_shell().await;
    let out = safe_command_unsandboxed("useradd", &[])
        .args(["-m", "-s", &shell, username])
        .output()
        .await
        .map_err(|e| format!("useradd failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "useradd {username} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // Set the password as a second, separate step so a hashing failure leaves a
    // login-less account the operator can see and remove, rather than a silent
    // half-created one. If it fails, roll the account back: an account with no
    // password is not usefully creatable and only invites confusion.
    if let Err(e) = set_password(username, password).await {
        let _ = safe_command_unsandboxed("userdel", &[]).args(["-r", username]).output().await;
        return Err(e);
    }

    tracing::info!("OS login account provisioned: {username} (shell {shell})");
    Ok(())
}

/// Set (or reset) `username`'s password. Mirrors `sftp_accounts::set_password`:
/// hash in-process and store via `usermod -p`, never pipe plaintext through
/// `chpasswd`'s stdin (the shared command primitive has no stdin support).
pub async fn set_password(username: &str, password: &str) -> Result<(), String> {
    if !is_valid_username(username) {
        return Err(format!("refusing to set a password for invalid login name '{username}'"));
    }
    let hash = sha512_crypt(password)?;
    let out = safe_command_unsandboxed("usermod", &[])
        .args(["-p", hash.as_str(), username])
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

/// Lock or unlock the account's password (`usermod -L` / `-U`).
///
/// Used when an administrator suspends or un-suspends the panel user. A `-L`
/// only prefixes the stored hash in `/etc/shadow`, so an SSH key already
/// installed by the account holder keeps working — this is "no new password
/// logins", not "cut off every session". Suspending a panel account is a
/// panel-level act; an SSH key the person installed is theirs to manage.
pub async fn set_locked(username: &str, locked: bool) -> Result<(), String> {
    if !is_valid_username(username) {
        return Err(format!("refusing to change lock state for invalid login name '{username}'"));
    }
    let flag = if locked { "-L" } else { "-U" };
    let out = safe_command_unsandboxed("usermod", &[])
        .args([flag, username])
        .output()
        .await
        .map_err(|e| format!("usermod failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "usermod {flag} failed for {username}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Remove the OS account and its home directory (`userdel -r`).
///
/// Best-effort in the same sense as `sftp_accounts::deprovision` — the panel
/// row is deleted regardless — but every failure is logged, never swallowed,
/// because a stale account is a login that outlives the account that owned it.
/// Any process still running as the user is killed first, since `userdel`
/// refuses to remove a uid with live processes.
pub async fn deprovision(username: &str) -> Result<(), String> {
    if !is_valid_username(username) {
        return Err(format!("refusing to delete invalid login name '{username}'"));
    }

    let _ = safe_command_unsandboxed("pkill", &[]).args(["-9", "-u", username]).output().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let out = safe_command_unsandboxed("userdel", &[])
        .args(["-r", username])
        .output()
        .await
        .map_err(|e| format!("userdel failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "userdel {username} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    tracing::info!("OS login account removed: {username}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_login_names() {
        for name in ["alice", "bob-2", "dev_ops", "_service"] {
            assert!(is_valid_username(name), "{name} should be a valid login name");
        }
    }

    #[test]
    fn refuses_shapes_useradd_should_never_see() {
        for name in ["", "Alice", "2alice", "-alice", "a.b", "alice smith", "a;rm"] {
            assert!(!is_valid_username(name), "{name:?} must be refused");
        }
        let too_long = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(!is_valid_username(&too_long), "over-long names must be refused");
    }

    #[test]
    fn refuses_infrastructure_identities() {
        for name in ["root", "www-data", "vmail", "dockpanel", "sftp_sites", "sftp30001"] {
            assert!(is_reserved_username(name), "{name} must be reserved");
        }
        assert!(!is_reserved_username("alice"), "an ordinary name is not reserved");
    }

    #[test]
    fn the_reserved_list_covers_the_names_the_panel_itself_uses() {
        // These are created elsewhere in the agent and a collision would misfile
        // a person's login as infrastructure. Pinned so removing one is noticed.
        for name in ["vmail", "dockpanel"] {
            assert!(RESERVED_USERNAMES.contains(&name), "{name} dropped off the reserved list");
        }
    }
}
