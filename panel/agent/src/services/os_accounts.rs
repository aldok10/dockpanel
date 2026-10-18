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
use base64::Engine as _;
use sha2::{Digest, Sha256};
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

    // Idempotent: `userdel` refuses a name that is not there, and the SSH
    // screen's "remove this login" treats that non-zero exit as a failure it
    // must not paper over. But an account already gone is the state we were
    // asked to reach, so it is success — otherwise a login deleted on the box
    // out-of-band could never be cleared from the panel.
    if !account_exists(username).await {
        tracing::info!("OS login account '{username}' was already absent");
        return Ok(());
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

// ── Authorized keys ─────────────────────────────────────────────────────
//
// cPanel's SSH screen is mostly this: the public keys that let someone in
// without typing the password the panel also holds. They live in the account's
// own `~/.ssh/authorized_keys`, which sshd reads as that user — so, exactly like
// the account operations above, the file writes must escape the agent sandbox:
// `ProtectHome=yes` hides `/home` entirely inside the unit's namespace, and a
// sandboxed `install` would answer EROFS. Reads go through `cat` and writes are
// staged under `/var/lib/dockpanel` (which IS in `ReadWritePaths`) and then
// installed outside the namespace with the right owner and mode.

/// Why an SSH-key operation failed, so a caller can pick a status code.
///
/// Split deliberately rather than returned as a bare `String`: the three key
/// routes have both a "the operator typed something wrong" failure (a bad name,
/// a malformed key, an account with no key file) and a "the box failed" one
/// (unreadable `/etc/passwd`, a failed `install`), and the panel turns the first
/// into a 400 the operator can read and the second into a 500 it can only
/// reference. Collapsing them is how a typo would reach a human as an incident
/// id.
#[derive(Debug, PartialEq)]
pub enum KeyError {
    /// The caller's mistake. Answers 400.
    Client(String),
    /// The box failed. Answers 500.
    Server(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Client(m) | KeyError::Server(m) => f.write_str(m),
        }
    }
}

/// One key in an `authorized_keys` file, shaped for the panel to render.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AuthorizedKey {
    /// The key algorithm, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// OpenSSH's `SHA256:…` fingerprint, the value the remove route matches on.
    pub fingerprint: String,
    /// Everything after the key body, treating the whole tail as the comment — a
    /// comment can contain spaces, and the root-key reader already joins it.
    pub comment: String,
    /// A short, non-sensitive preview for the list.
    pub preview: String,
}

/// OpenSSH's `SHA256:` fingerprint of a key's base64 body.
///
/// The literal format the `ssh-keygen -l` line prints, and the same value
/// `routes/server_utils.rs` computes for root's keys, so a fingerprint shown on
/// either screen is the one a person sees when they run `ssh-keygen`.
fn fingerprint_of(key_data: &str) -> String {
    // OpenSSH strips base64 padding from the key body, so try the padded engine
    // and fall back to the unpadded one. Using the padded engine alone leaves an
    // unpadded body undecoded, and hashing an EMPTY buffer still yields a
    // well-formed `SHA256:…` — a wrong fingerprint that looks right.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key_data)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(key_data))
        .unwrap_or_default();
    let hash = Sha256::digest(&decoded);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD
            .encode(&hash)
            .trim_end_matches('=')
    )
}

/// True for a blank line or a comment — skipped by both the reader and the
/// remover, so a `#`-commented key survives a removal it does not match.
fn is_ignored_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Parse the non-comment lines of an `authorized_keys` file.
///
/// Pure, so the panel's view of a key file can be unit-tested without a box. A
/// line with fewer than two whitespace-separated fields is not a key and is
/// dropped rather than rendered as a broken row.
pub fn parse_authorized_keys(content: &str) -> Vec<AuthorizedKey> {
    content
        .lines()
        .filter(|l| !is_ignored_line(l))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let key_type = parts.next()?.to_string();
            let key_data = parts.next()?.to_string();
            let comment = parts.collect::<Vec<_>>().join(" ");
            Some(AuthorizedKey {
                fingerprint: fingerprint_of(&key_data),
                preview: format!("{} {}…", key_type, &key_data[..key_data.len().min(20)]),
                key_type,
                comment,
            })
        })
        .collect()
}

/// True when `key` is one line of a public key we are willing to install.
///
/// Deliberately strict, and the same shape `routes/server_utils.rs` accepts for
/// root's keys: a single line, a known algorithm prefix, a body of at least 16
/// base64 characters, and no `authorized_keys` options. The options refusal is
/// load-bearing — a `command="…"` prefix handed to an account whose keys we do
/// not otherwise police is a way to pin that account to one program, and these
/// keys are meant to be a plain login.
pub fn validate_key(key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.contains('\n') || key.contains('\r') || key.contains('\0') {
        return Err("SSH key must be a single line".to_string());
    }
    if !key.starts_with("ssh-") && !key.starts_with("ecdsa-") && !key.starts_with("sk-") {
        return Err("Invalid SSH key format".to_string());
    }
    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 2 || parts[1].len() < 16 {
        return Err("Invalid SSH key: missing key data".to_string());
    }
    for forbidden in ["command=", "from=", "restrict", "no-pty", "permitopen"] {
        if key.contains(forbidden) {
            return Err("SSH key options are not allowed".to_string());
        }
    }
    Ok(())
}

/// The account's home directory, from its `/etc/passwd` entry (field 6).
///
/// Not assumed to be `/home/<name>`: `useradd`'s base directory comes from
/// `/etc/default/useradd` and `login.defs`, and a wrong guess would write a key
/// file into a directory sshd never reads. `/etc` is readable under
/// `ProtectSystem=strict`, and this is a read, so it needs no escape hatch.
async fn home_dir(username: &str) -> Result<String, KeyError> {
    let passwd = tokio::fs::read_to_string("/etc/passwd")
        .await
        .map_err(|e| KeyError::Server(format!("could not read /etc/passwd: {e}")))?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(username) {
            // After the name: password, uid, gid, gecos, then home. `nth(4)`
            // consumes the four between and returns the home field.
            if let Some(home) = fields.nth(4)
                && home.starts_with('/')
            {
                return Ok(home.to_string());
            }
        }
    }
    Err(KeyError::Client(format!(
        "no account named '{username}' exists on this server"
    )))
}

/// The absolute path of the account's `authorized_keys`.
async fn authorized_keys_path(username: &str) -> Result<String, KeyError> {
    let home = home_dir(username).await?;
    Ok(format!("{home}/.ssh/authorized_keys"))
}

/// Read a file from OUTSIDE the agent's sandbox, distinguishing "absent" from
/// "unreadable". `Ok(None)` means the file genuinely does not exist.
async fn read_file_unsandboxed(path: &str) -> Result<Option<String>, KeyError> {
    let exists = safe_command_unsandboxed("test", &[])
        .args(["-e", path])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }
    let out = safe_command_unsandboxed("cat", &[])
        .arg(path)
        .output()
        .await
        .map_err(|e| KeyError::Server(format!("could not read {path}: {e}")))?;
    if !out.status.success() {
        return Err(KeyError::Server(format!(
            "could not read {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// Write an `authorized_keys` file, staging inside the sandbox and installing
/// outside it, owned by the account and mode 600.
async fn write_file_unsandboxed(
    username: &str,
    path: &str,
    content: &str,
) -> Result<(), KeyError> {
    let staging = format!("/var/lib/dockpanel/.ssh_keys.{}", uuid::Uuid::new_v4());
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|e| KeyError::Server(format!("could not stage the key file: {e}")))?;
        f.write_all(content.as_bytes())
            .map_err(|e| KeyError::Server(format!("could not stage the key file: {e}")))?;
    }

    let result = async {
        let Some((dir, _)) = path.rsplit_once('/') else {
            return Err(KeyError::Server(format!(
                "refusing to write a key file outside a directory: {path}"
            )));
        };
        // `.ssh` must be 700 and owned by the account — sshd's StrictModes
        // refuses a directory anyone but the user can write. `install -D` would
        // create it 0755, so the directory is made explicitly first.
        let dir_out = safe_command_unsandboxed("install", &[])
            .args(["-d", "-m", "700", "-o", username, dir])
            .output()
            .await
            .map_err(|e| KeyError::Server(format!("could not create {dir}: {e}")))?;
        if !dir_out.status.success() {
            return Err(KeyError::Server(format!(
                "could not create {dir}: {}",
                String::from_utf8_lossy(&dir_out.stderr).trim()
            )));
        }
        let file_out = safe_command_unsandboxed("install", &[])
            .args(["-m", "600", "-o", username, &staging, path])
            .output()
            .await
            .map_err(|e| KeyError::Server(format!("could not install {path}: {e}")))?;
        if !file_out.status.success() {
            return Err(KeyError::Server(format!(
                "could not install {path}: {}",
                String::from_utf8_lossy(&file_out.stderr).trim()
            )));
        }
        Ok(())
    }
    .await;

    let _ = std::fs::remove_file(&staging);
    result
}

/// List the public keys installed for `username`.
pub async fn list_keys(username: &str) -> Result<Vec<AuthorizedKey>, KeyError> {
    if !is_valid_username(username) {
        return Err(KeyError::Client(format!(
            "refusing to read keys for invalid login name '{username}'"
        )));
    }
    let path = authorized_keys_path(username).await?;
    let content = read_file_unsandboxed(&path).await?.unwrap_or_default();
    Ok(parse_authorized_keys(&content))
}

/// Install one public key for `username`.
pub async fn add_key(username: &str, key: &str) -> Result<(), KeyError> {
    if !is_valid_username(username) {
        return Err(KeyError::Client(format!(
            "refusing to add a key for invalid login name '{username}'"
        )));
    }
    let key = key.trim();
    validate_key(key).map_err(KeyError::Client)?;
    let path = authorized_keys_path(username).await?;
    let mut content = read_file_unsandboxed(&path).await?.unwrap_or_default();
    if content.lines().any(|line| line.trim() == key) {
        return Err(KeyError::Client(
            "This key is already installed for this account".to_string(),
        ));
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(key);
    content.push('\n');
    write_file_unsandboxed(username, &path, &content).await
}

/// Remove the key whose fingerprint is `fingerprint` from `username`.
pub async fn remove_key(username: &str, fingerprint: &str) -> Result<(), KeyError> {
    if !is_valid_username(username) {
        return Err(KeyError::Client(format!(
            "refusing to remove a key for invalid login name '{username}'"
        )));
    }
    let path = authorized_keys_path(username).await?;
    let content = read_file_unsandboxed(&path)
        .await?
        .ok_or_else(|| KeyError::Client("this account has no SSH keys".to_string()))?;

    let new_content: String = content
        .lines()
        .filter(|line| {
            if is_ignored_line(line) {
                return true;
            }
            let mut parts = line.split_whitespace();
            let _key_type = parts.next();
            match parts.next() {
                Some(data) => fingerprint_of(data) != fingerprint,
                None => true,
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    write_file_unsandboxed(username, &path, &format!("{new_content}\n")).await
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

    /// A canonical, unpadded base64 key body — the exact shape OpenSSH writes.
    const ED_BODY: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEy";

    #[test]
    fn parses_only_real_key_lines() {
        let content = format!(
            "# a comment, not a key\n\nssh-ed25519 {ED_BODY} alice@laptop\nssh-ed25519 short body\n"
        );
        let keys = parse_authorized_keys(&content);
        assert_eq!(keys.len(), 2, "comments and blanks are not keys");
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].comment, "alice@laptop");
        // A comment may contain spaces; the whole tail is one comment, not a
        // third field dropped on the floor.
        let spaced = parse_authorized_keys(&format!("ssh-ed25519 {ED_BODY} a b c\n"));
        assert_eq!(spaced[0].comment, "a b c");
    }

    #[test]
    fn fingerprints_match_openssh() {
        // The literal `ssh-keygen -l` value for this body. A padded-only base64
        // decoder leaves an unpadded body (as OpenSSH writes it) undecoded and
        // hashes an EMPTY buffer — still a well-formed `SHA256:…`, so only a
        // known-answer test catches it.
        assert_eq!(
            fingerprint_of(ED_BODY),
            "SHA256:MwmEfO5FS0+Z3P6P3FURp7oWjOC25WhO9z+QMNAJuLU"
        );
        // A body whose length is 3 mod 4 exercises the other padding arm.
        let rsa = "YW4gc3NoLWVkMjU1MTkga2V5IGJvZHkgb2YgZXhhY3RseSBmaWZ0eSBvbmUgYnl0ZXMhISE";
        assert_eq!(
            fingerprint_of(rsa),
            "SHA256:1B2uyHlgB2nw5S3HULZrk4GV7xHErU/YYuhH18GayJo"
        );
        // And never the fingerprint of the empty buffer, which is what the
        // undecoded path would produce.
        assert_ne!(fingerprint_of(ED_BODY), fingerprint_of(""));
    }

    #[test]
    fn accepts_a_plain_public_key_and_refuses_the_rest() {
        let ok = format!("ssh-ed25519 {ED_BODY} a@b");
        assert!(validate_key(&ok).is_ok());
        // Unknown algorithm prefix.
        assert!(validate_key(&format!("wat {ED_BODY}")).is_err());
        // Missing body / too short.
        assert!(validate_key("ssh-ed25519 short").is_err());
        assert!(validate_key("ssh-ed25519").is_err());
        // Newlines would let one request append several keys.
        assert!(validate_key(&format!("ssh-ed25519 {ED_BODY}\nssh-ed25519 x")).is_err());
        // authorized_keys options are how a login is pinned to one program.
        assert!(validate_key(&format!("command=\"/bin/false\" ssh-ed25519 {ED_BODY}")).is_err());
        assert!(validate_key(&format!("restrict ssh-ed25519 {ED_BODY}")).is_err());
    }
}
