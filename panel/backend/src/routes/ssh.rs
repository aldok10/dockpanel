//! SSH login accounts — the screen for the Linux logins the panel itself made.
//!
//! A panel user may carry an `os_username`, and the agent provisions the matching
//! Linux account so its owner can sign in over SSH (see `routes::users` and the
//! agent's `services::os_accounts`). This module is the management surface those
//! accounts never had: one list, plus the four acts an operator wants on a login
//! — turn its password off and on, change its password, remove the login, and
//! manage the public keys that let someone in without one.
//!
//! Two facts the account list needs are stored here rather than derived:
//!
//! * `os_locked`, the administrator's explicit lock on the SSH password. It is
//!   independent of panel suspension on purpose — an operator wants to shut off a
//!   shell while leaving the panel login working. The EFFECTIVE lock is
//!   `role = 'suspended' OR os_locked`, so a suspended account is locked no matter
//!   what this holds, and un-suspending restores the explicit lock instead of
//!   blindly re-opening SSH.
//! * the panel `role`, which is how the screen shows "suspended" beside a login.
//!
//! Every act on another administrator's account is refused with the same rule
//! `routes::users` uses — a peer is not a subordinate.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::{agent_error, err, internal_error, ApiError};
use crate::models::User;
use crate::routes::users::{is_other_admin, normalize_os_username, os_username_taken};
use crate::services::activity;
use crate::AppState;

/// One SSH login, as the list renders it.
#[derive(serde::Serialize, sqlx::FromRow)]
pub struct SshAccount {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub os_username: String,
    pub os_locked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Percent-encode one path segment, unreserved characters and `:` left alone.
///
/// The remove-key route carries an OpenSSH fingerprint (`SHA256:…`), whose
/// standard-base64 tail can contain `/` and `+`. Sent raw, the `/` would split
/// the segment and the agent would 404 on a key it holds — intermittently, for
/// whichever keys happened to contain the character. Encoding here, with axum
/// decoding at the agent, keeps the fingerprint one opaque segment.
fn enc_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Load a user and the login name we manage for them, or the right refusal.
async fn load_ssh_user(state: &AppState, id: Uuid) -> Result<(User, String), ApiError> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("load ssh user", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;
    let name = user
        .os_username
        .clone()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "This user has no SSH login"))?;
    Ok((user, name))
}

/// GET /api/ssh/accounts — every panel user that has an SSH login.
pub async fn list_accounts(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<Vec<SshAccount>>, ApiError> {
    let accounts: Vec<SshAccount> = sqlx::query_as(
        "SELECT id, email, role, os_username, os_locked, created_at \
         FROM users WHERE os_username IS NOT NULL ORDER BY os_username",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list ssh accounts", e))?;
    Ok(Json(accounts))
}

#[derive(serde::Deserialize)]
pub struct CreateAccountRequest {
    pub user_id: Uuid,
    pub username: String,
    pub password: String,
}

/// POST /api/ssh/accounts — give an existing panel user an SSH login.
///
/// The panel-user half already exists, so this only attaches the OS half. It is
/// the reverse of `delete`: the name is persisted first, then the account is
/// created, and a failed provision clears the name again — the same order and the
/// same rollback `routes::users::create` uses, so the agent's `userdel` always has
/// a panel record naming the account it removes.
pub async fn create_account(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<CreateAccountRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.password.len() < 8 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters",
        ));
    }
    if body.password.len() > 128 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Password must be at most 128 characters",
        ));
    }

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(body.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("create ssh account", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    if is_other_admin(&user.role, user.id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot modify another administrator's account",
        ));
    }
    if user.os_username.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "This user already has an SSH login",
        ));
    }

    let name = normalize_os_username(&body.username)?
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Enter an SSH username"))?;
    if os_username_taken(&state.db, &name, Some(user.id)).await? {
        return Err(err(StatusCode::CONFLICT, "SSH username already in use"));
    }

    sqlx::query("UPDATE users SET os_username = $1, os_locked = FALSE, updated_at = NOW() WHERE id = $2")
        .bind(&name)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("create ssh account", e))?;

    if let Err(e) = state
        .agents
        .local()
        .post(
            "/os-users/provision",
            Some(serde_json::json!({ "username": name, "password": body.password })),
        )
        .await
    {
        let _ = sqlx::query("UPDATE users SET os_username = NULL WHERE id = $1")
            .bind(user.id)
            .execute(&state.db)
            .await;
        return Err(err(
            StatusCode::BAD_GATEWAY,
            &format!("The SSH account '{name}' could not be provisioned ({e})"),
        ));
    }

    // A suspended panel account is a locked SSH login. The account was just made
    // unlocked, so lock it now rather than leave a window where a suspended
    // person could sign in.
    if user.role == "suspended"
        && let Err(e) = state
            .agents
            .local()
            .post(
                "/os-users/state",
                Some(serde_json::json!({ "username": name, "locked": true })),
            )
            .await
    {
        tracing::warn!(
            user = %user.email,
            "SSH account '{name}' created but not locked for a suspended account: {e}"
        );
    }

    tracing::info!(
        "SSH login '{}' attached to {} by {}",
        name,
        user.email,
        claims.email
    );
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "ssh.account.create",
        Some("user"),
        Some(&user.email),
        Some(&name),
        ip.as_deref(),
        claims.key_id,
    )
    .await;
    crate::services::security_hardening::audit_log(
        &state.db,
        "ssh.account.create",
        Some(&claims.email),
        ip.as_deref(),
        Some("ssh"),
        Some(&name),
        Some(&user.email),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "id": user.id,
        "os_username": name,
    })))
}

/// DELETE /api/ssh/accounts/{id} — remove the SSH login, keep the panel user.
///
/// The OS account is removed BEFORE the panel record is cleared. Unlike
/// `routes::users::remove`, whose whole job is the panel row and which treats the
/// OS removal as best-effort cleanup, this action's entire promise is that the
/// login is gone — clearing `os_username` while the account survives on the box
/// would leave a working login with nothing in the panel pointing at it, exactly
/// the orphan the screen exists to prevent. So a failure here is reported and
/// nothing is cleared.
pub async fn remove_account(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, name) = load_ssh_user(&state, id).await?;
    if is_other_admin(&user.role, user.id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot modify another administrator's account",
        ));
    }

    state
        .agents
        .local()
        .delete(&format!("/os-users/{name}"))
        .await
        .map_err(|e| agent_error("Remove SSH account", e))?;

    sqlx::query("UPDATE users SET os_username = NULL, os_locked = FALSE, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("remove ssh account", e))?;

    tracing::info!(
        "SSH login '{}' removed from {} by {}",
        name,
        user.email,
        claims.email
    );
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "ssh.account.remove",
        Some("user"),
        Some(&user.email),
        Some(&name),
        ip.as_deref(),
        claims.key_id,
    )
    .await;
    crate::services::security_hardening::audit_log(
        &state.db,
        "ssh.account.remove",
        Some(&claims.email),
        ip.as_deref(),
        Some("ssh"),
        Some(&name),
        Some(&user.email),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true, "os_username": name })))
}

#[derive(serde::Deserialize)]
pub struct StateRequest {
    pub locked: bool,
}

/// POST /api/ssh/accounts/{id}/state — lock or unlock the SSH password.
///
/// Sets the explicit `os_locked` and applies the EFFECTIVE lock (suspended OR
/// locked) to the box, so asking to unlock an account whose panel login is
/// suspended leaves the password locked — and the response says so, rather than
/// reporting an unlock that did not happen.
pub async fn set_state(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<StateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, name) = load_ssh_user(&state, id).await?;
    if is_other_admin(&user.role, user.id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot modify another administrator's account",
        ));
    }

    let suspended = user.role == "suspended";
    let effective = suspended || body.locked;

    // Apply to the box first: the DB is only updated once the box agreed, so the
    // stored lock is never a claim the account does not honour.
    if let Err(e) = state
        .agents
        .local()
        .post(
            "/os-users/state",
            Some(serde_json::json!({ "username": name, "locked": effective })),
        )
        .await
    {
        return Err(agent_error("Set SSH account state", e));
    }

    sqlx::query("UPDATE users SET os_locked = $1, updated_at = NOW() WHERE id = $2")
        .bind(body.locked)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("set ssh account state", e))?;

    tracing::info!(
        "SSH login '{}' {} by {}",
        name,
        if effective { "locked" } else { "unlocked" },
        claims.email
    );
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        if body.locked {
            "ssh.account.lock"
        } else {
            "ssh.account.unlock"
        },
        Some("user"),
        Some(&user.email),
        Some(&name),
        ip.as_deref(),
        claims.key_id,
    )
    .await;
    crate::services::security_hardening::audit_log(
        &state.db,
        if body.locked {
            "ssh.account.lock"
        } else {
            "ssh.account.unlock"
        },
        Some(&claims.email),
        ip.as_deref(),
        Some("ssh"),
        Some(&name),
        Some(&user.email),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "locked": effective,
        "suspended": suspended,
    })))
}

/// GET /api/ssh/accounts/{id}/keys — the account's installed public keys.
pub async fn list_keys(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (_user, name) = load_ssh_user(&state, id).await?;
    let keys = state
        .agents
        .local()
        .get(&format!("/os-users/{name}/keys"))
        .await
        .map_err(|e| agent_error("List SSH keys", e))?;
    Ok(Json(keys))
}

#[derive(serde::Deserialize)]
pub struct AddKeyRequest {
    pub key: String,
}

/// POST /api/ssh/accounts/{id}/keys — install one public key.
pub async fn add_key(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<AddKeyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, name) = load_ssh_user(&state, id).await?;
    if is_other_admin(&user.role, user.id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot modify another administrator's account",
        ));
    }

    state
        .agents
        .local()
        .post(
            &format!("/os-users/{name}/keys"),
            Some(serde_json::json!({ "key": body.key })),
        )
        .await
        .map_err(|e| agent_error("Add SSH key", e))?;

    tracing::info!("SSH key added for '{}' by {}", name, claims.email);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "ssh.key.add",
        Some("user"),
        Some(&user.email),
        Some(&name),
        ip.as_deref(),
        claims.key_id,
    )
    .await;
    crate::services::security_hardening::audit_log(
        &state.db,
        "ssh.key.add",
        Some(&claims.email),
        ip.as_deref(),
        Some("ssh"),
        Some(&name),
        Some(&user.email),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// DELETE /api/ssh/accounts/{id}/keys/{fingerprint} — remove one key.
pub async fn remove_key(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path((id, fingerprint)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, name) = load_ssh_user(&state, id).await?;
    if is_other_admin(&user.role, user.id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot modify another administrator's account",
        ));
    }

    state
        .agents
        .local()
        .delete(&format!("/os-users/{name}/keys/{}", enc_segment(&fingerprint)))
        .await
        .map_err(|e| agent_error("Remove SSH key", e))?;

    tracing::info!("SSH key removed for '{}' by {}", name, claims.email);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "ssh.key.remove",
        Some("user"),
        Some(&user.email),
        Some(&name),
        ip.as_deref(),
        claims.key_id,
    )
    .await;
    crate::services::security_hardening::audit_log(
        &state.db,
        "ssh.key.remove",
        Some(&claims.email),
        ip.as_deref(),
        Some("ssh"),
        Some(&name),
        Some(&user.email),
        None,
        "warning",
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}
