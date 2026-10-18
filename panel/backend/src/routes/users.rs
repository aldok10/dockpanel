use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use uuid::Uuid;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

use crate::auth::AdminUser;
use crate::error::{internal_error, err, ApiError};
use crate::models::User;
use crate::services::activity;
use crate::AppState;

#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: Option<String>,
    /// Optional Linux login name for an SSH account on the panel host. When
    /// present the agent provisions the OS account as part of this request; when
    /// absent the user is panel-only, which is the default.
    #[serde(default)]
    pub os_username: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub password: Option<String>,
    /// Add an SSH login to a user that does not have one yet. Setting it on an
    /// account that already has one is refused (the OS account cannot be
    /// renamed in place); it is never used to *change* an existing login.
    #[serde(default)]
    pub os_username: Option<String>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub reseller_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub site_count: i64,
    /// Carried so the user table can offer "Reset 2FA" on the rows that have an
    /// enrolment and stay quiet on the rows that do not. Without it the control
    /// would be a button that refuses on most of the list — the shape this panel
    /// keeps having to remove.
    pub totp_enabled: bool,
    /// The SSH login this user holds on the panel host, or null. Carried so the
    /// table can show who can log in to the box and offer to remove an account.
    pub os_username: Option<String>,
}

/// Normalise and validate an operator-supplied OS login name.
///
/// Empty means "no SSH account" (`Ok(None)`), matching the optional-by-design
/// policy: a panel user without a login is the common case. The syntax is
/// mirrored from `agent::services::os_accounts::is_valid_username` — lower-case
/// POSIX, 1-32 characters — so the panel can reject a bad name with a clear
/// message before it ever reaches the agent. The authoritative check (is the
/// name already taken on the box?) still happens at the agent.
fn normalize_os_username(raw: &str) -> Result<Option<String>, ApiError> {
    let name = raw.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Ok(None);
    }
    let first_ok = name
        .chars()
        .next()
        .map(|c| c.is_ascii_lowercase() || c == '_')
        .unwrap_or(false);
    let rest_ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if name.len() > 32 || !first_ok || !rest_ok {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "SSH username must be 1-32 characters, start with a lowercase letter or \
             underscore, then lowercase letters, digits, underscores or hyphens",
        ));
    }
    Ok(Some(name))
}

/// Refuse an `os_username` another panel account already claims.
///
/// The `users` table's partial unique index is the backstop; this exists so the
/// operator gets a sentence instead of a raw constraint violation. Case is not
/// a concern because `normalize_os_username` has already lower-cased the value.
async fn os_username_taken(
    db: &sqlx::PgPool,
    name: &str,
    exclude: Option<Uuid>,
) -> Result<bool, ApiError> {
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE os_username = $1 AND ($2::uuid IS NULL OR id <> $2)")
            .bind(name)
            .bind(exclude)
            .fetch_optional(db)
            .await
            .map_err(|e| internal_error("check os_username", e))?;
    Ok(row.is_some())
}

/// Push a password to a user's SSH account, when they have one.
///
/// Every door that changes a panel password calls this so the panel login and
/// the SSH login stay the same credential — an administrator resetting it, the
/// user changing it themselves, a forgotten-password reset, and a reseller
/// resetting a tenant. A panel-only user (no `os_username`) is a no-op.
///
/// It is deliberately NOT best-effort: a password that changed for the panel but
/// not for SSH leaves the OLD SSH password working, which is the security half
/// of the change silently absent. Callers surface the failure; the panel hash is
/// already written by then, so the message says exactly that.
pub async fn sync_ssh_password(
    state: &AppState,
    user_id: Uuid,
    password: &str,
) -> Result<(), ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT os_username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("sync ssh password", e))?;

    let name = match row {
        Some((Some(name),)) => name,
        _ => return Ok(()),
    };

    state
        .agents
        .local()
        .post(
            "/os-users/password",
            Some(serde_json::json!({ "username": name, "password": password })),
        )
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "The panel password was changed, but the SSH account '{name}' password \
                     could not be updated ({e})"
                ),
            )
        })?;
    Ok(())
}

/// GET /api/users — List all users (admin only).
pub async fn list(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<Vec<UserResponse>>, ApiError> {

    let users: Vec<UserResponse> = sqlx::query_as(
        "SELECT u.id, u.email, u.role, u.reseller_id, u.created_at, \
         COALESCE((SELECT COUNT(*) FROM sites WHERE user_id = u.id), 0) as site_count, \
         u.totp_enabled, u.os_username \
         FROM users u ORDER BY u.created_at ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list users", e))?;

    Ok(Json(users))
}
/// The role values an operator may assign through this module.
///
/// ONE list, because there were three identical copies — create, update and the
/// un-suspend restore — and adding `client` to the database CHECK and to the user
/// editor still left all three refusing it, so the role existed everywhere except
/// where it is written. `suspended` is deliberately absent: it is reached through
/// `toggle_suspend`, never assigned directly.
///
/// Public because `helpers::unsuspend_account` validates a stashed role against
/// it. It is deliberately shared rather than copied — a fourth copy is how the
/// first three got out of step.
pub const ASSIGNABLE_ROLES: [&str; 4] = ["admin", "reseller", "user", "client"];

/// The message that names them. `err` takes a `&str`, so this cannot be built
/// from the list at runtime — a unit test asserts it mentions every one instead,
/// which is the same guarantee by a different route.
const ASSIGNABLE_ROLES_MSG: &str = "Role must be one of: admin, reseller, user, client";

/// True when `target` is another administrator — the caller's peer, not their
/// subordinate. `AdminUser` below is a role check ONLY, so without this every
/// two admin accounts on the same install are fully interchangeable: reset
/// each other's password, strip each other's 2FA-recovering password (see
/// `reset_password`), or delete each other and inherit their entire server
/// fleet (`remove`'s `UPDATE servers SET user_id = ...` below). Multiple
/// administrators is a live, supported configuration, not a hypothetical one
/// — `docs/guides/roles-and-ownership.md` describes a per-admin hardware
/// boundary for sites ("does not extend to a machine another administrator
/// added"), and `534dc51`/v2.185.0 fixed a second-admin-visibility bug
/// elsewhere in this arc. `list`/`create` are deliberately untouched: seeing
/// the directory or minting a new account doesn't hand over an existing one.
fn is_other_admin(target_role: &str, target_id: Uuid, caller_id: Uuid) -> bool {
    target_role == "admin" && target_id != caller_id
}


/// POST /api/users — Create a new user (admin only).
pub async fn create(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {

    if body.email.is_empty() || body.email.len() > 254 || !body.email.contains('@') {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid email"));
    }
    if body.password.len() < 8 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters",
        ));
    }

    let role = body.role.as_deref().unwrap_or("user");
    if !ASSIGNABLE_ROLES.contains(&role) {
        return Err(err(StatusCode::BAD_REQUEST, ASSIGNABLE_ROLES_MSG));
    }

    // Optional SSH account. Validated and reserved-checked here so a bad name
    // never reaches the agent; the agent still owns the "already on the box"
    // refusal, which only it can answer.
    let os_username = normalize_os_username(body.os_username.as_deref().unwrap_or(""))?;
    if let Some(ref name) = os_username {
        if os_username_taken(&state.db, name, None).await? {
            return Err(err(StatusCode::CONFLICT, "SSH username already in use"));
        }
    }

    // Check email uniqueness
    let existing: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE email = $1")
            .bind(&body.email)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("create users", e))?;

    if existing.is_some() {
        return Err(err(StatusCode::CONFLICT, "Email already registered"));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| internal_error("create users", e))?
        .to_string();

    // `email_verified` is TRUE because this is an ADMIN-CREATED account, not a
    // self-registration: the administrator types the address and the password, and
    // no verification mail is ever sent from here. Omitting the column left it at
    // its `NOT NULL DEFAULT FALSE` and issued no `email_token` either — which is
    // exactly the pair `login` treats as "unverified" while the verify route can
    // only match `WHERE email_token = $1`. Every account this door made was
    // therefore unable to sign in the moment SMTP existed, and unable to fix it.
    //
    // Same defect as #100, in a different door, and the trap closed on itself: the
    // welcome mail below goes out over the same SMTP whose presence arms the block,
    // and it says "please log in" while carrying no verification link.
    //
    // The address is ASSERTED here, not proven — the same trade the two other
    // non-self-service doors already make (`oauth`, `whmcs`). Proving it instead
    // would mean issuing a token and sending mail from an admin action, which
    // reintroduces the dependency on SMTP that caused the lockout.
    let user: User = sqlx::query_as(
        "INSERT INTO users (email, password_hash, role, email_verified, os_username) \
         VALUES ($1, $2, $3, TRUE, $4) RETURNING *",
    )
    .bind(&body.email)
    .bind(&hash)
    .bind(role)
    .bind(&os_username)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("create users", e))?;

    // The OS account is created AFTER the row, so that `os_username` is already
    // persisted and the agent's `userdel` has a panel record to belong to. If
    // the agent refuses or fails, the row is deleted again: a panel user that
    // silently has no SSH login would be a promise the create screen did not
    // keep, and a half-created pair is worse than a clean failure the operator
    // can retry.
    if let Some(ref name) = os_username {
        let provisioned = state
            .agents
            .local()
            .post(
                "/os-users/provision",
                Some(serde_json::json!({ "username": name, "password": body.password })),
            )
            .await;
        if let Err(e) = provisioned {
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user.id)
                .execute(&state.db)
                .await;
            return Err(err(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "User was not created: the SSH account '{name}' could not be provisioned ({e})"
                ),
            ));
        }
    }

    tracing::info!("User created by {}: {} ({})", claims.email, user.email, role);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "user.create",
        Some("user"), Some(&user.email), Some(role), ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "user.create", Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&user.email), Some(role), None, "warning",
        claims.key_id,
    ).await;

    // GAP 42: Send welcome email (best-effort, skip silently if SMTP not configured)
    {
        let panel_url = &state.config.base_url;
        let welcome_html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4f46e5;">Welcome to DockPanel</h2>
                <p>Your DockPanel account has been created by an administrator.</p>
                <p><strong>Email:</strong> {}</p>
                <p><strong>Panel URL:</strong> <a href="{}">{}</a></p>
                <p>Please log in and change your password at your earliest convenience.</p>
                <p style="color: #9ca3af; font-size: 12px;">If you did not expect this account, please contact your administrator.</p>
            </div>"#,
            user.email, panel_url, panel_url
        );
        if let Err(e) = crate::services::email::send_email(
            &state.db, &user.email, "Welcome to DockPanel", &welcome_html
        ).await {
            tracing::debug!("Welcome email not sent to {}: {e}", user.email);
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "os_username": user.os_username,
        })),
    ))
}

/// PUT /api/users/{id} — Update user role or password (admin only).
pub async fn update(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {

    // Verify user exists
    let _user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("update users", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    if is_other_admin(&_user.role, id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot modify another administrator's account",
        ));
    }

    // Adding an SSH login to a user that has none. An existing login cannot be
    // renamed through this route: the OS account would have to be torn down and
    // rebuilt (losing its home directory and any keys in it), which is a
    // deliberate operator act, not a field edit.
    let new_os_username = match normalize_os_username(body.os_username.as_deref().unwrap_or(""))? {
        None => None,
        Some(name) => match _user.os_username.as_deref() {
            Some(existing) if existing != name => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "This user already has an SSH account and its login name cannot be \
                     changed here — remove the account and add a new one instead",
                ))
            }
            Some(_) => None,
            None => {
                if os_username_taken(&state.db, &name, Some(id)).await? {
                    return Err(err(StatusCode::CONFLICT, "SSH username already in use"));
                }
                Some(name)
            }
        },
    };
    if new_os_username.is_some() && body.password.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Set a password in the same request to create the SSH account",
        ));
    }

    if let Some(ref role) = body.role {
        if !ASSIGNABLE_ROLES.contains(&role.as_str()) {
            return Err(err(StatusCode::BAD_REQUEST, ASSIGNABLE_ROLES_MSG));
        }
        let role_changed = role.as_str() != _user.role;
        // An admin cannot change their OWN role (mirrors the self-guards on
        // toggle_suspend/remove): prevents accidental self-lockout AND closes the
        // re-escalation path where a stale admin token flips itself back to admin.
        if id == claims.sub && role_changed {
            return Err(err(StatusCode::BAD_REQUEST, "Cannot change your own role"));
        }
        // Only mutate + revoke on an ACTUAL change — a no-op self-submit must not log the
        // caller out. The last-admin guard is folded into the UPDATE's WHERE so a demotion
        // can never orphan the panel of admins (the row updates only if the new role is
        // admin, the current role isn't admin, or more than one admin remains); this is
        // atomic-as-a-statement rather than the check-then-act it replaced. Clearing
        // reseller_id on promotion keeps a tenant-root from staying owned by another
        // reseller (PRIV-03).
        if role_changed {
            let res = sqlx::query(
                "UPDATE users SET role = $1, \
                 reseller_id = CASE WHEN $1 IN ('reseller','admin') THEN NULL ELSE reseller_id END, \
                 updated_at = NOW() \
                 WHERE id = $2 \
                   AND ($1 = 'admin' OR role <> 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1)",
            )
            .bind(role)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update users", e))?;

            if res.rows_affected() == 0 {
                // The user exists (fetched above), so a 0-row update means the last-admin
                // guard in the WHERE blocked the demotion.
                return Err(err(StatusCode::BAD_REQUEST, "Cannot demote the last admin"));
            }

            // Role change must take effect immediately — actually revoke the victim's live
            // token(s). A plain DELETE of user_sessions is a no-op against the stateless JWT.
            crate::routes::auth::revoke_all_user_sessions(&state, id).await;
        }
    }

    if let Some(ref password) = body.password {
        if password.len() < 8 {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Password must be at least 8 characters",
            ));
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| internal_error("update users", e))?
            .to_string();

        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&hash)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update users", e))?;

        // A password change must evict the user's live token(s) — same invariant as
        // reset_password (admin + self-service) and reseller update_user.
        crate::routes::auth::revoke_all_user_sessions(&state, id).await;
    }

    // Provision the new SSH account, if one was requested. The column is written
    // first so a failed provision can simply clear it again, mirroring `create`.
    if let Some(ref name) = new_os_username {
        sqlx::query("UPDATE users SET os_username = $1, updated_at = NOW() WHERE id = $2")
            .bind(name)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| internal_error("update users", e))?;

        let plaintext = body.password.as_deref().unwrap_or("");
        if let Err(e) = state
            .agents
            .local()
            .post(
                "/os-users/provision",
                Some(serde_json::json!({ "username": name, "password": plaintext })),
            )
            .await
        {
            let _ = sqlx::query("UPDATE users SET os_username = NULL WHERE id = $1")
                .bind(id)
                .execute(&state.db)
                .await;
            return Err(err(
                StatusCode::BAD_GATEWAY,
                &format!("The SSH account '{name}' could not be provisioned ({e})"),
            ));
        }
    }

    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "user.update",
        Some("user"), Some(&_user.email), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "user.update", Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&_user.email), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /api/users/{id}/toggle-suspend — Suspend or un-suspend a user (admin only).
///
/// Suspending sets the user's role to "suspended" and records what it was in
/// `users.prior_role`; un-suspending gives that role back. All sessions are
/// invalidated either way.
///
/// The stash used to live in `users.reset_token`, which the public password-reset
/// flow also writes — so a suspended account could destroy the record of its own
/// role by asking for a password reset, and came back as a plain `user`. Both
/// halves of the fix are elsewhere: the column is `prior_role` and the statements
/// are `helpers::suspend_account` / `helpers::unsuspend_account`, shared with the
/// billing webhook so the two cannot drift.
pub async fn toggle_suspend(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if id == claims.sub {
        return Err(err(StatusCode::BAD_REQUEST, "Cannot suspend your own account"));
    }

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("toggle_suspend", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    if is_other_admin(&user.role, id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot suspend another administrator's account",
        ));
    }

    // Both arms write the role themselves, in one statement each, so the stash and
    // the status can never come apart.
    //
    // An administrator restoring through the panel has no deny-list — they may
    // give back anything that was recorded, including `admin`. The billing
    // webhook passes one; see `helpers::unsuspend_account`.
    let (new_role, action) = if user.role == "suspended" {
        match crate::helpers::unsuspend_account(&state, id, &[]).await? {
            Some(role) => (role, "user.unsuspend"),
            // Only reachable for an account suspended by a build that predates
            // `users.prior_role`, whose record the password-reset flow had already
            // overwritten. Guessing here is the defect this whole change removes,
            // so say what happened and name the way out instead.
            None => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "This account was suspended by an older version and the record of its \
                     previous role was lost, so un-suspending cannot know what to give back. \
                     Set the role directly from the user editor — that also lifts the suspension.",
                ))
            }
        }
    } else {
        crate::helpers::suspend_account(&state, id, "").await?;
        ("suspended".to_string(), "user.suspend")
    };

    // Actually revoke the user's live token(s) — a plain DELETE of user_sessions does
    // not invalidate the stateless JWT, so suspension would otherwise be a no-op for
    // up to 2h (and the suspended user could keep whatever role their token carries).
    crate::routes::auth::revoke_all_user_sessions(&state, id).await;

    // Lock or unlock the SSH account's password alongside the panel suspension.
    // A `-L` prefixes the stored hash; an SSH key the person installed keeps
    // working, which is why this is "no new password logins", not "logged out".
    // The panel role has already changed by here, so a failure is reported with
    // that context rather than rolled back.
    if let Some(ref name) = user.os_username {
        let locked = new_role == "suspended";
        if let Err(e) = state
            .agents
            .local()
            .post(
                "/os-users/state",
                Some(serde_json::json!({ "username": name, "locked": locked })),
            )
            .await
        {
            let state_word = if locked { "suspended" } else { "unsuspended" };
            let verb = if locked { "locked" } else { "unlocked" };
            return Err(err(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "The account was {state_word} in the panel, but the SSH account \
                     '{name}' could not be {verb} ({e})"
                ),
            ));
        }
    }

    tracing::info!("{action} by {}: {} -> role={new_role}", claims.email, user.email);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, action,
        Some("user"), Some(&user.email), Some(&new_role), ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, action, Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&user.email), Some(&new_role), None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "email": user.email,
        "role": new_role,
        "suspended": new_role == "suspended",
    })))
}

#[derive(serde::Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

/// POST /api/users/{id}/reset-password — Admin resets a user's password.
///
/// Hashes the new password with Argon2, updates the DB, and invalidates all sessions.
pub async fn reset_password(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ResetPasswordRequest>,
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
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("reset_password", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    if is_other_admin(&user.role, id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot reset another administrator's password",
        ));
    }

    // Hash new password with Argon2
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| internal_error("reset_password", e))?
        .to_string();

    // Update password
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&hash)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("reset_password", e))?;

    // Actually revoke the user's live token(s) so a stolen/active session cannot
    // survive the reset — matches the self-service reset path (auth.rs).
    crate::routes::auth::revoke_all_user_sessions(&state, id).await;

    // Keep the SSH account's password in step — one credential to the person
    // holding it. The panel hash is already written, so a failure is reported
    // honestly rather than rolled back.
    sync_ssh_password(&state, id, &body.password).await?;

    tracing::info!("Password reset by admin {} for user {}", claims.email, user.email);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "user.reset_password",
        Some("user"), Some(&user.email), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "user.reset_password", Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&user.email), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "email": user.email })))
}

/// POST /api/users/{id}/reset-2fa — Clear a user's two-factor enrolment.
///
/// The door of last resort. `auth::twofa_disable` was, until this route existed,
/// the ONLY statement in the panel that clears `totp_enabled`, and it can only be
/// reached by someone who can still produce a code — either from the authenticator
/// they have lost, or from the recovery codes. Which is the trap: every account
/// that enrolled before v2.83.0 holds ten recovery codes it was never shown (the
/// block that draws them sat inside a branch the enable handler cleared in the
/// same breath), so for those accounts BOTH factors are gone at once and there was
/// no panel path back at all — only direct database access. This is that path.
///
/// ⚠ It deliberately refuses to act on the CALLER. Resetting your own 2FA from
/// here would strip the factor with no code presented at all, which is precisely
/// what `twofa_disable` exists to prevent — a hijacked admin session would turn
/// the safeguard off in one click. An administrator who has lost their own
/// authenticator is the case this route cannot serve, and the security-hardening
/// guide states that limit outright rather than papering over it.
///
/// ⚠ An administrator CAN reset another administrator's 2FA — deliberately left
/// outside `is_other_admin`, unlike `update`/`reset_password`/`remove`/
/// `toggle_suspend` below. Clearing a factor does not by itself grant sign-in
/// (the password is untouched), so it is not the same class as those four,
/// which do hand over full control of the target account. It is logged as its
/// own action so it is never silent, and it remains the only recovery path for
/// an administrator who has lost both their authenticator and their recovery
/// codes (see the doc comment above).
pub async fn reset_2fa(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if id == claims.sub {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Use My Account to change your own 2FA — resetting it here would skip the code check",
        ));
    }

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("reset_2fa", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    // A half-finished enrolment leaves `totp_secret` set with `totp_enabled` still
    // false, and that also wants clearing — so the refusal is keyed on there being
    // nothing at all to clear, not on the flag alone.
    if !user.totp_enabled && user.totp_secret.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "This user has no two-factor enrolment to reset",
        ));
    }

    sqlx::query(
        "UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, recovery_codes = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| internal_error("reset_2fa", e))?;

    // Same reasoning as `reset_password`: the account's authentication just
    // changed, so anything already holding a session on it starts again.
    crate::routes::auth::revoke_all_user_sessions(&state, id).await;

    tracing::info!("2FA reset by admin {} for user {}", claims.email, user.email);
    let ip = crate::routes::client_ip(&headers);
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "user.reset_2fa",
        Some("user"), Some(&user.email), None, ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "user.reset_2fa", Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&user.email), None, None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "email": user.email })))
}

/// DELETE /api/users/{id} — Delete a user (admin only, cannot delete self).
pub async fn remove(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {

    if id == claims.sub {
        return Err(err(StatusCode::BAD_REQUEST, "Cannot delete your own account"));
    }

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("remove users", e))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "User not found"))?;

    if is_other_admin(&user.role, id, claims.sub) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Cannot delete another administrator's account",
        ));
    }

    // Remove the OS account first, while the panel row still records the login
    // name. Best-effort on purpose: an unreachable agent must not make a panel
    // user undeletable, so a failure is reported in the response and the log
    // rather than refusing the delete — an operator can then remove the login by
    // hand. Doing it before the row is deleted means a retry after a transient
    // failure still knows which account to remove.
    let os_removed = match user.os_username.as_deref() {
        None => None,
        Some(name) => {
            let path = format!("/os-users/{name}");
            match state.agents.local().delete(&path).await {
                Ok(_) => Some(true),
                Err(e) => {
                    tracing::warn!(
                        "user delete: SSH account '{name}' (user {}) could not be removed: {e}",
                        user.email
                    );
                    Some(false)
                }
            }
        }
    };

    // Revoke the user's live token(s) BEFORE deletion — otherwise the stateless JWT
    // keeps authenticating as a now-nonexistent principal until it expires.
    crate::routes::auth::revoke_all_user_sessions(&state, id).await;

    // ⚠ THE MACHINE MUST CHANGE HANDS BEFORE THE ACCOUNT GOES, OR EVERY SITE ON IT
    // GOES WITH IT.
    //
    // `servers.user_id` is `NOT NULL REFERENCES users(id) ON DELETE CASCADE`
    // (20260312800000_saas_auth.sql:29) and `sites.server_id` is
    // `REFERENCES servers(id) ON DELETE CASCADE` (20260319000000_multi_server.sql:8).
    // Those two edges compose: deleting the account that happens to hold a machine
    // deleted the `servers` row, which deleted EVERY `sites` row on it — every
    // owner's, not just this account's — and with them everything keyed on `site_id`
    // (backups, crons, databases, schedules, deploy configs and logs, wp scans).
    // The handler returned `{"ok": true}` and the files kept serving from disk, so
    // the panel simply forgot an entire server's inventory with no error anywhere.
    //
    // It is not an exotic state. The local row is owned by the FIRST admin by
    // `created_at` (`services/agent.rs:1250`) and every fleet member by whoever
    // registered it (`routes/servers.rs:92`), so retiring the founding
    // administrator — the ordinary reason an operator opens this screen — was the
    // trigger.
    //
    // RE-POINT rather than REFUSE, deliberately. Refusing would be safe for the
    // data and would make that account permanently undeletable: nothing in the
    // panel can re-assign a server today, so the operator would have no way to
    // satisfy the refusal. The caller is an administrator by `AdminUser`, so
    // handing them the machine keeps every site, keeps every `WHERE user_id = $1`
    // read answering, and invents no owner. It is reported in the response and in
    // the activity log rather than done silently.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| internal_error("remove users", e))?;

    let reassigned: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM servers WHERE user_id = $1 ORDER BY is_local DESC, name")
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| internal_error("remove users", e))?;

    if !reassigned.is_empty() {
        sqlx::query("UPDATE servers SET user_id = $1 WHERE user_id = $2")
            .bind(claims.sub)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| internal_error("remove users", e))?;
    }

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| internal_error("remove users", e))?;

    tx.commit()
        .await
        .map_err(|e| internal_error("remove users", e))?;

    let reassigned: Vec<String> = reassigned.into_iter().map(|(n,)| n).collect();

    // Scrub the on-call references no foreign key can reach: rota membership is
    // a UUID[] and escalation routes are opaque strings inside a JSONB blob.
    // Leaving them dangling silently drops pages — `resolve_on_call_user` indexes
    // straight into `members` and hands back the deleted UUID, so the rotation
    // "pages" a principal that no longer exists. The write path already refuses
    // nonexistent members (on_call::validate_members_exist); this makes the
    // delete path reciprocate.
    //
    // Strictly AFTER the delete: several FKs to `users` are NO ACTION (maintenance
    // windows, deploy approvals), so the DELETE can legitimately fail — and this
    // scrub is irreversible. Running it first would strip a still-existing user
    // from every rotation and then return 500, leaving the operator with an
    // "internal error" and a silently gutted on-call schedule.
    crate::routes::on_call::scrub_deleted_user(&state.db, id).await;

    tracing::info!("User deleted by {}: {}", claims.email, user.email);
    if !reassigned.is_empty() {
        tracing::info!(
            "Reassigned {} server(s) from {} to {}: {}",
            reassigned.len(),
            user.email,
            claims.email,
            reassigned.join(", ")
        );
    }
    let ip = crate::routes::client_ip(&headers);
    // The `details` slot, so the reassignment is in the audit trail rather
    // than only in the response the operator may never read. Bound once so
    // both the mutable activity log and the immutable audit log carry the
    // same value.
    let details = if reassigned.is_empty() {
        None
    } else {
        Some(format!("reassigned servers: {}", reassigned.join(", ")))
    };
    activity::log_activity(
        &state.db, claims.sub, &claims.email, "user.delete",
        Some("user"), Some(&user.email), details.as_deref(), ip.as_deref(),
        claims.key_id,
    ).await;
    crate::services::security_hardening::audit_log(
        &state.db, "user.delete", Some(&claims.email), ip.as_deref(),
        Some("user"), Some(&user.email), details.as_deref(), None, "warning",
        claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({
        "ok": true,
        "email": user.email,
        "reassigned_servers": reassigned,
        "os_account_removed": os_removed,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_role_message_names_every_assignable_role() {
        // The list and the sentence describing it are two facts that must agree,
        // and `err` takes a `&str` so the sentence cannot be built from the list.
        // Adding a role to the array and forgetting the message would tell an
        // operator their valid role is invalid.
        for role in ASSIGNABLE_ROLES {
            assert!(
                ASSIGNABLE_ROLES_MSG.contains(role),
                "role {role:?} is assignable but the error message does not name it"
            );
        }
    }

    #[test]
    fn suspended_is_not_directly_assignable() {
        // It is reached through toggle_suspend, which also stashes the previous
        // role. Allowing it here would suspend an account without recording what
        // to restore it to.
        assert!(!ASSIGNABLE_ROLES.contains(&"suspended"));
    }

    #[test]
    fn the_client_role_is_assignable_and_survives_an_unsuspend() {
        // s312 / GitHub #51. Three separate copies of this list existed — create,
        // update and the un-suspend restore — so a role added to the database
        // CHECK and the user editor was still refused by all three.
        //
        // ⚠ This comment used to end by naming the harm outright — "silently
        // downgraded to user when the account is un-suspended, which would hand
        // a client back a role that can create sites" — above an assertion that
        // could not detect it. Membership in this list was never what decided
        // the restore: the stash it read lived in `users.reset_token`, which the
        // public password-reset flow also wrote, so the value was frequently not
        // a role at all and the fallback ran regardless of what this list said.
        // The test described the bug and passed through it (s316; the fifth time
        // a test in this project has spelled its own defect).
        //
        // The restore no longer reads a shared column and no longer falls back
        // to `user`. What this assertion is actually good for is the narrower
        // thing it always proved — that `client` is assignable at all — and the
        // arms that cover the restore now live beside the code, in
        // `helpers::suspend_restore_tests`, plus `tests/suspend-restore-pin-e2e.sh`.
        assert!(ASSIGNABLE_ROLES.contains(&"client"));
    }
}
