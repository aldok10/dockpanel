//! Roles, permissions and tokens for the Mail REST API.
//!
//! The mail API (`panel/mailapi`, the `dockpanel-mailapi` daemon) has two
//! families of route: `/v1/me/*` and `/v1/send`, which act on the caller's own
//! mailbox, and `/v1/domains/*` and `/v1/queue`, which act on the whole server.
//! Until this module existed the second family was gated by an address list in
//! the daemon's environment (`MAILAPI_ADMIN_EMAILS`), which meant a *token* had
//! no say in it: every token minted for a listed mailbox could administer the
//! server, and no token for one could be narrowed. The address was the grant.
//!
//! Here, instead, a mailbox is assigned a **role** (a named bundle of
//! permissions) and every token carries its own **subset** of what the mailbox
//! is allowed. The catalog is deliberately small — two entries — because a
//! capability the mail API does not have is not worth a name:
//!
//!   * `me`     — `/v1/me/*` and `/v1/send` (self-service)
//!   * `domain` — `/v1/domains/*` and `/v1/queue` (server-wide administration)
//!
//! The effective permission set of a mailbox is `role ∪ extras` (or just `me`
//! when it has no grant, so an empty table is still correct), and a token's
//! effective set is its own `permissions` intersected with that *live* value.
//! The intersection is the important half: it means removing `domain` from a
//! role, or moving a mailbox off `mail-admin`, downgrades tokens that are
//! already in somebody's application, without needing to find and revoke them.
//!
//! Tokens live in Postgres (`mail_api_tokens`) and the daemon reads them over the
//! panel's own database connection — not Roundcube's. Roundcube's Mail API tab
//! no longer mints or reads its local table; it lists, through
//! `GET /api/mail/webmail/tokens`, authenticated with a scoped key
//! (`mail_api_webmail_clients`) that can do nothing but read that listing.

use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    Json,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::error::{err, internal_error, ApiError};
use crate::services::activity;
use crate::AppState;

/// The permission catalog. Fixed in code, not a table: a permission has no
/// meaning without a route that checks it, so the two have to ship together.
pub const PERMISSION_CATALOG: [(&str, &str, &str); 2] = [
    (
        "me",
        "Mailbox (self-service)",
        "Send as the mailbox's own address, and read and change only that mailbox: \
         profile, password, forwarding, autoresponder, quota, folders, messages, \
         contacts, contact groups, identities, settings and canned responses.",
    ),
    (
        "domain",
        "Server (mail administration)",
        "Everything `me` allows, plus the server-wide surface: mail domains and their \
         mailboxes and aliases, and the mail queue.",
    ),
];

const PERM_ME: &str = "me";

/// Prefix for a minted mail-API token. Deliberately not `dp_`: that prefix is the
/// panel's own long-lived API key and `panel/mailapi` routes it down a different,
/// backend-delegated path. A mail-API token must never be mistaken for one.
pub const TOKEN_PREFIX: &str = "dpm_";

/// The request header the Roundcube Mail API tab presents its scoped key in.
/// A header of its own, rather than `Authorization`, so it can never be handed to
/// an `AuthUser`-gated route and mistaken for a session or an API key.
const WEBMAIL_KEY_HEADER: &str = "x-mail-webmail-key";

// ── Data types ───────────────────────────────────────────────────────────

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct MailApiRole {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub builtin: bool,
}

#[derive(serde::Serialize)]
pub struct MailApiGrant {
    pub email: String,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub extra_permissions: Vec<String>,
    /// What the mailbox can actually do right now (role ∪ extras, or `me`).
    pub effective_permissions: Vec<String>,
}

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct MailApiToken {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub token_prefix: String,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct PutGrantRequest {
    pub role_id: Option<Uuid>,
    pub extra_permissions: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub email: String,
    pub name: Option<String>,
    /// The subset to grant the token. Omitted means "everything the mailbox has".
    pub permissions: Option<Vec<String>>,
}

// ── Permission helpers ───────────────────────────────────────────────────

fn catalog_index(k: &str) -> Option<usize> {
    PERMISSION_CATALOG.iter().position(|(key, _, _)| *key == k)
}

fn is_known(k: &str) -> bool {
    catalog_index(k).is_some()
}

/// Keep only known permissions, drop duplicates, and order them the way the
/// catalog lists them (so `me` always precedes `domain` and two equal sets
/// compare equal as arrays).
///
/// `domain` implies `me`: the catalog describes `domain` as "everything `me`
/// allows, plus the server-wide surface", so a set that named only `domain` would
/// contradict its own definition. Normalising here means no caller — a role, an
/// extra, or a token's requested subset — can produce that set.
fn canonicalize(mut perms: Vec<String>) -> Vec<String> {
    perms.retain(|p| is_known(p));
    if perms.iter().any(|p| p == "domain") {
        perms.push("me".to_string());
    }
    perms.sort_by_key(|p| catalog_index(p).unwrap_or(usize::MAX));
    perms.dedup();
    perms
}

/// Parse and validate a permission list from a request body.
fn parse_permissions(input: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for p in input {
        let k = p.trim().to_ascii_lowercase();
        if !is_known(&k) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                &format!("Unknown permission `{k}`. Known permissions: me, domain."),
            ));
        }
        out.push(k);
    }
    Ok(canonicalize(out))
}

fn is_subset(sub: &[String], super_: &[String]) -> bool {
    sub.iter().all(|p| super_.contains(p))
}

/// Postgres reports a name collision as SQLSTATE 23505; the codebase's habit is
/// to read it off the message rather than reach for `PgDatabaseError`'s
/// downcast, and this stays with that so the two behave identically.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    let msg = e.to_string();
    msg.contains("unique") || msg.contains("duplicate")
}

/// What a mailbox may do right now: its role's permissions plus any extras, or
/// `me` alone when it has no grant. `me` is a floor — every mailbox can always
/// manage itself — which is why an unconfigured install is still correct.
pub async fn effective_permissions(db: &sqlx::PgPool, email: &str) -> Result<Vec<String>, ApiError> {
    let email = email.trim().to_ascii_lowercase();
    let row: Option<(Option<Vec<String>>, Vec<String>)> = sqlx::query_as(
        "SELECT r.permissions, g.extra_permissions \
           FROM mail_api_grants g \
           LEFT JOIN mail_api_roles r ON r.id = g.role_id \
          WHERE g.email = $1",
    )
    .bind(&email)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("mail_api effective_permissions", e))?;

    let mut perms: Vec<String> = match row {
        Some((role, extra)) => role.unwrap_or_default().into_iter().chain(extra).collect(),
        None => vec![PERM_ME.to_string()],
    };
    if perms.is_empty() {
        perms.push(PERM_ME.to_string());
    }
    Ok(canonicalize(perms))
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// A fresh token secret plus its stored hash and display prefix.
fn mint_token() -> (String, String, String) {
    // Two v4 UUIDs give 256 bits of randomness without a new dependency.
    let raw = format!(
        "{}{}{}",
        TOKEN_PREFIX,
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let hash = sha256_hex(&raw);
    let prefix = raw.chars().take(12).collect::<String>();
    (raw, hash, prefix)
}

fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') || email.len() > 255 {
        return Err(err(StatusCode::BAD_REQUEST, "A mailbox email address is required"));
    }
    Ok(email)
}

// ── Webmail client key ───────────────────────────────────────────────────

/// The scoped credential the Roundcube Mail API tab uses to *list* tokens.
///
/// It can do exactly one thing — read the metadata of tokens for one address —
/// so it is not an `api_keys` row. An `api_keys` row is a full panel credential
/// (the panel does not even read `api_keys.scopes`), and this key is written into
/// a webmail container's config; handing it the panel would be handing a
/// container the panel.
#[derive(Debug)]
pub struct WebmailClient;

impl FromRequestParts<AppState> for WebmailClient {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get(WEBMAIL_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Missing webmail Mail-API key"))?;

        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM mail_api_webmail_clients WHERE key_hash = $1 AND revoked = FALSE",
        )
        .bind(sha256_hex(&key))
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("mail_api webmail client lookup", e))?;
        let id = id.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Invalid webmail Mail-API key"))?;

        // Best-effort usage stamp — a failure here must not fail the request.
        let _ = sqlx::query("UPDATE mail_api_webmail_clients SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await;

        Ok(WebmailClient)
    }
}

/// Mint and store a fresh webmail client key, revoking every earlier one.
///
/// Called when the webmail container is (re)installed, because the raw key is
/// only ever known at mint time: a reinstall therefore rotates the credential,
/// and the just-written container config is the only holder of the new one.
pub async fn rotate_webmail_client(db: &sqlx::PgPool) -> Result<String, ApiError> {
    let (raw, hash, prefix) = {
        let raw = format!(
            "dpw_{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let hash = sha256_hex(&raw);
        let prefix = raw.chars().take(12).collect::<String>();
        (raw, hash, prefix)
    };

    let mut tx = db
        .begin()
        .await
        .map_err(|e| internal_error("mail_api rotate_webmail_client", e))?;
    sqlx::query("UPDATE mail_api_webmail_clients SET revoked = TRUE WHERE revoked = FALSE")
        .execute(&mut *tx)
        .await
        .map_err(|e| internal_error("mail_api rotate_webmail_client", e))?;
    sqlx::query(
        "INSERT INTO mail_api_webmail_clients (key_hash, key_prefix) VALUES ($1, $2)",
    )
    .bind(&hash)
    .bind(&prefix)
    .execute(&mut *tx)
    .await
    .map_err(|e| internal_error("mail_api rotate_webmail_client", e))?;
    tx.commit()
        .await
        .map_err(|e| internal_error("mail_api rotate_webmail_client", e))?;

    Ok(raw)
}

// ── Permissions & roles ──────────────────────────────────────────────────

/// GET /api/mail/api/permissions — the fixed catalog, for a UI to render.
pub async fn list_permissions(AdminUser(_claims): AdminUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "permissions": PERMISSION_CATALOG
            .iter()
            .map(|(key, name, description)| serde_json::json!({
                "key": key, "name": name, "description": description
            }))
            .collect::<Vec<_>>()
    }))
}

/// GET /api/mail/api/roles — every role, plus the catalog in the same response so
/// an editor can render both without a second round trip.
pub async fn list_roles(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let roles: Vec<MailApiRole> = sqlx::query_as(
        "SELECT id, name, description, permissions, builtin \
           FROM mail_api_roles ORDER BY builtin DESC, name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("mail_api list_roles", e))?;

    Ok(Json(serde_json::json!({
        "roles": roles,
        "permissions": PERMISSION_CATALOG
            .iter()
            .map(|(key, name, description)| serde_json::json!({
                "key": key, "name": name, "description": description
            }))
            .collect::<Vec<_>>()
    })))
}

/// POST /api/mail/api/roles — create a custom role.
pub async fn create_role(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Json(body): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<MailApiRole>), ApiError> {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(err(StatusCode::BAD_REQUEST, "Role name must be 1-64 characters"));
    }
    let permissions = parse_permissions(&body.permissions)?;

    let role: MailApiRole = sqlx::query_as(
        "INSERT INTO mail_api_roles (name, description, permissions, builtin) \
         VALUES ($1, $2, $3, FALSE) \
         RETURNING id, name, description, permissions, builtin",
    )
    .bind(name)
    .bind(body.description.as_deref())
    .bind(&permissions)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            err(StatusCode::CONFLICT, "A role with that name already exists")
        } else {
            internal_error("mail_api create_role", e)
        }
    })?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_role_create",
        Some("mail_api_role"),
        Some(&role.name),
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok((StatusCode::CREATED, Json(role)))
}

/// PUT /api/mail/api/roles/{id} — edit a custom role. Builtin roles are refused:
/// their names are what the product docs and the seeded grants mean by them.
pub async fn update_role(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<Json<MailApiRole>, ApiError> {
    let builtin: Option<bool> =
        sqlx::query_scalar("SELECT builtin FROM mail_api_roles WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("mail_api update_role", e))?;
    let builtin = builtin.ok_or_else(|| err(StatusCode::NOT_FOUND, "No such role"))?;
    if builtin {
        return Err(err(
            StatusCode::FORBIDDEN,
            "Built-in roles cannot be edited. Create a custom role instead.",
        ));
    }

    let permissions = match &body.permissions {
        Some(p) => Some(parse_permissions(p)?),
        None => None,
    };
    let name = body.name.as_deref().map(str::trim).filter(|n| !n.is_empty());

    let role: MailApiRole = sqlx::query_as(
        "UPDATE mail_api_roles \
            SET name = COALESCE($2, name), \
                description = COALESCE($3, description), \
                permissions = COALESCE($4, permissions), \
                updated_at = NOW() \
          WHERE id = $1 \
          RETURNING id, name, description, permissions, builtin",
    )
    .bind(id)
    .bind(name)
    .bind(body.description.as_deref())
    .bind(permissions.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            err(StatusCode::CONFLICT, "A role with that name already exists")
        } else {
            internal_error("mail_api update_role", e)
        }
    })?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_role_update",
        Some("mail_api_role"),
        Some(&role.name),
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(role))
}

/// DELETE /api/mail/api/roles/{id} — delete a custom role. Mailboxes assigned to
/// it fall back to the default (`me` only), which is the safe direction.
pub async fn delete_role(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let builtin: Option<bool> =
        sqlx::query_scalar("SELECT builtin FROM mail_api_roles WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("mail_api delete_role", e))?;
    let builtin = builtin.ok_or_else(|| err(StatusCode::NOT_FOUND, "No such role"))?;
    if builtin {
        return Err(err(StatusCode::FORBIDDEN, "Built-in roles cannot be deleted"));
    }

    sqlx::query("DELETE FROM mail_api_roles WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("mail_api delete_role", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_role_delete",
        Some("mail_api_role"),
        None,
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Per-mailbox grants ───────────────────────────────────────────────────

/// GET /api/mail/api/grants — every assignment. The set is small (one row per
/// configured mailbox), so the UI filters client-side rather than paging.
pub async fn list_grants(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rows: Vec<(String, Option<Uuid>, Option<String>, Vec<String>)> = sqlx::query_as(
        "SELECT g.email, g.role_id, r.name, g.extra_permissions \
           FROM mail_api_grants g \
           LEFT JOIN mail_api_roles r ON r.id = g.role_id \
          ORDER BY g.email",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("mail_api list_grants", e))?;

    let mut grants = Vec::with_capacity(rows.len());
    for (email, role_id, role_name, extras) in rows {
        let effective = effective_permissions(&state.db, &email).await?;
        grants.push(MailApiGrant {
            email,
            role_id,
            role_name,
            extra_permissions: extras,
            effective_permissions: effective,
        });
    }
    Ok(Json(serde_json::json!({ "grants": grants })))
}

/// GET /api/mail/api/grants/{email} — one mailbox's assignment, whether or not a
/// row exists (a rowless mailbox answers with the default).
pub async fn get_grant(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = normalize_email(&email)?;
    let row: Option<(Option<Uuid>, Option<String>, Vec<String>)> = sqlx::query_as(
        "SELECT g.role_id, r.name, g.extra_permissions \
           FROM mail_api_grants g \
           LEFT JOIN mail_api_roles r ON r.id = g.role_id \
          WHERE g.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("mail_api get_grant", e))?;

    let (role_id, role_name, extra_permissions) = row.unwrap_or((None, None, Vec::new()));
    let effective = effective_permissions(&state.db, &email).await?;

    Ok(Json(serde_json::json!({
        "email": email,
        "role_id": role_id,
        "role_name": role_name,
        "extra_permissions": extra_permissions,
        "effective_permissions": effective
    })))
}

/// PUT /api/mail/api/grants/{email} — assign a role and/or extra permissions.
///
/// Both fields together replace the mailbox's allowance, so a request that omits
/// `extra_permissions` clears them rather than leaving stale ones behind.
pub async fn put_grant(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(email): Path<String>,
    Json(body): Json<PutGrantRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = normalize_email(&email)?;
    let extras = parse_permissions(body.extra_permissions.as_deref().unwrap_or(&[]))?;
    let extras_csv = extras.join(",");

    if let Some(role_id) = body.role_id {
        let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mail_api_roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| internal_error("mail_api put_grant", e))?;
        if exists.is_none() {
            return Err(err(StatusCode::BAD_REQUEST, "No such role"));
        }
    }

    sqlx::query(
        "INSERT INTO mail_api_grants (email, role_id, extra_permissions, updated_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (email) DO UPDATE \
            SET role_id = EXCLUDED.role_id, \
                extra_permissions = EXCLUDED.extra_permissions, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = NOW()",
    )
    .bind(&email)
    .bind(body.role_id)
    .bind(&extras)
    .bind(claims.sub)
    .execute(&state.db)
    .await
    .map_err(|e| internal_error("mail_api put_grant", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_grant_update",
        Some("mail_account"),
        Some(&email),
        Some(extras_csv.as_str()),
        None,
        claims.key_id,
    )
    .await;

    get_grant(State(state), AdminUser(claims), Path(email)).await
}

/// DELETE /api/mail/api/grants/{email} — back to the default (`me` only).
pub async fn delete_grant(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = normalize_email(&email)?;
    sqlx::query("DELETE FROM mail_api_grants WHERE email = $1")
        .bind(&email)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("mail_api delete_grant", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_grant_delete",
        Some("mail_account"),
        Some(&email),
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ── Tokens ───────────────────────────────────────────────────────────────

fn token_select() -> &'static str {
    "SELECT id, email, name, token_prefix, permissions, created_at, last_used_at, revoked \
       FROM mail_api_tokens"
}

/// GET /api/mail/api/tokens?email= — list token metadata. Never the hash, never
/// the raw value: both are unrecoverable by design.
pub async fn list_tokens(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = match params.get("email") {
        Some(e) if !e.trim().is_empty() => Some(normalize_email(e)?),
        _ => None,
    };

    let tokens: Vec<MailApiToken> = match email {
        Some(email) => {
            sqlx::query_as(&format!("{} WHERE email = $1 ORDER BY created_at DESC", token_select()))
                .bind(email)
                .fetch_all(&state.db)
                .await
        }
        None => {
            sqlx::query_as(&format!("{} ORDER BY created_at DESC", token_select()))
                .fetch_all(&state.db)
                .await
        }
    }
    .map_err(|e| internal_error("mail_api list_tokens", e))?;

    Ok(Json(serde_json::json!({ "tokens": tokens })))
}

/// POST /api/mail/api/tokens — mint a token and return its secret exactly once.
///
/// The requested permissions must be a subset of what the mailbox is allowed
/// right now; asking for more is refused rather than silently widened. Omitting
/// them grants everything the mailbox has.
pub async fn create_token(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Json(body): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let email = normalize_email(&body.email)?;
    let effective = effective_permissions(&state.db, &email).await?;

    let permissions = match &body.permissions {
        None => effective.clone(),
        Some(requested) => {
            let wanted = parse_permissions(requested)?;
            if wanted.is_empty() {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "A token must be granted at least one permission (me or domain).",
                ));
            }
            if !is_subset(&wanted, &effective) {
                return Err(err(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "`{email}` may not be granted {}. Its current permissions are: {}.",
                        wanted.join(", "),
                        if effective.is_empty() { "none".to_string() } else { effective.join(", ") }
                    ),
                ));
            }
            wanted
        }
    };

    let name = body.name.as_deref().map(str::trim).filter(|n| !n.is_empty());
    let (raw, hash, prefix) = mint_token();

    let token: MailApiToken = sqlx::query_as(&format!(
        "INSERT INTO mail_api_tokens (email, name, token_hash, token_prefix, permissions, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {}",
        "id, email, name, token_prefix, permissions, created_at, last_used_at, revoked"
    ))
    .bind(&email)
    .bind(name)
    .bind(&hash)
    .bind(&prefix)
    .bind(&permissions)
    .bind(claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("mail_api create_token", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_token_create",
        Some("mail_account"),
        Some(&email),
        Some(&permissions.join(",")),
        None,
        claims.key_id,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "token": raw,
            "id": token.id,
            "email": token.email,
            "name": token.name,
            "token_prefix": token.token_prefix,
            "permissions": token.permissions,
            "created_at": token.created_at,
        })),
    ))
}

/// DELETE /api/mail/api/tokens/{id} — revoke (kept, not deleted, for the trail).
pub async fn revoke_token(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM mail_api_tokens WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("mail_api revoke_token", e))?;
    let email = email.ok_or_else(|| err(StatusCode::NOT_FOUND, "No such token"))?;

    sqlx::query("UPDATE mail_api_tokens SET revoked = TRUE WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("mail_api revoke_token", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_token_revoke",
        Some("mail_account"),
        Some(&email),
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /api/mail/api/tokens/{id}/rotate — replace the secret, keeping the
/// token's email and permissions. The old secret stops working immediately.
pub async fn rotate_token(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let existing: Option<(String, Option<String>, Vec<String>)> = sqlx::query_as(
        "SELECT email, name, permissions FROM mail_api_tokens WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("mail_api rotate_token", e))?;
    let (email, name, permissions) =
        existing.ok_or_else(|| err(StatusCode::NOT_FOUND, "No such token"))?;

    let (raw, hash, prefix) = mint_token();
    let new: MailApiToken = sqlx::query_as(&format!(
        "INSERT INTO mail_api_tokens (email, name, token_hash, token_prefix, permissions, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {}",
        "id, email, name, token_prefix, permissions, created_at, last_used_at, revoked"
    ))
    .bind(&email)
    .bind(name.as_deref())
    .bind(&hash)
    .bind(&prefix)
    .bind(&permissions)
    .bind(claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| internal_error("mail_api rotate_token", e))?;

    sqlx::query("UPDATE mail_api_tokens SET revoked = TRUE WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("mail_api rotate_token", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_token_rotate",
        Some("mail_account"),
        Some(&email),
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "token": raw,
        "id": new.id,
        "email": new.email,
        "name": new.name,
        "token_prefix": new.token_prefix,
        "permissions": new.permissions,
        "created_at": new.created_at,
    })))
}

/// GET /api/mail/webmail/tokens?email= — what the Roundcube Mail API tab calls.
///
/// Authenticated by the container's scoped key, and answered with metadata for
/// the named address only. It cannot mint, revoke or read a secret.
pub async fn webmail_tokens(
    State(state): State<AppState>,
    _client: WebmailClient,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = params
        .get("email")
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "An `email` query parameter is required"))?;
    let email = normalize_email(email)?;

    let tokens: Vec<MailApiToken> = sqlx::query_as(&format!(
        "{} WHERE email = $1 AND revoked = FALSE ORDER BY created_at DESC",
        token_select()
    ))
    .bind(&email)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("mail_api webmail_tokens", e))?;

    Ok(Json(serde_json::json!({ "tokens": tokens })))
}
