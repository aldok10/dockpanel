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
//! is allowed. The catalog names four capabilities, so the two halves of
//! `/v1/me/*` are separable and a token need not be all-or-nothing:
//!
//!   * `send`   — `/v1/send` and `/emails`
//!   * `read`   — the `GET` half of `/v1/me/*`
//!   * `write`  — the mutating half of `/v1/me/*` (implies `read`)
//!   * `domain` — `/v1/domains/*` and `/v1/queue` (implies all three above)
//!
//! `me`, the earlier single self-service entry, is accepted as an alias that
//! expands to `send`+`read`+`write`, so nothing minted before the split is
//! narrowed.
//!
//! The effective permission set of a mailbox is `role ∪ extras` (or the
//! self-service three when it has no grant, so an empty table is still correct),
//! and a token's effective set is its own `permissions` intersected with that
//! *live* value.
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
pub const PERMISSION_CATALOG: [(&str, &str, &str); 4] = [
    (
        "send",
        "Send",
        "Send as the mailbox's own address: `POST /v1/send` and `POST /emails`. Nothing \
         else — this token can mail out but cannot read a mailbox, change one, or touch \
         the server.",
    ),
    (
        "read",
        "Read",
        "Read the mailbox: profile, quota, folders, messages, contacts, contact groups, \
         identities, settings and canned responses. Every `GET /v1/me/*` route.",
    ),
    (
        "write",
        "Manage",
        "Change the mailbox: its profile and password, forwarding, autoresponder, folders, \
         messages (save, flag, move, delete, empty Trash), contacts, contact groups, \
         identities, settings and canned responses. Implies `read`.",
    ),
    (
        "domain",
        "Server (mail administration)",
        "Everything `send`, `read` and `write` allow, plus the server-wide surface: mail \
         domains and their mailboxes and aliases, and the mail queue.",
    ),
];

const PERM_SEND: &str = "send";
const PERM_READ: &str = "read";
const PERM_WRITE: &str = "write";
const PERM_DOMAIN: &str = "domain";

/// What a mailbox may do when it has no grant at all: the whole of self-service,
/// which is what the old single `me` entry meant.
fn self_service() -> Vec<String> {
    vec![
        PERM_SEND.to_string(),
        PERM_READ.to_string(),
        PERM_WRITE.to_string(),
    ]
}

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
    /// When the token stops being accepted. `None` means it never does.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
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
    /// Lifetime in days. Omitted (or `null`) means the token never expires.
    pub expires_in_days: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdateTokenRequest {
    pub name: Option<String>,
    /// `0` (or negative) clears the expiry; a positive number sets it that many
    /// days out; the field left out of the body leaves the current expiry alone.
    pub expires_in_days: Option<i64>,
}

// ── Permission helpers ───────────────────────────────────────────────────

fn catalog_index(k: &str) -> Option<usize> {
    PERMISSION_CATALOG.iter().position(|(key, _, _)| *key == k)
}

fn is_known(k: &str) -> bool {
    catalog_index(k).is_some()
}

/// Keep only known permissions, drop duplicates, and order them the way the
/// catalog lists them (so `send` always precedes `read`, and two equal sets
/// compare equal as arrays).
///
/// Two implications complete a set here, so that no caller — a role, an extra,
/// or a token's requested subset — can produce a set that contradicts the
/// catalog's own wording:
///
///   * `write` implies `read`: a credential allowed to change a mailbox but not
///     to look at it is not a combination any route needs, and the read half of a
///     change (fetch, then patch) is how every mutating handler here works.
///   * `domain` implies `send`+`read`+`write`: the catalog describes it as
///     "everything those allow, plus the server-wide surface".
///
/// `me` is the pre-split spelling of `send`+`read`+`write`, accepted as an alias
/// so a row minted before the catalog grew is neither dropped nor narrowed.
fn canonicalize(mut perms: Vec<String>) -> Vec<String> {
    if perms.iter().any(|p| p == "me") {
        perms.retain(|p| p != "me");
        perms.push(PERM_SEND.to_string());
        perms.push(PERM_READ.to_string());
        perms.push(PERM_WRITE.to_string());
    }
    perms.retain(|p| is_known(p));
    if perms.iter().any(|p| p == PERM_WRITE) {
        perms.push(PERM_READ.to_string());
    }
    if perms.iter().any(|p| p == PERM_DOMAIN) {
        perms.push(PERM_SEND.to_string());
        perms.push(PERM_READ.to_string());
        perms.push(PERM_WRITE.to_string());
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
        // `me` is not in the catalog any more, but it is the name every token
        // minted before the split carries, so it is still accepted (and expanded
        // by `canonicalize`) rather than rejected with a puzzling error.
        if !is_known(&k) && k != "me" {
            return Err(err(
                StatusCode::BAD_REQUEST,
                &format!("Unknown permission `{k}`. Known permissions: send, read, write, domain."),
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
/// the self-service set when it has no grant. Self-service is a floor — every
/// mailbox can always manage itself — which is why an unconfigured install is
/// still correct.
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
        None => self_service(),
    };
    if perms.is_empty() {
        perms = self_service();
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

/// Turn a requested lifetime into an absolute expiry.
///
/// `None` is "never expires". A value is bounded so a slipped keystroke cannot
/// mint a credential that outlives the database — ten years is already far past
/// any operational reason to keep one.
fn expiry_from_days(days: Option<i64>) -> Result<Option<chrono::DateTime<chrono::Utc>>, ApiError> {
    match days {
        None => Ok(None),
        Some(d) if d <= 0 => Err(err(
            StatusCode::BAD_REQUEST,
            "expires_in_days must be a positive number of days (omit the field for no expiry)",
        )),
        Some(d) if d > 3650 => Err(err(
            StatusCode::BAD_REQUEST,
            "expires_in_days must be at most 3650 (ten years)",
        )),
        Some(d) => Ok(Some(chrono::Utc::now() + chrono::Duration::days(d))),
    }
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
    "SELECT id, email, name, token_prefix, permissions, created_at, expires_at, last_used_at, revoked \
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
                    "A token must be granted at least one permission (send, read, write or domain).",
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
    let expires_at = expiry_from_days(body.expires_in_days)?;
    let (raw, hash, prefix) = mint_token();

    let token: MailApiToken = sqlx::query_as(&format!(
        "INSERT INTO mail_api_tokens (email, name, token_hash, token_prefix, permissions, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {}",
        "id, email, name, token_prefix, permissions, created_at, expires_at, last_used_at, revoked"
    ))
    .bind(&email)
    .bind(name)
    .bind(&hash)
    .bind(&prefix)
    .bind(&permissions)
    .bind(expires_at)
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
            "expires_at": token.expires_at,
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
/// token's email, permissions and expiry. The old secret stops working
/// immediately.
pub async fn rotate_token(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let existing: Option<(String, Option<String>, Vec<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT email, name, permissions, expires_at FROM mail_api_tokens WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("mail_api rotate_token", e))?;
    let (email, name, permissions, expires_at) =
        existing.ok_or_else(|| err(StatusCode::NOT_FOUND, "No such token"))?;

    let (raw, hash, prefix) = mint_token();
    let new: MailApiToken = sqlx::query_as(&format!(
        "INSERT INTO mail_api_tokens (email, name, token_hash, token_prefix, permissions, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {}",
        "id, email, name, token_prefix, permissions, created_at, expires_at, last_used_at, revoked"
    ))
    .bind(&email)
    .bind(name.as_deref())
    .bind(&hash)
    .bind(&prefix)
    .bind(&permissions)
    .bind(expires_at)
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
        "expires_at": new.expires_at,
    })))
}

/// PUT /api/mail/api/tokens/{id} — rename a token and/or change its expiry.
/// The secret is untouched; rotate is what replaces that.
///
/// `expires_in_days` is a tri-state on purpose: left out, the current expiry
/// stands; a positive number sets a new one that many days out; `0` clears it
/// (never expires). A handful of calls in a UI is all this serves, so the three
/// states are worth spelling out rather than inventing a nested `Option`.
pub async fn update_token(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateTokenRequest>,
) -> Result<Json<MailApiToken>, ApiError> {
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM mail_api_tokens WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| internal_error("mail_api update_token", e))?;
    let email = email.ok_or_else(|| err(StatusCode::NOT_FOUND, "No such token"))?;

    let name = body.name.as_deref().map(str::trim).filter(|n| !n.is_empty());

    // `None` leaves the column alone; `Some(None)` clears it; `Some(Some(_))`
    // sets it. Validating before the UPDATE keeps a rejected value from having
    // already renamed the token.
    let expiry: Option<Option<chrono::DateTime<chrono::Utc>>> = match body.expires_in_days {
        None => None,
        Some(d) if d <= 0 => Some(None),
        Some(d) => Some(expiry_from_days(Some(d))?),
    };

    let token: MailApiToken = match expiry {
        None => sqlx::query_as(&format!(
            "UPDATE mail_api_tokens SET name = COALESCE($2, name) WHERE id = $1 RETURNING {}",
            "id, email, name, token_prefix, permissions, created_at, expires_at, last_used_at, revoked"
        ))
        .bind(id)
        .bind(name)
        .fetch_one(&state.db)
        .await,
        Some(expires_at) => sqlx::query_as(&format!(
            "UPDATE mail_api_tokens SET name = COALESCE($2, name), expires_at = $3 \
              WHERE id = $1 RETURNING {}",
            "id, email, name, token_prefix, permissions, created_at, expires_at, last_used_at, revoked"
        ))
        .bind(id)
        .bind(name)
        .bind(expires_at)
        .fetch_one(&state.db)
        .await,
    }
    .map_err(|e| internal_error("mail_api update_token", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "mail.api_token_update",
        Some("mail_account"),
        Some(&email),
        None,
        None,
        claims.key_id,
    )
    .await;

    Ok(Json(token))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// `domain` is defined as the whole self-service set *plus* the server-wide
    /// surface, and `write` as every change a mailbox can make — which a route
    /// also has to be able to read first. A set naming only the narrow half is
    /// completed rather than accepted, in the catalog's order so that two equal
    /// sets serialize as two equal arrays.
    #[test]
    fn canonicalize_completes_the_implied_permissions() {
        assert_eq!(
            canonicalize(keys(&["domain"])),
            keys(&["send", "read", "write", "domain"])
        );
        assert_eq!(canonicalize(keys(&["write"])), keys(&["read", "write"]));
        assert_eq!(canonicalize(keys(&["read"])), keys(&["read"]));
        assert_eq!(
            canonicalize(keys(&["write", "send"])),
            keys(&["send", "read", "write"])
        );
    }

    /// `me` predates the split. It is expanded, not dropped: a grant, an extra or
    /// a token minted against it keeps every self-service right it had and gains
    /// nothing server-wide. Anything unrecognised is dropped instead — the same
    /// thing `canonicalize` does with a typo.
    #[test]
    fn me_is_the_legacy_spelling_of_self_service() {
        assert_eq!(canonicalize(keys(&["me"])), keys(&["send", "read", "write"]));
        assert_eq!(
            canonicalize(keys(&["me", "domain"])),
            keys(&["send", "read", "write", "domain"])
        );
        assert_eq!(canonicalize(keys(&["nonsense", "read"])), keys(&["read"]));
        // ...and the old spelling still parses, in any case a client sends it.
        assert_eq!(
            parse_permissions(&keys(&[" Me "])).unwrap(),
            keys(&["send", "read", "write"])
        );
    }

    /// An unknown permission is refused rather than silently dropped: a role
    /// built on a typo would otherwise look like it had granted something.
    #[test]
    fn an_unknown_permission_is_refused() {
        let (status, body) =
            parse_permissions(&keys(&["rda"])).expect_err("`rda` is not a permission");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let msg = body.0["error"].as_str().unwrap_or_default();
        assert!(msg.contains("rda"), "{msg}");
        assert!(msg.contains("send, read, write, domain"), "{msg}");
    }

    /// Minting must never be able to ask for more than the mailbox allows, while
    /// a narrower subset is exactly the point of the feature.
    #[test]
    fn a_token_cannot_exceed_its_mailbox() {
        let allowance = keys(&["send", "read", "write"]);
        assert!(is_subset(&keys(&["read"]), &allowance));
        assert!(is_subset(&keys(&["send"]), &allowance));
        assert!(!is_subset(&keys(&["domain"]), &allowance));
        assert!(!is_subset(
            &keys(&["send", "read", "write", "domain"]),
            &allowance
        ));
    }

    /// A lifetime is optional, and a mistake in one is refused rather than
    /// minting a credential that outlives the database.
    #[test]
    fn expiry_is_optional_and_bounded() {
        assert_eq!(expiry_from_days(None).unwrap(), None);
        assert!(expiry_from_days(Some(0)).is_err());
        assert!(expiry_from_days(Some(-5)).is_err());
        assert!(expiry_from_days(Some(3651)).is_err());

        let at = expiry_from_days(Some(30)).unwrap().expect("30 days is an expiry");
        let now = chrono::Utc::now();
        assert!(at > now + chrono::Duration::days(29), "{at}");
        assert!(at < now + chrono::Duration::days(31), "{at}");
    }
}
