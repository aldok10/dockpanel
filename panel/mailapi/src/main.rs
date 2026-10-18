//! dockpanel-mailapi — a small REST API for sending and managing mail on the
//! host, authenticated with a per-mailbox token issued from Roundcube.
//!
//! Why a host-side daemon instead of sending from the Roundcube plugin: an
//! offline REST caller has no Roundcube session, and Roundcube only ever holds a
//! mailbox password inside that session. So a token-authenticated request cannot
//! reuse Roundcube's authenticated submission path. This daemon instead injects
//! through the loopback smtpd, which is already in Postfix's `mynetworks`, so
//! `smtpd_milters` still signs with DKIM and the envelope sender is the real
//! mailbox the token belongs to. A copy of each sent message is filed into the
//! sender's Sent folder with `doveadm`, so it shows up in Roundcube exactly as
//! if the user had sent it there.
//!
//! Auth accepts either:
//!   * a mail-API token minted in the panel (its sha256 looked up in the panel's
//!     `mail_api_tokens` table, over the same Postgres the panel uses), or
//!   * a token minted by the bundled Roundcube plugin before the panel took
//!     over — its sha256 is looked up in Roundcube's SQLite
//!     `dockpanel_mailapi_tokens` table and it is granted `me` and nothing more, or
//!   * a JWT signed with the panel's `JWT_SECRET` (HS256) that carries an
//!     `email` claim — the "internal" path used by the panel itself, or
//!   * a panel API key (`dp_…`), which is forwarded to the backend untouched so
//!     the panel's own authorization decides what it may do.
//!
//! A token identifies a MAILBOX and carries its own set of PERMISSIONS, drawn
//! from a two-entry catalog:
//!   * `me`     — `/v1/me/*` and `/v1/send`; manage only the token's own mailbox
//!   * `domain` — `/v1/domains/*` and `/v1/queue`; manage the whole server
//!
//! The token's permissions are an upper bound, not a floor: they are intersected
//! on every request with what the mailbox is *currently* allowed (its role in the
//! panel, `panel/backend/src/routes/mail_api.rs`). That is what makes a `/me`-only
//! token stay `/me`-only even for an administrator mailbox, and what makes
//! removing `domain` from a mailbox take effect on tokens already handed out.
//! Management is not reimplemented here: the daemon calls the panel backend's
//! existing `/api/mail/*` routes over loopback, so there is one implementation of
//! each operation and one place where its authorization rule lives. The `dp_` key
//! it presents for that leg is `MAILAPI_BACKEND_API_KEY` — a service credential,
//! not the caller's.
//!
//! ⚠ `MAILAPI_BACKEND_API_KEY` must belong to an ADMIN user: the backend gates
//! domain creation, updates, deletion and the mail queue on `AdminUser`, so a
//! non-admin key makes those routes 403 even though this daemon asked for them.
//! Self-service calls do not need admin rights, but they ride the same
//! credential, which is why the daemon restricts them to the caller's own
//! mailbox itself rather than trusting the backend to.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use lettre::message::{header::ContentType, header::MIME_VERSION_1_0, Mailbox, MultiPart};
use lettre::Message;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use utoipa_swagger_ui::SwaggerUi;

mod roundcube;

/// A recipient list that may arrive either as a bare string or an array.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SendRequest {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<OneOrMany>,
    #[serde(default)]
    cc: Option<OneOrMany>,
    #[serde(default)]
    bcc: Option<OneOrMany>,
    #[serde(default)]
    reply_to: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
}

#[derive(Clone)]
struct Config {
    listen: String,
    /// Path to the Postfix `sendmail` wrapper. Injection through it is trusted
    /// (it runs as the daemon's own user, which is in Postfix `mynetworks`), so
    /// the loopback smtpd's mandatory STARTTLS never gets in the way, and
    /// `non_smtpd_milters` still DKIM-signs the message.
    sendmail: String,
    roundcube_db: Option<PathBuf>,
    /// Extra static tokens (raw token -> sender email), for host-local callers.
    static_tokens: HashMap<String, String>,
    jwt_secret: Option<String>,
    save_sent: bool,
    /// The panel backend's base URL, for `/api/mail/*` management calls. Loopback
    /// by default; the daemon and the backend live on the same host.
    backend_url: String,
    /// The panel API key (`dp_…`) this daemon presents to the backend. Must
    /// belong to an ADMIN user — see the module comment.
    backend_api_key: Option<String>,
    /// The panel's Postgres. Mail-API tokens and their permissions live there now
    /// (`mail_api_tokens`, `mail_api_grants`, `mail_api_roles`), and this daemon
    /// reads them directly rather than calling back into the panel for every
    /// request. `None` disables the panel-token path in favour of the legacy
    /// Roundcube table only.
    database_url: Option<String>,
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    /// One pooled client for the loopback calls into the panel backend.
    http: reqwest::Client,
    /// The panel's Postgres, when `DATABASE_URL` is set. `None` means only the
    /// legacy Roundcube token table can authenticate a mailbox token.
    pg: Option<sqlx::PgPool>,
}

#[derive(Debug)]
struct ApiErr(StatusCode, String);

impl ApiErr {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiErr(status, msg.into())
    }
    fn bad(msg: impl Into<String>) -> Self {
        ApiErr(StatusCode::BAD_REQUEST, msg.into())
    }
    fn unauthorized(msg: impl Into<String>) -> Self {
        ApiErr(StatusCode::UNAUTHORIZED, msg.into())
    }
    fn forbidden(msg: impl Into<String>) -> Self {
        ApiErr(StatusCode::FORBIDDEN, msg.into())
    }
    fn not_found(msg: impl Into<String>) -> Self {
        ApiErr(StatusCode::NOT_FOUND, msg.into())
    }
    fn internal(msg: impl Into<String>) -> Self {
        ApiErr(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/// Parse a `KEY=VALUE` env file, ignoring comments and blank lines.
fn parse_env_file(path: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

impl Config {
    fn load() -> Config {
        let mut env = parse_env_file("/etc/dockpanel/mailapi.env");
        // The panel's own env carries JWT_SECRET; mailapi.env wins when it
        // overrides anything.
        for (k, v) in parse_env_file("/etc/dockpanel/api.env") {
            env.entry(k).or_insert(v);
        }
        let get = |k: &str| env.get(k).cloned();

        let static_tokens = get("MAILAPI_STATIC_TOKENS")
            .map(|s| {
                s.split(',')
                    .filter_map(|pair| pair.split_once(':'))
                    .map(|(t, e)| (t.to_string(), e.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Config {
            listen: get("MAILAPI_LISTEN").unwrap_or_else(|| "127.0.0.1:8081".into()),
            sendmail: get("MAILAPI_SENDMAIL").unwrap_or_else(|| "/usr/sbin/sendmail".into()),
            roundcube_db: get("MAILAPI_ROUNDCUBE_DB")
                .or_else(|| Some("/var/lib/dockpanel/apps/roundcube/var/roundcube/db/sqlite.db".into()))
                .map(PathBuf::from),
            static_tokens,
            jwt_secret: get("MAILAPI_JWT_SECRET").or_else(|| get("JWT_SECRET")),
            save_sent: get("MAILAPI_SAVE_SENT").map(|v| v != "false").unwrap_or(true),
            backend_url: get("MAILAPI_BACKEND_URL")
                .unwrap_or_else(|| "http://127.0.0.1:3080".into()),
            backend_api_key: get("MAILAPI_BACKEND_API_KEY"),
            database_url: get("DATABASE_URL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if let Some(rest) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
            return Some(rest.trim().to_string());
        }
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// A locally unique `Message-ID` for the sender's domain.
fn generate_message_id(identity: &str) -> String {
    let domain = identity.split('@').nth(1).unwrap_or("localhost");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{nanos}-{}-{identity}", std::process::id());
    let hash = sha256_hex(&seed);
    format!("<{nanos}.{}@{domain}>", &hash[..16])
}

/// The permissions a mail-API token can hold.
///
/// Deliberately two booleans rather than a `Vec<String>`: there are exactly two
/// entries, and a typo in a lookup is then a compile error instead of a
/// permission that silently never matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Permissions {
    /// `/v1/me/*` and `/v1/send` — manage the token's own mailbox.
    me: bool,
    /// `/v1/domains/*` and `/v1/queue` — manage the whole server.
    domain: bool,
}

impl Permissions {
    /// What a credential the panel itself vouches for may do: a panel JWT, a
    /// `dp_` key the backend has already authorised, or a host-local static
    /// token. None of these is a mailbox token — they belong to the panel and to
    /// root on the box, so they keep the whole surface.
    const ALL: Permissions = Permissions { me: true, domain: true };

    /// A token minted by the old Roundcube plugin: `me`, and nothing wider.
    const ME: Permissions = Permissions { me: true, domain: false };

    fn has(self, key: &str) -> bool {
        match key {
            "me" => self.me,
            "domain" => self.domain,
            _ => false,
        }
    }

    fn names(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.me {
            out.push("me");
        }
        if self.domain {
            out.push("domain");
        }
        out
    }
}

/// Credentials the daemon can resolve without the panel: the panel's JWT and the
/// host-local static tokens, each returning the mailbox and the full permission
/// set. The panel-minted token path is separate because it is async.
fn resolve_local_identity(cfg: &Config, token: &str) -> Option<(String, Permissions)> {
    // 1. JWT signed with the panel secret, carrying an email claim. This is the
    //    panel's own internal path — it vouches for the address.
    if let Some(secret) = &cfg.jwt_secret {
        if token.matches('.').count() == 2 {
            let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            val.validate_exp = false;
            if let Ok(data) = jsonwebtoken::decode::<Value>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
                &val,
            ) {
                for key in ["email", "mail", "sub"] {
                    if let Some(email) = data.claims.get(key).and_then(|v| v.as_str()) {
                        if email.contains('@') {
                            return Some((email.to_lowercase(), Permissions::ALL));
                        }
                    }
                }
            }
        }
    }

    // 2. Static host-local token, listed in the daemon's own environment. Root on
    //    the box already has everything the daemon can reach.
    if let Some((_, email)) = cfg.static_tokens.iter().find(|(t, _)| t.as_str() == token) {
        return Some((email.to_lowercase(), Permissions::ALL));
    }

    None
}

/// Look up `token_hash` in Roundcube's **legacy** token table.
///
/// Tokens minted by the old plugin (before the panel took over) still
/// authenticate here, and they are granted `me` and nothing more — deliberately.
/// The old model decided a token's power from the mailbox's *address*, so a row
/// in this table was potentially a server-wide one; refusing to read anything
/// wider than `me` out of it is what stops the old behaviour surviving the
/// change. A mailbox that wants `domain` mints a panel token.
fn lookup_roundcube_token(cfg: &Config, token_hash: &str) -> Option<String> {
    let db = cfg.roundcube_db.as_ref()?;
    if !db.exists() {
        return None;
    }
    let conn = rusqlite::Connection::open(db).ok()?;
    conn.busy_timeout(Duration::from_secs(5)).ok()?;
    let email: Option<String> = conn
        .query_row(
            "SELECT email FROM dockpanel_mailapi_tokens WHERE token_hash = ?1 AND revoked = 0",
            [token_hash],
            |row| row.get(0),
        )
        .ok();
    if email.is_some() {
        // Best-effort usage stamp; a locked DB must never fail the send.
        let _ = conn.execute(
            "UPDATE dockpanel_mailapi_tokens SET last_used_at = datetime('now') WHERE token_hash = ?1",
            [token_hash],
        );
    }
    email
}

/// Intersect what a token was granted with what its mailbox is allowed now.
///
/// Split out from `lookup_panel_token` so the rule can be pinned without a
/// database: this is the function that makes a revocation immediate, and it is
/// the only place the two lists meet.
fn intersect_token_permissions(token_perms: &[String], allowance: &[String]) -> Permissions {
    let mut effective = Permissions::default();
    for key in token_perms {
        if !allowance.iter().any(|a| a == key) {
            continue;
        }
        match key.as_str() {
            "me" => effective.me = true,
            "domain" => effective.domain = true,
            _ => {}
        }
    }
    effective
}

/// Look up a panel-minted token by its hash, returning the mailbox and the
/// token's **effective** permissions.
///
/// Effective = the token's own set ∩ the mailbox's current allowance. The
/// intersection is the point of the whole design: a token that was granted
/// `domain` stops having it the moment the mailbox's role stops granting it, so
/// revoking does not require finding every token that was handed out.
async fn lookup_panel_token(
    pg: &sqlx::PgPool,
    token_hash: &str,
) -> Result<Option<(String, Permissions)>, sqlx::Error> {
    let row: Option<(String, Vec<String>, Option<Vec<String>>, Option<Vec<String>>)> = sqlx::query_as(
        "SELECT t.email, t.permissions, r.permissions, g.extra_permissions \
           FROM mail_api_tokens t \
           LEFT JOIN mail_api_grants g ON g.email = t.email \
           LEFT JOIN mail_api_roles r ON r.id = g.role_id \
          WHERE t.token_hash = $1 AND t.revoked = FALSE",
    )
    .bind(token_hash)
    .fetch_optional(pg)
    .await?;

    let Some((email, token_perms, role_perms, extra)) = row else {
        return Ok(None);
    };

    // No grant row at all is the default allowance — `me` alone, the same rule
    // the panel applies. A grant whose role was deleted falls back the same way.
    let allowance: Vec<String> = match (role_perms, extra) {
        (None, None) => vec!["me".to_string()],
        (role, extra) => role
            .unwrap_or_default()
            .into_iter()
            .chain(extra.unwrap_or_default())
            .collect(),
    };

    let effective = intersect_token_permissions(&token_perms, &allowance);

    // Best-effort usage stamp; a lock or a blip must never fail the request.
    let _ = sqlx::query("UPDATE mail_api_tokens SET last_used_at = NOW() WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pg)
        .await;

    Ok(Some((email, effective)))
}

/// What a request's credential resolves to.
struct Principal {
    /// The mailbox the credential speaks for.
    email: String,
    /// What this particular credential may do. Always the *intersection* of what
    /// the token asked for and what the mailbox is currently allowed.
    permissions: Permissions,
    /// A panel `dp_` key the caller supplied. When set, backend calls carry this
    /// key instead of the service one, so the panel authorises the caller as
    /// whoever minted it — which is strictly narrower than the service key.
    passthrough_key: Option<String>,
}

impl Principal {
    fn domain(&self) -> Option<&str> {
        self.email.split_once('@').map(|(_, d)| d)
    }
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, ApiErr> {
    Ok(principal(state, headers).await?.email)
}

/// Resolve a bearer credential into the mailbox it speaks for and the
/// permissions it holds.
///
/// Four credential classes, and the difference between them is the whole
/// authorization story:
///   * a panel `dp_` key — the panel already knows what its user may do, so it
///     is forwarded untouched and the backend decides;
///   * a panel JWT or a host-local static token — trusted, full surface;
///   * a panel-minted mail-API token — a mailbox plus its own permissions,
///     intersected with what the mailbox is allowed right now;
///   * a legacy Roundcube token — a mailbox, `me` only.
async fn principal(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiErr> {
    let token = bearer_token(headers)
        .ok_or_else(|| ApiErr::unauthorized("Missing API token (Authorization: Bearer <token>)"))?;

    if token.starts_with("dp_") {
        let email = backend_me(state, &token).await?;
        return Ok(Principal {
            email,
            permissions: Permissions::ALL,
            passthrough_key: Some(token),
        });
    }

    // The panel's own internal credentials, resolved offline.
    if let Some((email, permissions)) = resolve_local_identity(&state.cfg, &token) {
        return Ok(Principal {
            email,
            permissions,
            passthrough_key: None,
        });
    }

    let hash = sha256_hex(&token);

    // The supported path: a token minted in the panel.
    if let Some(pg) = &state.pg {
        match lookup_panel_token(pg, &hash).await {
            Ok(Some((email, permissions))) => {
                return Ok(Principal {
                    // The panel stores addresses lowercased; the daemon lowercases
                    // anyway so a mixed-case row cannot fail `send`'s sender check.
                    email: email.to_lowercase(),
                    permissions,
                    passthrough_key: None,
                });
            }
            Ok(None) => {}
            Err(e) => {
                // Fail closed. Falling through to the legacy table on a database
                // error would still authenticate the token — as `me` — and a
                // broken connection would then look like a token that had been
                // narrowed, which is exactly the outcome to refuse.
                tracing::error!("panel mail-API token lookup failed: {e}");
                return Err(ApiErr::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The panel's mail token store is unavailable",
                ));
            }
        }
    }

    // The old Roundcube table: `me` only, never wider.
    if let Some(email) = lookup_roundcube_token(&state.cfg, &hash) {
        return Ok(Principal {
            email: email.to_lowercase(),
            permissions: Permissions::ME,
            passthrough_key: None,
        });
    }

    Err(ApiErr::unauthorized("Invalid or revoked API token"))
}

/// Refuse a route the caller's token was not granted.
///
/// The refusal names the permission and where to grant it, because the common
/// case is an operator who minted a `/me`-only token and then pointed it at a
/// management route — the fix is a grant in the panel, not a different token.
fn require_permission(p: &Principal, permission: &str) -> Result<(), ApiErr> {
    if p.permissions.has(permission) {
        return Ok(());
    }
    let msg = match permission {
        "domain" => format!(
            "{} may not administer the whole server: its token was not granted the `domain` permission. Grant it in the panel under Mail -> Mail API, then mint a token with it.",
            p.email
        ),
        other => format!(
            "{} may not use this route: its token was not granted the `{other}` permission.",
            p.email
        ),
    };
    Err(ApiErr::forbidden(msg))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "dockpanel-mailapi" }))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(json!({
        "email": p.email,
        "domain": p.domain(),
        "permissions": p.permissions.names(),
    })))
}

/// Everything a caller may put on a message, resolved and validated.
///
/// One type for both doors: `/v1/send` injects the result, and the append route
/// writes it into a folder without sending it — that is how a draft is saved.
/// Keeping them on one builder is what stops a saved draft from drifting from
/// the message that would have been sent; the MIME-Version header below is one
/// such detail that only the send path had any reason to care about until
/// drafts existed.
struct Draft {
    /// The mailbox the token belongs to: the only address this message may come
    /// from, and the one a message that names no `from` is sent as.
    identity: String,
    sender: Mailbox,
    reply_to: Option<Mailbox>,
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    bcc: Vec<Mailbox>,
    subject: String,
    text: Option<String>,
    html: Option<String>,
}

impl Draft {
    /// Resolve a request against the mailbox the token belongs to.
    ///
    /// `from` may name that mailbox and nothing else — a display name is fine,
    /// another address is not. No recipient is required here: a draft
    /// legitimately has none, so the door that must have one says so itself.
    fn resolve(identity: &str, body: SendRequest) -> Result<Draft, ApiErr> {
        let sender: Mailbox = match &body.from {
            Some(f) => f
                .parse::<Mailbox>()
                .map_err(|_| ApiErr::bad(format!("Invalid 'from' address: {f}")))?,
            None => identity
                .parse::<Mailbox>()
                .map_err(|_| ApiErr::internal("Token has no usable mailbox address"))?,
        };
        if sender.email.to_string().to_lowercase() != identity {
            return Err(ApiErr(
                StatusCode::FORBIDDEN,
                format!(
                    "Token is bound to {identity} and may not send as {}",
                    sender.email
                ),
            ));
        }

        let parse_list = |v: Option<OneOrMany>| -> Result<Vec<Mailbox>, ApiErr> {
            v.map(OneOrMany::into_vec)
                .unwrap_or_default()
                .iter()
                .map(|s| s.parse::<Mailbox>().map_err(|_| ApiErr::bad(format!("Invalid recipient: {s}"))))
                .collect()
        };

        Ok(Draft {
            identity: identity.to_string(),
            sender,
            // A reply-to that will not parse is dropped rather than refused: it
            // is a hint to the recipient's client, not an address this server
            // will ever deliver to.
            reply_to: body.reply_to.as_ref().and_then(|rt| rt.parse::<Mailbox>().ok()),
            to: parse_list(body.to)?,
            cc: parse_list(body.cc)?,
            bcc: parse_list(body.bcc)?,
            subject: body.subject.unwrap_or_default(),
            text: body.text,
            html: body.html,
        })
    }

    /// The message itself.
    fn build(&self) -> Result<Message, ApiErr> {
        let mut builder = Message::builder()
            .from(self.sender.clone())
            .subject(self.subject.clone())
            // `.body()` emits Content-Type and Content-Transfer-Encoding but not
            // MIME-Version (only `.multipart()` sets that), so a plain-text send went
            // out with MIME headers and no version marker — a long-standing spam
            // heuristic. `.header` sets rather than appends, so this is a no-op on the
            // multipart path, which sets it again itself.
            .header(MIME_VERSION_1_0)
            // Give the caller a stable handle to key on. Postfix would mint one at
            // injection time, but returning it is more useful than returning null.
            .message_id(Some(generate_message_id(&self.identity)));
        if let Some(rt) = &self.reply_to {
            builder = builder.reply_to(rt.clone());
        }
        for r in &self.to {
            builder = builder.to(r.clone());
        }
        for r in &self.cc {
            builder = builder.cc(r.clone());
        }
        for r in &self.bcc {
            builder = builder.bcc(r.clone());
        }

        match (self.text.as_ref(), self.html.as_ref()) {
            (Some(text), Some(html)) => builder
                .multipart(MultiPart::alternative_plain_html(text.clone(), html.clone()))
                .map_err(|e| ApiErr::bad(format!("Failed to build email: {e}"))),
            (_, Some(html)) => builder
                .header(ContentType::TEXT_HTML)
                .body(html.clone())
                .map_err(|e| ApiErr::bad(format!("Failed to build email: {e}"))),
            (Some(text), None) => builder
                .header(ContentType::TEXT_PLAIN)
                .body(text.clone())
                .map_err(|e| ApiErr::bad(format!("Failed to build email: {e}"))),
            (None, None) => Err(ApiErr::bad("Provide 'text' and/or 'html' body")),
        }
    }
}

async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SendRequest>,
) -> Result<Json<Value>, ApiErr> {
    let identity = authenticate(&state, &headers).await?;
    let draft = Draft::resolve(&identity, body)?;
    if draft.to.is_empty() {
        return Err(ApiErr::bad("At least one 'to' recipient is required"));
    }
    let message = draft.build()?;

    let message_id = message
        .headers()
        .get_raw("Message-ID")
        .map(|s| s.to_string());

    // Envelope recipients include BCC, which by design never appears in the
    // headers, so they must come from the envelope rather than the To/Cc lists.
    let sender_addr = message
        .envelope()
        .from()
        .map(|a| a.to_string())
        .unwrap_or_else(|| identity.clone());
    let rcpt: Vec<String> = message
        .envelope()
        .to()
        .iter()
        .map(|a| a.to_string())
        .collect();
    let raw = message.formatted();

    deliver_via_sendmail(&state.cfg, &sender_addr, &rcpt, &raw)
        .await
        .map_err(|e| ApiErr::internal(format!("sendmail failed: {e}")))?;

    if state.cfg.save_sent {
        if let Err(e) = save_to_folder(&identity, "Sent", &raw).await {
            tracing::warn!("could not file sent copy for {identity}: {e}");
        }
    }

    let accepted: Vec<String> = draft
        .to
        .iter()
        .chain(draft.cc.iter())
        .chain(draft.bcc.iter())
        .map(|m| m.email.to_string())
        .collect();

    Ok(Json(json!({
        "id": message_id,
        "accepted": accepted,
    })))
}

/// Inject a message through Postfix's `sendmail` wrapper.
///
/// This is the same path a local cron job or PHP `mail()` uses: the wrapper is
/// invoked by a trusted local user, so the smtpd is not consulted and its
/// STARTTLS requirement never applies — while `non_smtpd_milters` still hands
/// the message to OpenDKIM and rspamd. `-i` stops a line that is a single dot
/// from being read as end-of-input, and `--` ends option parsing so a recipient
/// can never be mistaken for a flag.
async fn deliver_via_sendmail(
    cfg: &Config,
    sender: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<(), String> {
    if recipients.is_empty() {
        return Err("no recipients".into());
    }

    let mut cmd = tokio::process::Command::new(&cfg.sendmail);
    cmd.arg("-f").arg(sender).arg("-i").arg("--");
    for r in recipients {
        cmd.arg(r);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", cfg.sendmail))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(raw)
            .await
            .map_err(|e| format!("write {}-stdin: {e}", cfg.sendmail))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait {}: {e}", cfg.sendmail))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

/// File a copy into a folder of the mailbox so clients show it.
///
/// Used for the Sent copy of a send, and by the append route to write a draft.
async fn save_to_folder(email: &str, folder: &str, raw: &[u8]) -> Result<(), String> {
    // `doveadm save` refuses to create its target, and a mailbox that has never
    // been opened in a client has no Sent folder yet. Mint one up front — and
    // subscribe it, so it shows in clients immediately. A failure here is almost
    // always just "already exists" and must not stop the save below.
    let _ = tokio::process::Command::new("doveadm")
        .args(["mailbox", "create", "-u", email, "-s", folder])
        .output()
        .await;

    let mut child = tokio::process::Command::new("doveadm")
        .args(["save", "-u", email, "-m", folder])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn doveadm: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(raw)
            .await
            .map_err(|e| format!("write doveadm stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait doveadm: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The panel backend
//
// Management is not reimplemented here. The panel already owns the mail state
// (domains, mailboxes, aliases, autoresponder, forwarding) in its database, and
// already knows how to push a change out to Postfix and Dovecot — through the
// agent's `/mail/sync`, which only the backend can build. Writing a second copy
// of that in this daemon would mean two places to keep in step, so instead every
// management call is a loopback call into the backend's own `/api/mail/*`.
// ---------------------------------------------------------------------------

/// Call the panel backend, returning its JSON body or its error.
///
/// The credential comes from `principal`: a caller's own `dp_` key when they
/// presented one, otherwise the daemon's service key. A `dp_` key is never
/// widened to the service key — the caller's own authority is what the panel
/// should apply to it.
async fn backend_call(
    state: &AppState,
    principal: &Principal,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, ApiErr> {
    let key = principal
        .passthrough_key
        .clone()
        .or_else(|| state.cfg.backend_api_key.clone())
        .ok_or_else(|| {
            ApiErr::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Management API not configured. Either authenticate with a panel API key \
                 (Authorization: Bearer dp_…) or set MAILAPI_BACKEND_API_KEY to one issued \
                 by an admin.",
            )
        })?;

    let url = format!("{}{}", state.cfg.backend_url.trim_end_matches('/'), path);
    let mut req = state.http.request(method, &url).bearer_auth(&key);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.map_err(|e| {
        ApiErr::new(StatusCode::BAD_GATEWAY, format!("panel backend unreachable: {e}"))
    })?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::String(text.clone()));

    if !status.is_success() {
        // The backend's own message is the useful one ("Domain not found",
        // "Invalid forwarding email address", …). Pass it through rather than
        // flattening every failure into a 500.
        let msg = value
            .get("error")
            .or_else(|| value.get("message"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| text.trim().to_string());
        return Err(ApiErr::new(status, msg));
    }
    Ok(value)
}

/// `GET /api/auth/me`, used only to name the mailbox a `dp_` key speaks for.
async fn backend_me(state: &AppState, key: &str) -> Result<String, ApiErr> {
    let url = format!("{}/api/auth/me", state.cfg.backend_url.trim_end_matches('/'));
    let resp = state
        .http
        .get(&url)
        .bearer_auth(key)
        .send()
        .await
        .map_err(|e| {
            ApiErr::new(StatusCode::BAD_GATEWAY, format!("panel backend unreachable: {e}"))
        })?;
    if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN {
        return Err(ApiErr::unauthorized("Invalid or revoked panel API key"));
    }
    if !resp.status().is_success() {
        return Err(ApiErr::new(
            StatusCode::BAD_GATEWAY,
            format!("panel backend returned {} for /api/auth/me", resp.status()),
        ));
    }
    let value: Value = resp
        .json()
        .await
        .map_err(|e| ApiErr::internal(format!("bad /api/auth/me response: {e}")))?;
    value
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .ok_or_else(|| ApiErr::internal("/api/auth/me returned no email"))
}

/// The backend's list routes return a bare JSON array. Accept a `{key: […]}}`
/// envelope too, so wrapping one later does not break every route here.
fn as_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    if let Some(arr) = value.as_array() {
        return arr;
    }
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

fn json_str(v: &Value, key: &str, what: &str) -> Result<String, ApiErr> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiErr::internal(format!("backend response had no {what}")))
}

fn find_by<'a>(rows: &'a [Value], key: &str, want: &str) -> Option<&'a Value> {
    rows.iter().find(|r| {
        r.get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|x| x.eq_ignore_ascii_case(want))
    })
}

/// A mailbox located in the panel — the pieces `/api/mail` addresses it by.
struct Located {
    domain_id: String,
    account_id: String,
}

/// Resolve an email address to its domain id and account id.
///
/// The public API is keyed by addresses because that is what a caller holds; the
/// backend is keyed by UUIDs. Resolving here keeps the surface readable and makes
/// a typed address that no longer exists fail with a 404 instead of silently
/// addressing a different row.
async fn locate_mailbox(
    state: &AppState,
    principal: &Principal,
    email: &str,
) -> Result<Located, ApiErr> {
    let domain = email
        .split_once('@')
        .map(|(_, d)| d.to_lowercase())
        .ok_or_else(|| ApiErr::bad(format!("Not an email address: {email}")))?;

    let domains = backend_call(state, principal, Method::GET, "/api/mail/domains", None).await?;
    let domain_row = find_by(as_array(&domains, "domains"), "domain", &domain)
        .ok_or_else(|| ApiErr::not_found(format!("No mail domain {domain} is managed here")))?;
    let domain_id = json_str(domain_row, "id", "domain id")?;

    let account_id = account_id_in(state, principal, &domain_id, email).await?;
    Ok(Located { domain_id, account_id })
}

async fn account_id_in(
    state: &AppState,
    principal: &Principal,
    domain_id: &str,
    email: &str,
) -> Result<String, ApiErr> {
    let path = format!("/api/mail/domains/{domain_id}/accounts");
    let accounts = backend_call(state, principal, Method::GET, &path, None).await?;
    let account = find_by(as_array(&accounts, "accounts"), "email", email)
        .ok_or_else(|| ApiErr::not_found(format!("No mailbox {email}")))?;
    json_str(account, "id", "account id")
}

/// Resolve a domain name to its panel id, for the address-keyed admin routes.
async fn locate_domain(
    state: &AppState,
    principal: &Principal,
    domain: &str,
) -> Result<String, ApiErr> {
    let domains = backend_call(state, principal, Method::GET, "/api/mail/domains", None).await?;
    let row = find_by(as_array(&domains, "domains"), "domain", domain)
        .ok_or_else(|| ApiErr::not_found(format!("No mail domain {domain}")))?;
    json_str(row, "id", "domain id")
}

/// Read the caller's own mailbox row (used by the GET self-service routes, which
/// have no single-account GET to lean on).
async fn fetch_account(
    state: &AppState,
    principal: &Principal,
    email: &str,
) -> Result<Value, ApiErr> {
    let loc = locate_mailbox(state, principal, email).await?;
    let path = format!("/api/mail/domains/{}/accounts", loc.domain_id);
    let accounts = backend_call(state, principal, Method::GET, &path, None).await?;
    find_by(as_array(&accounts, "accounts"), "email", email)
        .cloned()
        .ok_or_else(|| ApiErr::not_found(format!("No mailbox {email}")))
}

/// Update the caller's own mailbox through the backend's account route.
async fn patch_account(
    state: &AppState,
    principal: &Principal,
    patch: Value,
) -> Result<Value, ApiErr> {
    let loc = locate_mailbox(state, principal, &principal.email).await?;
    let path = format!("/api/mail/domains/{}/accounts/{}", loc.domain_id, loc.account_id);
    backend_call(state, principal, Method::PUT, &path, Some(patch)).await
}

// ---------------------------------------------------------------------------
// Self-service handlers — any mailbox token may call these, for itself only.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AccountPatch {
    #[serde(default)]
    display_name: Option<String>,
}

/// `PUT /v1/me` — rename the caller's mailbox.
async fn me_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccountPatch>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let value = patch_account(&state, &p, json!({ "display_name": body.display_name })).await?;
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
struct PasswordChange {
    new_password: String,
}

/// `POST /v1/me/password` — change the caller's own mailbox password.
async fn me_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PasswordChange>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    if body.new_password.is_empty() {
        return Err(ApiErr::bad("new_password is required"));
    }
    let value = patch_account(&state, &p, json!({ "password": body.new_password })).await?;
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
struct ForwardSetting {
    #[serde(default)]
    forward_to: Option<String>,
}

/// `GET /v1/me/forward`
async fn me_forward_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let acc = fetch_account(&state, &p, &p.email).await?;
    Ok(Json(json!({ "forward_to": acc.get("forward_to").cloned().unwrap_or(Value::Null) })))
}

/// `PUT /v1/me/forward` — set, or clear with an empty string.
async fn me_forward_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ForwardSetting>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    // A PUT replaces the setting, so an omitted field means "no forwarding"
    // rather than "leave it as it was" — the backend clears on an empty string.
    let value =
        patch_account(&state, &p, json!({ "forward_to": body.forward_to.unwrap_or_default() }))
            .await?;
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
struct AutoresponderSetting {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

/// `GET /v1/me/autoresponder`
async fn me_autoresponder_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let acc = fetch_account(&state, &p, &p.email).await?;
    Ok(Json(json!({
        "enabled": acc.get("autoresponder_enabled").cloned().unwrap_or(Value::Bool(false)),
        "subject": acc.get("autoresponder_subject").cloned().unwrap_or(Value::Null),
        "body": acc.get("autoresponder_body").cloned().unwrap_or(Value::Null),
    })))
}

/// `PUT /v1/me/autoresponder` — the vacation/out-of-office reply.
async fn me_autoresponder_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AutoresponderSetting>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let patch = json!({
        "autoresponder_enabled": body.enabled,
        "autoresponder_subject": body.subject,
        "autoresponder_body": body.body,
    });
    let value = patch_account(&state, &p, patch).await?;
    Ok(Json(value))
}

/// `GET /v1/me/quota` — mailbox size against its quota.
///
/// Usage comes live from Dovecot (`doveadm mailbox status`), not from the panel
/// database, so it reflects what has actually been delivered. The LIMIT comes
/// from the panel, because that is where it is configured. `doveadm quota get` is
/// deliberately not used: it needs the `quota` Dovecot plugin enabled, and a
/// Dovecot without it answers "Unknown command 'quota'", which would make a
/// read-only reporting route fail on a perfectly healthy install.
async fn me_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;

    //        INBOX messages=8 vsize=12345
    let out = doveadm(&["mailbox", "status", "-u", &p.email, "messages vsize", "*"])
        .await
        .map_err(|e| ApiErr::internal(format!("doveadm mailbox status: {e}")))?;

    let (mut messages, mut bytes) = (0i64, 0i64);
    for line in out.lines() {
        for field in line.split_whitespace() {
            if let Some(v) = field.strip_prefix("messages=") {
                messages += v.parse::<i64>().unwrap_or(0);
            } else if let Some(v) = field.strip_prefix("vsize=") {
                bytes += v.parse::<i64>().unwrap_or(0);
            }
        }
    }

    // Best-effort: if the management credential is not configured, still report
    // the usage that Dovecot just told us rather than failing the whole route.
    let account = fetch_account(&state, &p, &p.email).await.unwrap_or(Value::Null);
    let quota_mb = account.get("quota_mb").and_then(|v| v.as_i64());

    Ok(Json(json!({
        "email": p.email,
        "used_kb": bytes / 1024,
        "messages": messages,
        "quota_mb": quota_mb,
        "limit_kb": quota_mb.map(|mb| mb * 1024),
    })))
}

#[derive(Debug, Deserialize)]
struct FolderCreate {
    name: String,
}

#[derive(Debug, Deserialize)]
struct FolderQuery {
    name: String,
}

/// `GET /v1/me/folders`
async fn me_folders(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let out = doveadm(&["mailbox", "list", "-u", &p.email])
        .await
        .map_err(|e| ApiErr::internal(format!("doveadm mailbox list: {e}")))?;
    let folders: Vec<&str> = out.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
    Ok(Json(json!({ "email": p.email, "folders": folders })))
}

/// `POST /v1/me/folders` — body `{"name": "Archive"}`, or `INBOX/Sub` for a
/// nested folder.
async fn me_folder_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FolderCreate>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    if body.name.trim().is_empty() {
        return Err(ApiErr::bad("name is required"));
    }
    doveadm(&["mailbox", "create", "-u", &p.email, "-s", &body.name])
        .await
        .map_err(|e| ApiErr::bad(format!("could not create {}: {e}", body.name)))?;
    Ok(Json(json!({ "created": body.name })))
}

/// `DELETE /v1/me/folders?name=Archive` — a query parameter, not a path
/// segment, because folder names legitimately contain `/`.
async fn me_folder_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FolderQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    // Refuse to remove a folder Dovecot treats as structural.
    const PROTECTED: [&str; 3] = ["INBOX", "Sent", "Trash"];
    if PROTECTED.iter().any(|f| f.eq_ignore_ascii_case(&q.name)) {
        return Err(ApiErr::bad(format!("{} must not be deleted", q.name)));
    }
    doveadm(&["mailbox", "delete", "-u", &p.email, "-s", &q.name])
        .await
        .map_err(|e| ApiErr::bad(format!("could not delete {}: {e}", q.name)))?;
    Ok(Json(json!({ "deleted": q.name })))
}

// ---------------------------------------------------------------------------
// Message handlers — the mail IN the folders, not just the folders.
//
// `Drafts`, `Sent` and `Trash` are ordinary Dovecot folders, so there is no
// per-folder route to write: `?folder=` names which one, and the same handlers
// reach every folder and every one of the caller's own messages. That is also
// why the folder travels as a query parameter and never as a path segment —
// folder names legitimately contain `/`.
//
// Every command runs with `-u <the caller's own address>`, taken from the token
// and never from the request, so no request can name another mailbox. Every
// caller-supplied value that reaches `doveadm` is validated first: a uid must be
// a number, a folder must be one the mailbox actually has, and a flag is
// replaced by the fixed spelling of a closed list. `doveadm` reads an argument
// that begins with `-` as an option, so none may be passed through unchecked.
// ---------------------------------------------------------------------------

/// The fields a listing needs, in the names `doveadm fetch` uses.
const MESSAGE_FIELDS: &str =
    "uid flags size.virtual date.sent date.received hdr.subject hdr.from hdr.to hdr.cc hdr.date";

/// The flags a caller may set — a closed list, both because these land in argv
/// and because a mailbox has no business accumulating keywords nobody reads.
const SETTABLE_FLAGS: [&str; 5] = ["\\Seen", "\\Answered", "\\Flagged", "\\Draft", "\\Deleted"];

/// Run a `doveadm` command that answers in JSON.
///
/// `-f json` is a global option and must precede the command, not follow it.
async fn doveadm_json(args: &[&str]) -> Result<Value, ApiErr> {
    let mut argv = vec!["-f", "json"];
    argv.extend_from_slice(args);
    let out = doveadm(&argv).await.map_err(|e| {
        ApiErr::internal(format!("doveadm {}: {e}", args.first().unwrap_or(&"")))
    })?;
    serde_json::from_str(out.trim())
        .map_err(|e| ApiErr::internal(format!("doveadm answered with no JSON: {e}")))
}

/// Refuse a folder the mailbox does not have.
///
/// Two reasons, and the second is the real one: `save` would create a folder out
/// of a typo, and the name is handed to `doveadm` as-is, so one beginning with
/// `-` must never reach argv. Membership in the mailbox list settles both.
async fn known_folder(email: &str, folder: &str) -> Result<(), ApiErr> {
    let name = folder.trim();
    if name.is_empty() {
        return Err(ApiErr::bad("folder is required"));
    }
    let out = doveadm(&["mailbox", "list", "-u", email])
        .await
        .map_err(|e| ApiErr::internal(format!("doveadm mailbox list: {e}")))?;
    if out.lines().any(|l| l.trim() == name) {
        Ok(())
    } else {
        Err(ApiErr::not_found(format!("{email} has no folder named {name}")))
    }
}

/// A message ordinal, refused rather than coerced: it lands in argv.
fn parse_uid(raw: &str) -> Result<u32, ApiErr> {
    raw.parse::<u32>()
        .map_err(|_| ApiErr::bad(format!("uid must be a mailbox number, not {raw:?}")))
}

/// Canonicalise caller-supplied flags against [`SETTABLE_FLAGS`].
///
/// Returns the fixed literal rather than the caller's own text, so nothing a
/// request contains reaches `doveadm` as an argument. `Seen` and `\Seen` are the
/// same flag to IMAP, so both spellings are accepted.
fn checked_flags(flags: &[String]) -> Result<Vec<&'static str>, ApiErr> {
    flags
        .iter()
        .map(|f| {
            let f = f.trim();
            let canonical = if f.starts_with('\\') { f.to_string() } else { format!("\\{f}") };
            SETTABLE_FLAGS
                .iter()
                .find(|k| k.eq_ignore_ascii_case(&canonical))
                .copied()
                .ok_or_else(|| {
                    ApiErr::bad(format!(
                        "unknown flag {f:?}; one of \\Seen, \\Answered, \\Flagged, \\Draft, \\Deleted"
                    ))
                })
        })
        .collect()
}

/// One fetched message, under the names this API promises rather than the field
/// names `doveadm` happens to use.
fn message_row(row: &Value) -> Value {
    let field = |k: &str| row.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "uid": row.get("uid").and_then(|v| v.as_str()).and_then(|s| s.parse::<u32>().ok()),
        // Dovecot answers one space-separated string ("\\Seen \\Recent"), which a
        // caller should not have to split themselves.
        "flags": row
            .get("flags")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().collect::<Vec<_>>())
            .unwrap_or_default(),
        "size": row
            .get("size.virtual")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok()),
        "subject": field("hdr.subject"),
        "from": field("hdr.from"),
        "to": field("hdr.to"),
        "cc": field("hdr.cc"),
        "date": field("hdr.date"),
    })
}

/// The uid of a message just written, found by the Message-ID we gave it.
///
/// `doveadm save` prints nothing at all — not even the uid it assigned — so the
/// only way to act on what was written is to ask for it back, and the Message-ID
/// this server generated is what makes that lookup unambiguous.
async fn find_by_message_id(email: &str, folder: &str, message_id: &str) -> Option<u32> {
    let rows = doveadm_json(&[
        "search", "-u", email, "mailbox", folder, "header", "Message-ID", message_id,
    ])
    .await
    .ok()?;
    rows.as_array()?
        .first()?
        .get("uid")?
        .as_str()?
        .parse::<u32>()
        .ok()
}

// ---------------------------------------------------------------------------
// Searching and sorting a listing
//
// `GET /v1/me/messages` reads a folder the way the Roundcube webmail in front
// of it searches one: free text over a chosen set of fields, the filter and
// interval dropdowns, the `is:`/`larger:`/`since:`/`OR` tokens a user can type
// into the search box, and the column sort with its order. The search runs in
// Dovecot — `doveadm fetch` takes an IMAP search query — so `BODY` and `TEXT`
// searches do not drag every message body through this daemon; only the sort
// and the page are applied here, over the matching rows.
//
// Safety rests on the same rule as the rest of the file, extended to free text:
// `doveadm` is spawned without a shell, every value is its own argv element,
// and `--` is placed before the query so a value that begins with `-` cannot be
// read as an option (doveadm's option parser stops there). The search KEYS come
// only from the closed sets below — a caller supplies values, never keys.
// ---------------------------------------------------------------------------

/// The fields a plain-text term may look in — Roundcube's "search in" choices.
/// `all` is not one of its field names but the set a caller usually means by it.
const TEXT_FIELDS: [&str; 6] = ["subject", "from", "to", "cc", "bcc", "body"];

/// Every field name accepted, `subject:…` and the slightly odd Webmail
/// spellings included.
const NAMED_FIELDS: [&str; 9] = [
    "subject",
    "from",
    "to",
    "cc",
    "bcc",
    "body",
    "text",
    "reply-to",
    "followup-to",
];

/// One piece of an IMAP search, built only from the keys of
/// `doveadm-search-query(7)`.
enum Cond {
    /// A key and its arguments, already in argv order: `["HEADER","SUBJECT","x"]`.
    Key(Vec<String>),
    /// `( a OR b OR c )` — parentheses are what let an OR sit inside an AND.
    Or(Vec<Cond>),
    /// `( a b c )`, an explicit AND group.
    And(Vec<Cond>),
    /// `NOT a`.
    Not(Box<Cond>),
}

impl Cond {
    fn key(parts: &[&str]) -> Cond {
        Cond::Key(parts.iter().map(|p| (*p).to_string()).collect())
    }

    /// `HEADER <field> <value>`, the way Roundcube spells subject/from/to/cc/bcc.
    fn header(field: &str, value: &str) -> Cond {
        Cond::Key(vec!["HEADER".to_string(), field.to_ascii_uppercase(), value.to_string()])
    }

    /// Flatten to the argv `doveadm` reads a query from.
    fn push(&self, out: &mut Vec<String>) {
        match self {
            Cond::Key(parts) => out.extend(parts.iter().cloned()),
            Cond::Or(parts) => {
                out.push("(".to_string());
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        out.push("OR".to_string());
                    }
                    part.push(out);
                }
                out.push(")".to_string());
            }
            Cond::And(parts) => {
                out.push("(".to_string());
                for part in parts {
                    part.push(out);
                }
                out.push(")".to_string());
            }
            Cond::Not(inner) => {
                out.push("NOT".to_string());
                inner.push(out);
            }
        }
    }
}

/// AND a list of conditions into one doveadm query.
fn query_of(conds: &[Cond]) -> Vec<String> {
    let mut out = Vec::new();
    for cond in conds {
        cond.push(&mut out);
    }
    out
}

/// One search field, as the key Roundcube would emit for it.
fn field_cond(field: &str, value: &str) -> Option<Cond> {
    Some(match field {
        "subject" => Cond::header("SUBJECT", value),
        "from" => Cond::header("FROM", value),
        "to" => Cond::header("TO", value),
        "cc" => Cond::header("CC", value),
        "bcc" => Cond::header("BCC", value),
        "body" => Cond::key(&["BODY", value]),
        "text" => Cond::key(&["TEXT", value]),
        // Two headers apiece on the wire, because the "reply-to"/"followup-to"
        // spellings vary — the same OR Roundcube builds.
        "reply-to" | "replyto" => {
            Cond::Or(vec![Cond::header("REPLY-TO", value), Cond::header("MAIL-REPLY-TO", value)])
        }
        "followup-to" | "followupto" => Cond::Or(vec![
            Cond::header("FOLLOWUP-TO", value),
            Cond::header("MAIL-FOLLOWUP-TO", value),
        ]),
        _ => return None,
    })
}

/// `has:attachment` / the filter dropdown's "with attachment", built the way
/// Roundcube builds it: the content types a message with an attachment carries,
/// OR the `$HasAttachment` keyword the Webmail's own list recognises — with
/// `$HasNoAttachment` excluded. Nothing in this install sets the keyword, but a
/// mailbox that already carries it must still match, exactly as it would there.
fn attachment_cond() -> Cond {
    let types = ["application/", "multipart/mixed", "multipart/signed", "multipart/report"];
    let mut conds: Vec<Cond> = types.iter().map(|t| Cond::header("CONTENT-TYPE", t)).collect();
    conds.push(Cond::And(vec![
        Cond::key(&["KEYWORD", "$HasAttachment"]),
        Cond::Not(Box::new(Cond::key(&["KEYWORD", "$HasNoAttachment"]))),
    ]));
    Cond::Or(conds)
}

/// The filter dropdown's names, plus the read/unread and keywoded flags people
/// ask for directly.
fn filter_cond(name: &str) -> Option<Cond> {
    Some(match name.to_ascii_lowercase().as_str() {
        "all" => return None,
        "unread" => Cond::key(&["UNSEEN"]),
        "read" | "seen" => Cond::key(&["SEEN"]),
        "flagged" => Cond::key(&["FLAGGED"]),
        "unflagged" => Cond::key(&["UNFLAGGED"]),
        "answered" => Cond::key(&["ANSWERED"]),
        "unanswered" => Cond::key(&["UNANSWERED"]),
        "deleted" => Cond::key(&["DELETED"]),
        "undeleted" => Cond::key(&["UNDELETED"]),
        "draft" => Cond::key(&["DRAFT"]),
        "undraft" => Cond::key(&["UNDRAFT"]),
        "attachment" | "has-attachment" => attachment_cond(),
        "priority-highest" => Cond::header("X-PRIORITY", "1"),
        "priority-high" => Cond::header("X-PRIORITY", "2"),
        "priority-normal" => Cond::And(vec![
            Cond::Not(Box::new(Cond::header("X-PRIORITY", "1"))),
            Cond::Not(Box::new(Cond::header("X-PRIORITY", "2"))),
            Cond::Not(Box::new(Cond::header("X-PRIORITY", "4"))),
            Cond::Not(Box::new(Cond::header("X-PRIORITY", "5"))),
        ]),
        "priority-low" => Cond::header("X-PRIORITY", "4"),
        "priority-lowest" => Cond::header("X-PRIORITY", "5"),
        _ => return None,
    })
}

/// `is:<value>`, the token form of the flag filters.
fn is_cond(value: &str) -> Option<Cond> {
    Some(match value.to_ascii_lowercase().as_str() {
        "unread" | "unseen" => Cond::key(&["UNSEEN"]),
        "read" | "seen" => Cond::key(&["SEEN"]),
        "flagged" => Cond::key(&["FLAGGED"]),
        "unflagged" => Cond::key(&["UNFLAGGED"]),
        "answered" => Cond::key(&["ANSWERED"]),
        "unanswered" => Cond::key(&["UNANSWERED"]),
        "deleted" => Cond::key(&["DELETED"]),
        "undeleted" => Cond::key(&["UNDELETED"]),
        "draft" => Cond::key(&["DRAFT"]),
        "undraft" => Cond::key(&["UNDRAFT"]),
        "recent" => Cond::key(&["RECENT"]),
        "old" => Cond::key(&["OLD"]),
        "new" => Cond::key(&["NEW"]),
        _ => return None,
    })
}

/// A date written the way `doveadm` reads one: `YYYY-MM-DD`, accepted with `/`
/// as well because that is how people type it.
fn iso_date(value: &str) -> Option<String> {
    let normalized = value.trim().replace('/', "-");
    let mut parts = normalized.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let year: i32 = y.parse().ok()?;
    let month = time::Month::try_from(m.parse::<u8>().ok()?).ok()?;
    let day: u8 = d.parse().ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    date.format(&time::format_description::well_known::Iso8601::DATE).ok()
}

/// Step a date back by a number of months, clamping the day to the shorter
/// month — what PHP's `DateInterval('P1M')` does for Roundcube.
fn months_back(now: time::OffsetDateTime, months: i64) -> Option<time::OffsetDateTime> {
    let total = now.year() as i64 * 12 + (u8::from(now.month()) as i64 - 1) - months;
    let year = i32::try_from(total.div_euclid(12)).ok()?;
    let month = time::Month::try_from(u8::try_from(total.rem_euclid(12) + 1).ok()?).ok()?;
    let day = now.day().min(time::util::days_in_month(month, year));
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    Some(now.replace_date(date))
}

/// The date an interval names, resolved against today the way Roundcube
/// resolves its dropdown rather than handed to Dovecot as `1M`, which Dovecot
/// would read as one *minute*.
fn interval_date(value: &str) -> Option<String> {
    let value = value.trim();
    let mut chars = value.chars();
    let unit = chars.next_back()?;
    let n: i64 = chars.as_str().parse().ok()?;
    if n <= 0 {
        return None;
    }
    let now = time::OffsetDateTime::now_utc();
    let date = match unit.to_ascii_uppercase() {
        'W' => now - time::Duration::weeks(n),
        'D' => now - time::Duration::days(n),
        'M' => months_back(now, n)?,
        'Y' => months_back(now, n.checked_mul(12)?)?,
        _ => return None,
    };
    date.format(&time::format_description::well_known::Iso8601::DATE).ok()
}

/// `since:`/`before:` — an interval or an explicit date, both turned into a
/// `YYYY-MM-DD` Dovecot reads.
fn date_cond(key: &str, value: &str) -> Option<Cond> {
    let date = interval_date(value).or_else(|| iso_date(value))?;
    Some(Cond::key(&[key, &date]))
}

/// `larger:`/`smaller:` — bytes, with the size suffixes Dovecot itself takes.
fn size_bytes(value: &str) -> Option<String> {
    let value = value.trim();
    let mut chars = value.chars();
    let last = chars.next_back()?;
    let (num, mult): (&str, u64) = match last.to_ascii_uppercase() {
        'K' => (chars.as_str(), 1024),
        'M' => (chars.as_str(), 1024 * 1024),
        'G' => (chars.as_str(), 1024 * 1024 * 1024),
        'T' => (chars.as_str(), 1024 * 1024 * 1024 * 1024),
        'B' => (chars.as_str(), 1),
        _ => (value, 1),
    };
    let n: f64 = num.trim().parse().ok()?;
    if !n.is_finite() || n < 0.0 {
        return None;
    }
    Some(((n * mult as f64) as u64).to_string())
}

/// A `key:value` token, with the `-` negation left on the key for the caller to
/// strip. Names are letters and `-` only, so a bare `http://…` stays text.
fn split_option(token: &str) -> Option<(&str, &str)> {
    let (option, value) = token.split_once(':')?;
    let name = option.strip_prefix('-').unwrap_or(option);
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphabetic() || c == '-') {
        return None;
    }
    Some((option, value))
}

/// Drop the surrounding quotes Roundcube's tokens may carry and undouble `\"`.
fn unquote(value: &str) -> String {
    let mut v = value.trim();
    if let Some(rest) = v.strip_prefix('"') {
        v = rest;
    }
    if let Some(rest) = v.strip_suffix('"') {
        v = rest;
    }
    v.replace("\\\"", "\"")
}

/// Split on whitespace, but not inside quotes — Roundcube's
/// `explode_quoted_string('\s+', …)`, and the only way `subject:"two words"`
/// arrives as one token.
fn tokenize(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in raw.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// The inline tokens of the search box that name a field, a flag, a size or a
/// date — `from:x`, `is:unread`, `larger:1M`, `since:2024-01-01`.
fn option_cond(option: &str, value: &str) -> Option<Cond> {
    let name = option.to_ascii_lowercase();
    match name.as_str() {
        "subject" | "from" | "to" | "cc" | "bcc" | "body" | "text" | "reply-to" | "replyto"
        | "followup-to" | "followupto" => field_cond(&name, value),
        "larger" | "smaller" => {
            let size = size_bytes(value)?;
            let key = name.to_ascii_uppercase();
            Some(Cond::key(&[key.as_str(), size.as_str()]))
        }
        "since" => date_cond("SINCE", value),
        // GMail's aliases, which Roundcube accepts too.
        "newer_than" => date_cond("SINCE", value),
        "before" => date_cond("BEFORE", value),
        "older_than" => date_cond("BEFORE", value),
        "is" => is_cond(value),
        "has" if value.eq_ignore_ascii_case("attachment") => Some(attachment_cond()),
        _ => None,
    }
}

/// A plain-text term, OR-ed across the fields it was told to look in.
fn or_over_fields(value: &str, fields: &[String]) -> Cond {
    let conds: Vec<Cond> = fields.iter().filter_map(|f| field_cond(f, value)).collect();
    match conds.len() {
        0 => Cond::key(&["ALL"]),
        1 => conds.into_iter().next().unwrap(),
        _ => Cond::Or(conds),
    }
}

/// One token of the parsed search box.
enum Part {
    Expr(Cond),
    Or,
    And,
}

/// Parse the free-text `q` into conditions, mirroring Roundcube's
/// `search_input`: `OR` joins the term before it to the term after, `AND` is
/// dropped (AND is the default), a leading `-` negates an option or a quoted
/// phrase, and anything unrecognised is text.
fn text_conds(raw: &str, fields: &[String]) -> Vec<Cond> {
    let mut pieces: Vec<Part> = Vec::new();

    for token in tokenize(raw) {
        if token.eq_ignore_ascii_case("OR") {
            pieces.push(Part::Or);
            continue;
        }
        if token.eq_ignore_ascii_case("AND") {
            pieces.push(Part::And);
            continue;
        }

        if let Some((option, value)) = split_option(&token) {
            let (name, negated) = match option.strip_prefix('-') {
                Some(n) => (n, true),
                None => (option, false),
            };
            // An option with no value is not an option at all: Roundcube leaves
            // the token to be read as plain text, and so does this.
            let value = unquote(value);
            if !value.trim().is_empty() {
                if let Some(cond) = option_cond(name, &value) {
                    pieces.push(Part::Expr(if negated { Cond::Not(Box::new(cond)) } else { cond }));
                    continue;
                }
            }
        }

        let mut negated = false;
        let mut text = token.as_str();
        if let Some(rest) = token.strip_prefix('-') {
            if rest.len() >= 2 && rest.starts_with('"') && rest.ends_with('"') {
                negated = true;
                text = rest;
            }
        }
        let value = unquote(text);
        if value.trim().is_empty() {
            continue;
        }
        let cond = or_over_fields(&value, fields);
        pieces.push(Part::Expr(if negated { Cond::Not(Box::new(cond)) } else { cond }));
    }

    // `a OR b OR c` becomes `( ( a OR b ) OR c )`; an `OR` with nothing to its
    // left or right is dropped, as Roundcube drops it.
    let mut out: Vec<Cond> = Vec::new();
    let mut pending_or = false;
    for piece in pieces {
        match piece {
            Part::Expr(cond) => {
                if pending_or {
                    match out.pop() {
                        Some(prev) => out.push(Cond::Or(vec![prev, cond])),
                        None => out.push(cond),
                    }
                    pending_or = false;
                } else {
                    out.push(cond);
                }
            }
            Part::Or => pending_or = true,
            Part::And => {}
        }
    }
    out
}

/// Whether `name` is `base` or sits under it — Roundcube's folder comparison,
/// which reads both hierarchy separators because a mailbox may use either.
fn is_under(name: &str, base: &str) -> bool {
    match name.get(..base.len()) {
        Some(head) if head.eq_ignore_ascii_case(base) => {
            name.len() == base.len() || name[base.len()..].starts_with(['.', '/'])
        }
        _ => false,
    }
}

/// The fields `q`'s plain words look in when the caller names none.
///
/// Roundcube's own default `search_mods`: `subject` and `from`, and `subject`
/// and `to` in the folders the account writes into (`Sent`, `Drafts` and their
/// children) — so a bare `q` reads the same mail the Webmail's search box would.
fn default_search_fields(folder: &str) -> Vec<String> {
    let folder = folder.trim();
    if is_under(folder, "Sent") || is_under(folder, "Drafts") {
        vec!["subject".to_string(), "to".to_string()]
    } else {
        vec!["subject".to_string(), "from".to_string()]
    }
}

/// The fields a free-text term looks in, from the `search` parameter. Naming
/// none — or naming only blanks — leaves [`default_search_fields`].
fn parse_fields(raw: Option<&str>, folder: &str) -> Result<Vec<String>, ApiErr> {
    let mut out: Vec<String> = Vec::new();
    for name in raw.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let name = name.to_ascii_lowercase();
        if name == "all" || name == "any" {
            for field in TEXT_FIELDS {
                if !out.iter().any(|f| f == field) {
                    out.push(field.to_string());
                }
            }
        } else if NAMED_FIELDS.contains(&name.as_str()) {
            if !out.contains(&name) {
                out.push(name);
            }
        } else {
            return Err(ApiErr::bad(format!(
                "unknown search field {name:?}; one of all, subject, from, to, cc, bcc, body, text, \
                 reply-to, followup-to"
            )));
        }
    }
    if out.is_empty() {
        out = default_search_fields(folder);
    }
    Ok(out)
}

/// The interval dropdown: `1W`, `1M`, `1Y`, and the `-` forms that mean
/// "before", resolved to a date here.
fn interval_cond(interval: &str) -> Result<Cond, ApiErr> {
    let (back, rest) = match interval.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, interval),
    };
    let date = interval_date(rest).ok_or_else(|| {
        ApiErr::bad(format!("unknown interval {interval:?}; one of 1W, 1M, 1Y, -1W, -1M, -1Y"))
    })?;
    Ok(Cond::key(&[if back { "BEFORE" } else { "SINCE" }, &date]))
}

/// Every condition the query parameters and the free text add up to.
fn search_conds(q: &MessagesQuery) -> Result<Vec<Cond>, ApiErr> {
    let mut conds = Vec::new();

    let fields = parse_fields(q.search.as_deref(), q.folder.as_deref().unwrap_or("INBOX"))?;
    if let Some(text) = q.q.as_deref() {
        conds.extend(text_conds(text, &fields));
    }

    if let Some(filter) = q.filter.as_deref() {
        for name in filter.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            // `all` is the dropdown's "no filter" and adds nothing.
            if name.eq_ignore_ascii_case("all") {
                continue;
            }
            match filter_cond(name) {
                Some(cond) => conds.push(cond),
                None => {
                    return Err(ApiErr::bad(format!(
                        "unknown filter {name:?}; one of all, unread, read, flagged, unflagged, \
                         answered, unanswered, deleted, undeleted, draft, undraft, attachment, \
                         priority-highest, priority-high, priority-normal, priority-low, \
                         priority-lowest"
                    )));
                }
            }
        }
    }

    // The read/unread switch people reach for first.
    if let Some(read) = q.read {
        conds.push(Cond::key(&[if read { "SEEN" } else { "UNSEEN" }]));
    }

    if let Some(interval) = q.interval.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        conds.push(interval_cond(interval)?);
    }

    Ok(conds)
}

/// The column a listing is sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Date,
    Arrival,
    Subject,
    From,
    To,
    Cc,
    Size,
    /// The empty column: Dovecot's own uid order, folder by folder, with the
    /// direction applied by reverting each folder's run.
    None,
}

impl Sort {
    fn parse(raw: Option<&str>, folder: &str) -> Result<Sort, ApiErr> {
        Ok(match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("date") => Sort::Date,
            Some("arrival") | Some("received") => Sort::Arrival,
            Some("subject") => Sort::Subject,
            Some("from") => Sort::From,
            Some("to") => Sort::To,
            // Roundcube's "smart" From/To column: the recipient in the folders
            // the account writes into, the sender everywhere else. It resolves
            // here, so the answer reports the column actually sorted by.
            Some("fromto") => {
                let folder = folder.trim();
                if is_under(folder, "Sent") || is_under(folder, "Drafts") {
                    Sort::To
                } else {
                    Sort::From
                }
            }
            Some("cc") => Sort::Cc,
            Some("size") => Sort::Size,
            // Roundcube's empty column: Dovecot's own uid order — folder by
            // folder — with the direction applied by reverting each folder.
            Some("none") | Some("natural") | Some("server") => Sort::None,
            Some(other) => {
                return Err(ApiErr::bad(format!(
                    "unknown sort {other:?}; one of date, arrival, subject, from, to, fromto, cc, \
                     size, none"
                )));
            }
        })
    }

    fn name(self) -> &'static str {
        match self {
            Sort::Date => "date",
            Sort::Arrival => "arrival",
            Sort::Subject => "subject",
            Sort::From => "from",
            Sort::To => "to",
            Sort::Cc => "cc",
            Sort::Size => "size",
            Sort::None => "none",
        }
    }
}

/// `order`, defaulting to newest/highest first the way a mail list does.
fn descending(raw: Option<&str>) -> Result<bool, ApiErr> {
    Ok(match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("desc") | Some("descending") => true,
        Some("asc") | Some("ascending") => false,
        Some(other) => {
            return Err(ApiErr::bad(format!("unknown order {other:?}; one of asc, desc")));
        }
    })
}

/// The `Date:` header, which is what `sort=date` is about.
fn parse_sent(value: Option<&str>) -> Option<i64> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822)
        .ok()
        .map(|d| d.unix_timestamp())
}

/// Dovecot's `date.received`, e.g. `2010-01-19 01:17:41 (+0100)`.
fn parse_received(value: Option<&str>) -> Option<i64> {
    let value = value?.trim();
    let format = time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second] ([offset_hour sign:mandatory][offset_minute])"
    );
    time::OffsetDateTime::parse(value, &format)
        .ok()
        .map(|d| d.unix_timestamp())
}

/// One listing row: the message as the API reports it, plus the keys a sort may
/// need that the reported fields do not carry in a sortable form.
struct Row {
    message: Value,
    folder: String,
    uid: u64,
    size: u64,
    subject: String,
    from: String,
    to: String,
    cc: String,
    sent: i64,
    received: i64,
}

impl Row {
    fn new(raw: &Value, folder: &str) -> Row {
        let mut message = message_row(raw);
        // `folder` is what makes a uid unambiguous once more than one folder is
        // in the result, so every row carries it.
        if let Some(obj) = message.as_object_mut() {
            obj.insert("folder".to_string(), Value::String(folder.to_string()));
        }
        let text = |k: &str| {
            message.get(k).and_then(|v| v.as_str()).unwrap_or("").to_lowercase()
        };
        Row {
            uid: message.get("uid").and_then(|v| v.as_u64()).unwrap_or(0),
            size: message.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            subject: text("subject"),
            from: text("from"),
            to: text("to"),
            cc: text("cc"),
            sent: parse_sent(raw.get("hdr.date").and_then(|v| v.as_str())).unwrap_or(0),
            received: parse_received(raw.get("date.received").and_then(|v| v.as_str()))
                .unwrap_or(0),
            folder: folder.to_string(),
            // `folder` is what makes a uid unambiguous once more than one folder
            // is in the result, so every row carries it.
            message,
        }
    }
}

/// Sort in this process: `doveadm fetch` returns a folder in uid order and has
/// no SORT of its own. Ties — and rows that carry no date at all — fall back to
/// the folder and uid, so the order is total and a page boundary cannot move.
fn sort_rows(rows: &mut [Row], sort: Sort, desc: bool) {
    // Roundcube's empty column: Dovecot's own order — folder by folder, uid
    // ascending — with the direction still applied, reverting each folder's run
    // so the folders themselves keep the order Dovecot listed them in.
    if sort == Sort::None {
        if desc {
            let mut i = 0;
            while i < rows.len() {
                let mut j = i + 1;
                while j < rows.len() && rows[j].folder == rows[i].folder {
                    j += 1;
                }
                rows[i..j].reverse();
                i = j;
            }
        }
        return;
    }
    rows.sort_by(|a, b| {
        let ord = match sort {
            Sort::Date => a.sent.cmp(&b.sent),
            Sort::Arrival => a.received.cmp(&b.received),
            Sort::Subject => a.subject.cmp(&b.subject),
            Sort::From => a.from.cmp(&b.from),
            Sort::To => a.to.cmp(&b.to),
            Sort::Cc => a.cc.cmp(&b.cc),
            Sort::Size => a.size.cmp(&b.size),
            // Unreachable: `none` returned above. Only here to keep the match
            // exhaustive; it is never reached.
            Sort::None => std::cmp::Ordering::Equal,
        }
        .then_with(|| a.folder.cmp(&b.folder))
        .then_with(|| a.uid.cmp(&b.uid));
        if desc {
            ord.reverse()
        } else {
            ord
        }
    });
}

/// `doveadm fetch` for one folder, with the search query when there is one.
///
/// `--` sits between the options and the query only when a query is present:
/// it is what lets a value beginning with `-` be a value rather than an option,
/// and a plain listing has no values of its own to protect.
fn fetch_args(email: &str, folder: &str, query: &[String]) -> Vec<String> {
    let mut args = vec!["fetch".to_string(), "-u".to_string(), email.to_string()];
    if !query.is_empty() {
        args.push("--".to_string());
    }
    args.push(MESSAGE_FIELDS.to_string());
    args.push("mailbox".to_string());
    args.push(folder.to_string());
    args.extend(query.iter().cloned());
    args
}

async fn fetch_rows(email: &str, folder: &str, query: &[String]) -> Result<Value, ApiErr> {
    let args = fetch_args(email, folder, query);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    doveadm_json(&refs).await
}

/// The folders a listing reads: the one asked for, its children, or all of them.
async fn scoped_folders(email: &str, base: &str, scope: &str) -> Result<Vec<String>, ApiErr> {
    if scope == "base" {
        return Ok(vec![base.to_string()]);
    }
    let out = doveadm(&["mailbox", "list", "-u", email])
        .await
        .map_err(|e| ApiErr::internal(format!("doveadm mailbox list: {e}")))?;
    let all: Vec<String> = out
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if scope == "all" {
        return Ok(all);
    }
    // `sub`: the folder itself and anything nested under it, whichever
    // hierarchy separator the mailbox uses.
    let dot = format!("{base}.");
    let slash = format!("{base}/");
    let mut folders = vec![base.to_string()];
    folders.extend(
        all.into_iter().filter(|f| f.starts_with(&dot) || f.starts_with(&slash)),
    );
    Ok(folders)
}

fn resolve_scope(raw: Option<&str>) -> Result<&'static str, ApiErr> {
    let name = raw.map(|s| s.trim().to_ascii_lowercase());
    Ok(match name.as_deref() {
        None | Some("") | Some("base") | Some("current") | Some("folder") => "base",
        Some("sub") | Some("subfolders") => "sub",
        Some("all") => "all",
        Some(other) => {
            return Err(ApiErr::bad(format!(
                "unknown scope {other:?}; one of base, sub, all"
            )));
        }
    })
}

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    /// Defaults to `INBOX`.
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    /// Free text to search for. Roundcube's inline tokens — `from:`, `is:`,
    /// `larger:`, `since:`, `OR`, a `-` prefix — are understood here too.
    #[serde(default)]
    q: Option<String>,
    /// Comma-separated fields `q`'s plain text looks in. Naming none leaves
    /// Roundcube's own default — `subject`+`from`, `subject`+`to` in
    /// `Sent`/`Drafts`.
    #[serde(default)]
    search: Option<String>,
    /// Comma-separated filter names, or the same thing as `is:` tokens.
    #[serde(default)]
    filter: Option<String>,
    /// `true` for read, `false` for unread.
    #[serde(default)]
    read: Option<bool>,
    /// `1W`, `1M`, `1Y`, `-1W`, `-1M`, `-1Y` — the interval dropdown.
    #[serde(default)]
    interval: Option<String>,
    /// `base` (default), `sub` or `all`.
    #[serde(default)]
    scope: Option<String>,
    /// `date` (default), `arrival`, `subject`, `from`, `to`, `fromto`, `cc`,
    /// `size` or `none`.
    #[serde(default)]
    sort: Option<String>,
    /// `asc` or `desc` (default).
    #[serde(default)]
    order: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MessageQuery {
    folder: String,
    /// `true` expunges instead of moving to `Trash`.
    #[serde(default)]
    permanent: Option<bool>,
}

/// `GET /v1/me/messages?folder=Sent`
///
/// How `Drafts`, `Sent` and `Trash` are read: they are folders, not routes, and
/// `folder` defaults to `INBOX`.
///
/// The listing doubles as the search the Webmail in front of it offers: `q` for
/// free text (with `search`, `filter`, `read` and `interval` alongside it, and
/// Roundcube's inline `from:`/`is:`/`larger:`/`since:`/`OR` tokens accepted in
/// the text), `scope` to widen it past one folder, and `sort`/`order` for the
/// column. `limit` and `offset` page over the sorted result.
async fn me_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MessagesQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let folder = q.folder.clone().unwrap_or_else(|| "INBOX".to_string());
    known_folder(&p.email, &folder).await?;

    let scope = resolve_scope(q.scope.as_deref())?;
    let folders = scoped_folders(&p.email, &folder, scope).await?;

    let query = query_of(&search_conds(&q)?);
    let sort = Sort::parse(q.sort.as_deref(), &folder)?;
    let desc = descending(q.order.as_deref())?;

    let mut rows: Vec<Row> = Vec::new();
    for name in &folders {
        let fetched = fetch_rows(&p.email, name, &query).await?;
        for raw in fetched.as_array().map(Vec::as_slice).unwrap_or_default() {
            rows.push(Row::new(raw, name));
        }
    }
    sort_rows(&mut rows, sort, desc);

    let total = rows.len();
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(500);
    let page: Vec<Value> = rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|row| row.message)
        .collect();

    Ok(Json(json!({
        "email": p.email,
        "folder": folder,
        "scope": scope,
        "sort": sort.name(),
        "order": if desc { "desc" } else { "asc" },
        "total": total,
        "offset": offset,
        "messages": page,
    })))
}

/// `GET /v1/me/messages/{uid}?folder=Drafts`
async fn me_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<String>,
    Query(q): Query<MessageQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let uid = parse_uid(&uid)?;
    known_folder(&p.email, &q.folder).await?;
    let uid_arg = uid.to_string();

    let rows = doveadm_json(&[
        "fetch", "-u", &p.email, &format!("{MESSAGE_FIELDS} text"),
        "mailbox", &q.folder, "uid", &uid_arg,
    ])
    .await?;

    match rows.as_array().and_then(|a| a.first()) {
        Some(row) => Ok(Json(json!({
            "email": p.email,
            "folder": q.folder,
            "uid": uid,
            "message": message_row(row),
            // The message as stored, headers included — what a caller that renders
            // or archives it wants, alongside the parsed fields above.
            "text": row.get("text").cloned().unwrap_or(Value::Null),
        }))),
        None => Err(ApiErr::not_found(format!("no message uid {uid} in {}", q.folder))),
    }
}

/// `DELETE /v1/me/messages/{uid}?folder=INBOX`
///
/// A delete in mail is a move to `Trash`. `permanent=true` expunges instead, and
/// a message already in `Trash` is expunged either way — that is what the folder
/// means.
async fn me_message_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<String>,
    Query(q): Query<MessageQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let uid = parse_uid(&uid)?;
    known_folder(&p.email, &q.folder).await?;
    let uid_arg = uid.to_string();

    if q.permanent.unwrap_or(false) || q.folder.eq_ignore_ascii_case("Trash") {
        doveadm(&["expunge", "-u", &p.email, "mailbox", &q.folder, "uid", &uid_arg])
            .await
            .map_err(|e| ApiErr::bad(format!("could not delete uid {uid}: {e}")))?;
        return Ok(Json(json!({
            "deleted": uid, "folder": q.folder, "permanent": true,
        })));
    }

    // `Trash` is structural: the install creates it, and a client that has just
    // emptied it still has it.
    doveadm(&["move", "-u", &p.email, "Trash", "mailbox", &q.folder, "uid", &uid_arg])
        .await
        .map_err(|e| ApiErr::bad(format!("could not move uid {uid} to Trash: {e}")))?;
    Ok(Json(json!({
        "deleted": uid, "folder": q.folder, "moved_to": "Trash", "permanent": false,
    })))
}

#[derive(Debug, Deserialize)]
struct MessageMove {
    folder: String,
    to: String,
}

/// `POST /v1/me/messages/{uid}/move` — body `{"folder":"Trash","to":"INBOX"}`.
///
/// The general case, and the two it exists for are restoring a message out of
/// `Trash` and filing one into `Sent`.
async fn me_message_move(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<String>,
    Json(body): Json<MessageMove>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let uid = parse_uid(&uid)?;
    known_folder(&p.email, &body.folder).await?;
    known_folder(&p.email, &body.to).await?;
    let uid_arg = uid.to_string();

    doveadm(&[
        "move", "-u", &p.email, &body.to, "mailbox", &body.folder, "uid", &uid_arg,
    ])
    .await
    .map_err(|e| ApiErr::bad(format!("could not move uid {uid} to {}: {e}", body.to)))?;

    Ok(Json(json!({ "moved": uid, "from": body.folder, "to": body.to })))
}

#[derive(Debug, Deserialize)]
struct FlagsChange {
    folder: String,
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
}

/// `POST /v1/me/messages/{uid}/flags` — body `{"folder":"Drafts","add":["Draft"]}`.
///
/// The answer is the flags the mailbox holds AFTER the change, read back rather
/// than predicted: `\Recent` is Dovecot's to set, and a caller that asked for
/// `Draft` should see what it actually got.
async fn me_message_flags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(uid): Path<String>,
    Json(body): Json<FlagsChange>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let uid = parse_uid(&uid)?;
    known_folder(&p.email, &body.folder).await?;
    let uid_arg = uid.to_string();
    // Both lists are validated before either is applied, so a bad name in
    // `remove` cannot leave the message half-changed.
    let add = checked_flags(&body.add)?;
    let remove = checked_flags(&body.remove)?;

    for (verb, flags) in [("add", add), ("remove", remove)] {
        for flag in flags {
            doveadm(&[
                "flags", verb, "-u", &p.email, flag, "mailbox", &body.folder, "uid", &uid_arg,
            ])
            .await
            .map_err(|e| ApiErr::bad(format!("could not {verb} {flag} on uid {uid}: {e}")))?;
        }
    }

    let rows =
        doveadm_json(&["fetch", "-u", &p.email, "uid flags", "mailbox", &body.folder, "uid", &uid_arg])
            .await?;
    let flags = rows
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r.get("flags"))
        .and_then(|v| v.as_str())
        .map(|s| s.split_whitespace().collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(Json(json!({ "uid": uid, "folder": body.folder, "flags": flags })))
}

#[derive(Debug, Deserialize)]
struct MessageAppend {
    folder: String,
    /// Flags to set once the message is written. `["\\Draft"]` for a draft.
    #[serde(default)]
    flags: Vec<String>,
    #[serde(flatten)]
    message: SendRequest,
}

/// `POST /v1/me/messages` — write a message into a folder without sending it.
///
/// How a draft is saved: the message is built by the same code `/v1/send` sends
/// with, then handed to `doveadm save`. It is also how a message is filed into
/// `Sent`, or copied into any folder.
///
/// The uid is not known until the message is written — `doveadm save` reports
/// nothing — so it is looked up by the Message-ID this server generated, and the
/// flags are applied to that. A mailbox that does not give the message back is
/// reported as saved with `uid: null` rather than as a failure.
async fn me_message_append(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MessageAppend>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    known_folder(&p.email, &body.folder).await?;
    // Everything is validated before anything is written: a bad flag or a bad
    // address must not leave behind a message the caller cannot then find.
    let flags = checked_flags(&body.flags)?;
    let draft = Draft::resolve(&p.email, body.message)?;
    let message = draft.build()?;
    let message_id = message
        .headers()
        .get_raw("Message-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();
    let raw = message.formatted();

    save_to_folder(&p.email, &body.folder, &raw)
        .await
        .map_err(|e| ApiErr::internal(format!("could not save to {}: {e}", body.folder)))?;

    let uid = find_by_message_id(&p.email, &body.folder, &message_id).await;
    if let Some(uid) = uid {
        let uid_arg = uid.to_string();
        for flag in flags {
            // The message is written either way, so a flag that will not stick is
            // logged and still reported as saved — failing here would invite the
            // caller to save a second copy.
            if let Err(e) = doveadm(&[
                "flags", "add", "-u", &p.email, flag, "mailbox", &body.folder, "uid", &uid_arg,
            ])
            .await
            {
                tracing::warn!(
                    "saved to {} but could not add {flag} to uid {uid}: {e}",
                    body.folder
                );
            }
        }
    }

    Ok(Json(json!({
        "id": message_id,
        "folder": body.folder,
        "uid": uid,
    })))
}

/// `POST /v1/me/trash/empty` — delete everything in `Trash` for good.
async fn me_trash_empty(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    // Counted first, because `expunge` reports nothing about what it removed and
    // "how much" is the only thing a caller can check afterwards.
    let before = doveadm_json(&["mailbox", "status", "-u", &p.email, "messages", "Trash"]).await?;
    let messages = before
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r.get("messages"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    doveadm(&["expunge", "-u", &p.email, "mailbox", "Trash", "ALL"])
        .await
        .map_err(|e| ApiErr::internal(format!("could not empty Trash: {e}")))?;

    Ok(Json(json!({ "emptied": "Trash", "messages": messages })))
}

// ---------------------------------------------------------------------------
// Management handlers — server-wide, so `require_permission(.., "domain")` gates each one.
// ---------------------------------------------------------------------------

/// `GET /v1/domains`
async fn domains_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    Ok(Json(backend_call(&state, &p, Method::GET, "/api/mail/domains", None).await?))
}

/// `POST /v1/domains` — body `{"domain": "example.com"}`. Creates the domain,
/// its DKIM key and (when the panel manages the zone) its DNS records.
async fn domains_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    Ok(Json(backend_call(&state, &p, Method::POST, "/api/mail/domains", Some(body)).await?))
}

/// `GET /v1/domains/{domain}`
async fn domain_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let domains = backend_call(&state, &p, Method::GET, "/api/mail/domains", None).await?;
    let row = find_by(as_array(&domains, "domains"), "domain", &domain)
        .cloned()
        .ok_or_else(|| ApiErr::not_found(format!("No mail domain {domain}")))?;
    Ok(Json(row))
}

/// `PUT /v1/domains/{domain}` — body `{"catch_all": "…", "enabled": true}`.
async fn domain_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{id}");
    Ok(Json(backend_call(&state, &p, Method::PUT, &path, Some(body)).await?))
}

/// `DELETE /v1/domains/{domain}` — removes the domain, its mailboxes and, when
/// the panel manages the zone, the DNS records it created.
async fn domain_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{id}");
    Ok(Json(backend_call(&state, &p, Method::DELETE, &path, None).await?))
}

/// `GET /v1/domains/{domain}/accounts`
async fn accounts_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{id}/accounts");
    Ok(Json(backend_call(&state, &p, Method::GET, &path, None).await?))
}

/// `POST /v1/domains/{domain}/accounts` — body
/// `{"email": "a@b.c", "password": "…", "quota_mb": 1024, "display_name": "…"}`.
async fn accounts_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{id}/accounts");
    Ok(Json(backend_call(&state, &p, Method::POST, &path, Some(body)).await?))
}

/// `PUT /v1/domains/{domain}/accounts/{email}` — any of `password`,
/// `display_name`, `quota_mb`, `enabled`, `forward_to`, `autoresponder_*`.
async fn account_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((domain, email)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let domain_id = locate_domain(&state, &p, &domain).await?;
    let account_id = account_id_in(&state, &p, &domain_id, &email).await?;
    let path = format!("/api/mail/domains/{domain_id}/accounts/{account_id}");
    Ok(Json(backend_call(&state, &p, Method::PUT, &path, Some(body)).await?))
}

/// `DELETE /v1/domains/{domain}/accounts/{email}`
async fn account_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((domain, email)): Path<(String, String)>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let domain_id = locate_domain(&state, &p, &domain).await?;
    let account_id = account_id_in(&state, &p, &domain_id, &email).await?;
    let path = format!("/api/mail/domains/{domain_id}/accounts/{account_id}");
    Ok(Json(backend_call(&state, &p, Method::DELETE, &path, None).await?))
}

/// `GET /v1/domains/{domain}/aliases`
async fn aliases_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{id}/aliases");
    Ok(Json(backend_call(&state, &p, Method::GET, &path, None).await?))
}

/// `POST /v1/domains/{domain}/aliases` — body
/// `{"source_email": "sales@…", "destination_email": "someone@…"}`.
async fn aliases_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{id}/aliases");
    Ok(Json(backend_call(&state, &p, Method::POST, &path, Some(body)).await?))
}

/// `DELETE /v1/domains/{domain}/aliases/{id}`
async fn alias_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((domain, alias_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let domain_id = locate_domain(&state, &p, &domain).await?;
    let path = format!("/api/mail/domains/{domain_id}/aliases/{alias_id}");
    Ok(Json(backend_call(&state, &p, Method::DELETE, &path, None).await?))
}

/// `GET /v1/queue` — what Postfix is holding, and why.
async fn queue_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    Ok(Json(backend_call(&state, &p, Method::GET, "/api/mail/queue", None).await?))
}

/// `POST /v1/queue/flush` — retry everything queued.
async fn queue_flush(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    Ok(Json(backend_call(&state, &p, Method::POST, "/api/mail/queue/flush", None).await?))
}

#[derive(Debug, Deserialize)]
struct QueueIdQuery {
    id: String,
}

/// `DELETE /v1/queue?id=<queue_id>` — drop one queued message.
async fn queue_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<QueueIdQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_permission(&p, "domain")?;
    let path = format!("/api/mail/queue/{}", q.id);
    Ok(Json(backend_call(&state, &p, Method::DELETE, &path, None).await?))
}

// ---------------------------------------------------------------------------
// doveadm
// ---------------------------------------------------------------------------

/// Run `doveadm`, returning stdout, or its stderr as the error.
async fn doveadm(args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new("doveadm")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("spawn doveadm: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// ---------------------------------------------------------------------------
// Address book and settings — the tables Roundcube already keeps for a mailbox.
//
// These live in the Webmail's own SQLite database rather than a store of this
// daemon's own, so a contact or identity touched here is the same one the
// webmail shows. The daemon already opens that file to resolve API tokens; the
// schema knowledge sits in the `roundcube` module, and these handlers are only
// the HTTP edge over it.
// ---------------------------------------------------------------------------

/// `GET /v1/me/contacts` — search, filter by group, sort and page.
async fn contacts_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<roundcube::ContactQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::contacts(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        &q,
    )?))
}

/// `POST /v1/me/contacts`
async fn contacts_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<roundcube::ContactInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::contact_create(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        &body,
    )?))
}

/// `GET /v1/me/contacts/{id}`
async fn contact_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::contact_get(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

/// `PUT /v1/me/contacts/{id}` — only the named fields change.
async fn contact_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<roundcube::ContactInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::contact_update(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
        &body,
    )?))
}

/// `DELETE /v1/me/contacts/{id}`
async fn contact_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::contact_delete(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

/// `GET /v1/me/contactgroups`
async fn groups_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::groups(state.cfg.roundcube_db.as_deref(), &p.email)?))
}

/// `POST /v1/me/contactgroups`
async fn group_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<roundcube::GroupInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::group_create(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        &body,
    )?))
}

/// `GET /v1/me/contactgroups/{id}` — the group and its member ids.
async fn group_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::group_get(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

/// `PUT /v1/me/contactgroups/{id}` — rename.
async fn group_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<roundcube::GroupInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::group_update(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
        &body,
    )?))
}

/// `DELETE /v1/me/contactgroups/{id}`
async fn group_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::group_delete(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

/// `PUT /v1/me/contactgroups/{id}/contacts` — body `{"contact_ids":[…]}`.
async fn group_set_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<roundcube::GroupMembers>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::group_set_members(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
        &body,
    )?))
}

/// `GET /v1/me/identities`
async fn identities_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::identities(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
    )?))
}

/// `POST /v1/me/identities`
async fn identity_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<roundcube::IdentityInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::identity_create(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        &body,
    )?))
}

/// `PUT /v1/me/identities/{id}`
async fn identity_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<roundcube::IdentityInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::identity_update(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
        &body,
    )?))
}

/// `DELETE /v1/me/identities/{id}`
async fn identity_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::identity_delete(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

/// `GET /v1/me/responses` — canned responses.
async fn responses_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::responses(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
    )?))
}

/// `POST /v1/me/responses`
async fn response_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<roundcube::ResponseInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::response_create(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        &body,
    )?))
}

/// `PUT /v1/me/responses/{id}`
async fn response_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<roundcube::ResponseInput>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::response_update(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
        &body,
    )?))
}

/// `DELETE /v1/me/responses/{id}`
async fn response_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::response_delete(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

/// `GET /v1/me/settings` — the Webmail's preferences, decoded.
async fn settings_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::preferences_get(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
    )?))
}

/// `PUT /v1/me/settings` — merge the given preferences; a `null` removes one.
async fn settings_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Map<String, Value>>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::preferences_put(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        &body,
    )?))
}

#[derive(Debug, Deserialize)]
struct CollectedQuery {
    /// 1 for recipients collected from sent mail, 2 for trusted senders.
    #[serde(default, rename = "type")]
    kind: Option<i64>,
}

/// `GET /v1/me/collected-addresses`
async fn collected_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CollectedQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::collected(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        q.kind,
    )?))
}

/// `DELETE /v1/me/collected-addresses/{id}`
async fn collected_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::collected_delete(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        id,
    )?))
}

#[derive(Debug, Deserialize)]
struct AutocompleteQuery {
    #[serde(default)]
    q: Option<String>,
}

/// `GET /v1/me/autocomplete?q=` — address suggestions for a recipient field.
async fn autocomplete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AutocompleteQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    Ok(Json(roundcube::autocomplete(
        state.cfg.roundcube_db.as_deref(),
        &p.email,
        q.q.as_deref().unwrap_or_default(),
    )?))
}

// ---------------------------------------------------------------------------

/// The OpenAPI document, embedded at build time. Serving the spec out of the
/// binary rather than off disk keeps it in step with the routes compiled into
/// that binary — a deployment cannot ship one without the other. `SwaggerUi`
/// below serves it at `/openapi.json` and renders it at `/docs`.
const OPENAPI_JSON: &str = include_str!("../openapi.json");

/// Parse the embedded spec once, so a malformed document fails loudly at startup
/// instead of quietly serving a broken `/docs` page.
fn openapi_spec() -> Value {
    serde_json::from_str(OPENAPI_JSON).expect("embedded openapi.json must be valid JSON")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dockpanel_mailapi=info".into()),
        )
        .init();

    let cfg = Arc::new(Config::load());
    let listen = cfg.listen.clone();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    // The panel's database, where mail-API tokens and their permissions live.
    // A pool that cannot be built is not fatal: the daemon still starts and the
    // legacy Roundcube-token path still works, so a mail host whose Postgres is
    // down can still send. A *failed lookup* at request time is fatal (see
    // `principal`), so a reachable pool that goes away refuses requests rather
    // than silently narrowing them.
    let pg = match &cfg.database_url {
        Some(url) if !url.trim().is_empty() => {
            match sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(5))
                .connect_lazy(url)
            {
                Ok(pool) => Some(pool),
                Err(e) => {
                    tracing::error!("could not configure the panel database pool: {e}");
                    None
                }
            }
        }
        _ => None,
    };

    let state = AppState { cfg, http, pg };

    let app = Router::new()
        .route("/health", get(health))
        // Send
        .route("/v1/send", post(send))
        .route("/emails", post(send))
        // Self-service — any mailbox token, and only for its own mailbox
        .route("/v1/me", get(me).put(me_update))
        .route("/v1/me/password", post(me_password))
        .route("/v1/me/forward", get(me_forward_get).put(me_forward_put))
        .route(
            "/v1/me/autoresponder",
            get(me_autoresponder_get).put(me_autoresponder_put),
        )
        .route("/v1/me/quota", get(me_quota))
        .route(
            "/v1/me/folders",
            get(me_folders).post(me_folder_create).delete(me_folder_delete),
        )
        // The mail IN those folders. `Drafts`, `Sent` and `Trash` are folder
        // names rather than routes, so `?folder=` picks one and these reach all.
        .route("/v1/me/messages", get(me_messages).post(me_message_append))
        .route(
            "/v1/me/messages/{uid}",
            get(me_message).delete(me_message_delete),
        )
        .route("/v1/me/messages/{uid}/move", post(me_message_move))
        .route("/v1/me/messages/{uid}/flags", post(me_message_flags))
        .route("/v1/me/trash/empty", post(me_trash_empty))
        // The address book and settings Roundcube keeps for the mailbox: same
        // tables the Webmail reads, so the two stay in step.
        .route("/v1/me/contacts", get(contacts_list).post(contacts_create))
        .route(
            "/v1/me/contacts/{id}",
            get(contact_get).put(contact_update).delete(contact_delete),
        )
        .route("/v1/me/contactgroups", get(groups_list).post(group_create))
        .route(
            "/v1/me/contactgroups/{id}",
            get(group_get).put(group_update).delete(group_delete),
        )
        .route(
            "/v1/me/contactgroups/{id}/contacts",
            put(group_set_members),
        )
        .route("/v1/me/identities", get(identities_list).post(identity_create))
        .route(
            "/v1/me/identities/{id}",
            put(identity_update).delete(identity_delete),
        )
        .route("/v1/me/responses", get(responses_list).post(response_create))
        .route(
            "/v1/me/responses/{id}",
            put(response_update).delete(response_delete),
        )
        .route("/v1/me/settings", get(settings_get).put(settings_put))
        .route("/v1/me/collected-addresses", get(collected_list))
        .route(
            "/v1/me/collected-addresses/{id}",
            delete(collected_delete),
        )
        .route("/v1/me/autocomplete", get(autocomplete))
        // Management — admin mailboxes, or a panel `dp_` API key
        .route("/v1/domains", get(domains_list).post(domains_create))
        .route(
            "/v1/domains/{domain}",
            get(domain_get).put(domain_update).delete(domain_delete),
        )
        .route(
            "/v1/domains/{domain}/accounts",
            get(accounts_list).post(accounts_create),
        )
        .route(
            "/v1/domains/{domain}/accounts/{email}",
            put(account_update).delete(account_delete),
        )
        .route(
            "/v1/domains/{domain}/aliases",
            get(aliases_list).post(aliases_create),
        )
        .route("/v1/domains/{domain}/aliases/{id}", delete(alias_delete))
        .route("/v1/queue", get(queue_list).delete(queue_delete))
        .route("/v1/queue/flush", post(queue_flush))
        // API documentation. Unauthenticated, unlike everything else: the spec
        // describes the API, it does not grant access to it, and every route it
        // documents still demands a bearer token of its own.
        .merge(
            SwaggerUi::new("/docs")
                .external_url_unchecked("/openapi.json", openapi_spec()),
        )
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {listen}: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("dockpanel-mailapi listening on {listen}");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("server error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec is embedded, so a typo in it would otherwise only surface as a
    /// broken `/docs` page in production. Parsing it here keeps that honest.
    #[test]
    fn embedded_openapi_spec_is_valid() {
        let spec = openapi_spec();
        assert!(
            spec.get("paths").is_some_and(|p| p.as_object().is_some_and(|o| !o.is_empty())),
            "the embedded spec must describe at least one path"
        );
    }

    /// A query with only the parameters a test names, the rest defaulted.
    fn query(params: Value) -> MessagesQuery {
        serde_json::from_value(params).expect("a query")
    }

    /// The argv the search builds, with no filters or text.
    fn tokens(params: Value) -> Vec<String> {
        query_of(&search_conds(&query(params)).ok().expect("valid search"))
    }

    /// A value beginning with `-` must sit behind `--`, or doveadm reads it as
    /// an option. A plain listing has no such value and keeps its old argv.
    #[test]
    fn a_leading_dash_is_never_an_option() {
        let plain = fetch_args("a@b.c", "INBOX", &[]);
        assert!(!plain.iter().any(|a| a == "--"), "no query, no separator: {plain:?}");
        assert_eq!(
            plain,
            vec!["fetch", "-u", "a@b.c", MESSAGE_FIELDS, "mailbox", "INBOX"]
        );

        let search = fetch_args(
            "a@b.c",
            "INBOX",
            &["HEADER".into(), "SUBJECT".into(), "-foo".into()],
        );
        assert_eq!(search[3], "--");
        assert_eq!(search[4], MESSAGE_FIELDS);
        assert_eq!(search.last().unwrap(), "-foo");
    }

    /// The read/unread filter, called by its two names.
    #[test]
    fn read_and_unread() {
        assert_eq!(tokens(json!({ "read": false })), vec!["UNSEEN"]);
        assert_eq!(tokens(json!({ "read": true })), vec!["SEEN"]);
        assert_eq!(tokens(json!({ "filter": "unread" })), vec!["UNSEEN"]);
        // `all` is the dropdown's "no filter" and adds nothing.
        assert!(tokens(json!({ "filter": "all" })).is_empty());
        assert!(tokens(json!({ "filter": " , " })).is_empty());
        // A name the dropdown does not carry is refused, not ignored.
        assert!(search_conds(&query(json!({ "filter": "bogus" }))).is_err());
        // Both at once would contradict, and so match nothing — that is the
        // caller's doing, not something to silently drop one half of. The
        // filter names are written first, then the read switch.
        assert_eq!(
            tokens(json!({ "read": false, "filter": "read" })),
            vec!["SEEN", "UNSEEN"]
        );
    }

    /// The Roundcube token forms, field, flag, size and date alike.
    #[test]
    fn inline_tokens() {
        assert_eq!(tokens(json!({ "q": "is:unread" })), vec!["UNSEEN"]);
        assert_eq!(
            tokens(json!({ "q": "from:alice" })),
            vec!["HEADER", "FROM", "alice"]
        );
        assert_eq!(
            tokens(json!({ "q": "subject:\"two words\"" })),
            vec!["HEADER", "SUBJECT", "two words"]
        );
        // A `-` on an option negates it.
        assert_eq!(
            tokens(json!({ "q": "-from:spam" })),
            vec!["NOT", "HEADER", "FROM", "spam"]
        );
        assert_eq!(
            tokens(json!({ "q": "larger:1M" })),
            vec!["LARGER", "1048576"]
        );
        assert_eq!(
            tokens(json!({ "q": "has:attachment" })),
            vec![
                "(",
                "HEADER",
                "CONTENT-TYPE",
                "application/",
                "OR",
                "HEADER",
                "CONTENT-TYPE",
                "multipart/mixed",
                "OR",
                "HEADER",
                "CONTENT-TYPE",
                "multipart/signed",
                "OR",
                "HEADER",
                "CONTENT-TYPE",
                "multipart/report",
                "OR",
                "(",
                "KEYWORD",
                "$HasAttachment",
                "NOT",
                "KEYWORD",
                "$HasNoAttachment",
                ")",
                ")"
            ]
        );
    }

    /// `OR` joins the term before it to the term after; `AND` is the default and
    /// is dropped; a leading `OR` with nothing on its left is dropped too.
    #[test]
    fn or_joins_its_neighbours() {
        assert_eq!(
            tokens(json!({ "q": "from:a OR from:b" })),
            vec!["(", "HEADER", "FROM", "a", "OR", "HEADER", "FROM", "b", ")"]
        );
        assert_eq!(
            tokens(json!({ "q": "from:a OR OR from:b" })),
            vec!["(", "HEADER", "FROM", "a", "OR", "HEADER", "FROM", "b", ")"]
        );
        assert_eq!(
            tokens(json!({ "q": "OR from:a" })),
            vec!["HEADER", "FROM", "a"]
        );
        assert_eq!(
            tokens(json!({ "q": "from:a AND from:b" })),
            vec!["HEADER", "FROM", "a", "HEADER", "FROM", "b"]
        );
    }

    /// Plain text is OR-ed across the fields `search` names, and a field name
    /// that is not one of them is refused rather than dropped.
    #[test]
    fn plain_text_spans_the_chosen_fields() {
        assert_eq!(
            tokens(json!({ "q": "hello", "search": "subject,from" })),
            vec!["(", "HEADER", "SUBJECT", "hello", "OR", "HEADER", "FROM", "hello", ")"]
        );
        // `all` reaches the body too: five headers at three keys each, the body
        // at two, five ORs and the two parentheses.
        assert_eq!(
            tokens(json!({ "q": "hello", "search": "all" })).len(),
            5 * 3 + 2 + 5 + 2
        );
        assert!(search_conds(&query(json!({ "search": "subject,bogus" }))).is_err());
    }

    /// A bare `q` reads Roundcube's default fields — `subject`+`from`, and
    /// `subject`+`to` in the folders the account writes into.
    #[test]
    fn a_bare_query_uses_roundcubes_default_fields() {
        let subject_from =
            vec!["(", "HEADER", "SUBJECT", "hello", "OR", "HEADER", "FROM", "hello", ")"];
        let subject_to =
            vec!["(", "HEADER", "SUBJECT", "hello", "OR", "HEADER", "TO", "hello", ")"];

        assert_eq!(tokens(json!({ "q": "hello" })), subject_from);
        assert_eq!(tokens(json!({ "q": "hello", "folder": "INBOX" })), subject_from);
        assert_eq!(tokens(json!({ "q": "hello", "folder": "Sent" })), subject_to);
        assert_eq!(tokens(json!({ "q": "hello", "folder": "Drafts" })), subject_to);
        // A child of either counts as one of them, whichever separator is used.
        assert_eq!(tokens(json!({ "q": "hello", "folder": "Sent.2026" })), subject_to);
        assert_eq!(tokens(json!({ "q": "hello", "folder": "Drafts/notes" })), subject_to);
        // Naming fields still wins over the default.
        assert_eq!(tokens(json!({ "q": "hello", "search": "body" })), vec!["BODY", "hello"]);
    }

    /// An option with no value is not an option: Roundcube reads the token as
    /// plain text, and so does this.
    #[test]
    fn an_option_with_no_value_is_text() {
        assert_eq!(
            tokens(json!({ "q": "from:" })),
            vec!["(", "HEADER", "SUBJECT", "from:", "OR", "HEADER", "FROM", "from:", ")"]
        );
    }

    /// The sort names Roundcube offers, and the two that resolve rather than
    /// name a column of their own.
    #[test]
    fn sort_names_resolve_like_roundcube() {
        assert_eq!(Sort::parse(None, "INBOX").ok(), Some(Sort::Date));
        assert_eq!(Sort::parse(Some("fromto"), "INBOX").ok(), Some(Sort::From));
        assert_eq!(Sort::parse(Some("fromto"), "Sent").ok(), Some(Sort::To));
        assert_eq!(Sort::parse(Some("fromto"), "Drafts").ok(), Some(Sort::To));
        assert_eq!(Sort::parse(Some("fromto"), "Sent.2026").ok(), Some(Sort::To));
        assert_eq!(Sort::parse(Some("none"), "INBOX").ok(), Some(Sort::None));
        assert!(Sort::parse(Some("bogus"), "INBOX").is_err());
    }

    /// The interval dropdown resolves to a date here, because Dovecot would read
    /// `1M` as one minute.
    #[test]
    fn intervals_resolve_to_dates() {
        let since = interval_date("1M").expect("1M");
        assert_eq!(since.len(), 10, "{since}");
        assert!(since.as_bytes()[4] == b'-');

        assert_eq!(query_of(&[interval_cond("1W").ok().expect("1W")])[0], "SINCE");
        assert_eq!(query_of(&[interval_cond("-1W").ok().expect("-1W")])[0], "BEFORE");
        assert!(interval_cond("1M").is_ok());
        assert!(interval_cond("1Y").is_ok());
        assert!(interval_cond("nonsense").is_err());
    }

    /// Size suffixes, and a bare number read as octets.
    #[test]
    fn sizes_are_bytes() {
        assert_eq!(size_bytes("1M").as_deref(), Some("1048576"));
        assert_eq!(size_bytes("500k").as_deref(), Some("512000"));
        assert_eq!(size_bytes("1024").as_deref(), Some("1024"));
        assert_eq!(size_bytes("0").as_deref(), Some("0"));
        assert_eq!(size_bytes("x").as_deref(), None);
    }

    /// Dates are read from both formats the two sort keys arrive in.
    #[test]
    fn dates_parse() {
        let sent = parse_sent(Some("Tue, 19 Jan 2010 01:17:41 +0100"));
        assert!(sent.is_some(), "an RFC 2822 Date header should parse");
        assert!(parse_received(Some("2010-01-19 01:17:41 (+0100)")).is_some());
        assert!(parse_received(Some("not a date")).is_none());
    }

    /// The sort is total regardless of the column, so two equal keys never
    /// reorder between requests.
    #[test]
    fn sorting_is_total() {
        let mut rows = vec![
            Row {
                message: json!({ "uid": 3 }),
                folder: "INBOX".to_string(),
                uid: 3,
                size: 30,
                subject: "b".to_string(),
                from: String::new(),
                to: String::new(),
                cc: String::new(),
                sent: 10,
                received: 10,
            },
            Row {
                message: json!({ "uid": 1 }),
                folder: "INBOX".to_string(),
                uid: 1,
                size: 10,
                subject: "a".to_string(),
                from: String::new(),
                to: String::new(),
                cc: String::new(),
                sent: 30,
                received: 30,
            },
        ];
        sort_rows(&mut rows, Sort::Size, true);
        assert_eq!(rows.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![3, 1]);
        // `none` keeps Dovecot's uid order ascending, and reverts it descending.
        sort_rows(&mut rows, Sort::None, false);
        assert_eq!(rows.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![3, 1]);
        sort_rows(&mut rows, Sort::None, true);
        assert_eq!(rows.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![1, 3]);
        sort_rows(&mut rows, Sort::Size, false);
        assert_eq!(rows.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![1, 3]);
        sort_rows(&mut rows, Sort::Date, true);
        assert_eq!(rows.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![1, 3]);
    }

    /// `none` reverts each folder's run, not the whole result, so the folders
    /// keep the order Dovecot listed them in.
    #[test]
    fn none_reverts_within_each_folder() {
        let folder = |name: &str, uids: &[u64]| {
            uids.iter()
                .map(|&uid| Row {
                    message: json!({ "uid": uid }),
                    folder: name.to_string(),
                    uid,
                    size: 0,
                    subject: String::new(),
                    from: String::new(),
                    to: String::new(),
                    cc: String::new(),
                    sent: 0,
                    received: 0,
                })
                .collect::<Vec<_>>()
        };
        let mut all = folder("INBOX", &[1, 3]);
        all.extend(folder("Sent", &[2, 4]));

        sort_rows(&mut all, Sort::None, false);
        assert_eq!(all.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![1, 3, 2, 4]);
        sort_rows(&mut all, Sort::None, true);
        assert_eq!(all.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![3, 1, 4, 2]);
    }

    /// A message carries the folder that makes its uid mean something.
    #[test]
    fn rows_are_folder_qualified() {
        let raw = json!({
            "uid": "7",
            "flags": "\\Seen",
            "size.virtual": "42",
            "hdr.subject": "hi",
            "hdr.date": "Tue, 19 Jan 2010 01:17:41 +0100",
        });
        let row = Row::new(&raw, "Sent");
        assert_eq!(row.message.get("folder").and_then(|v| v.as_str()), Some("Sent"));
        assert_eq!(row.uid, 7);
        assert_eq!(row.size, 42);
    }

    /// A token only ever holds the intersection of what it was granted and what
    /// its mailbox is allowed now — this is the rule that makes a role change
    /// take effect on tokens already handed out, so it is pinned directly.
    #[test]
    fn a_token_is_capped_by_its_mailbox() {
        let keys = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // Granted `domain` and `me`, mailbox still allowed both.
        let p = intersect_token_permissions(&keys(&["me", "domain"]), &keys(&["me", "domain"]));
        assert!(p.has("me") && p.has("domain"));

        // The mailbox was moved back to `me`: the token loses `domain` at once,
        // with no need to find and revoke it.
        let p = intersect_token_permissions(&keys(&["me", "domain"]), &keys(&["me"]));
        assert!(p.has("me") && !p.has("domain"));

        // A token may be narrower than its mailbox, and stays that way.
        let p = intersect_token_permissions(&keys(&["me"]), &keys(&["me", "domain"]));
        assert!(p.has("me") && !p.has("domain"));

        // An empty grant is not a wildcard.
        let p = intersect_token_permissions(&keys(&[]), &keys(&["me", "domain"]));
        assert!(!p.has("me") && !p.has("domain"));
    }
}
