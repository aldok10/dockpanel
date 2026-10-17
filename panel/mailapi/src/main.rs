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
//!   * an opaque API token created in Roundcube (sha256 looked up in its SQLite
//!     `dockpanel_mailapi_tokens` table), or
//!   * a JWT signed with the panel's `JWT_SECRET` (HS256) that carries an
//!     `email` claim — the "internal" path used by the panel itself, or
//!   * a panel API key (`dp_…`), which is forwarded to the backend untouched so
//!     the panel's own authorization decides what it may do.
//!
//! A token identifies a MAILBOX, so what it may manage follows from that:
//! every mailbox may manage itself (`/v1/me/*`, and `/v1/send`), and a mailbox
//! listed in `MAILAPI_ADMIN_EMAILS` may manage the whole server
//! (`/v1/domains/*`, `/v1/queue`). Management is not reimplemented here: the
//! daemon calls the panel backend's existing `/api/mail/*` routes over loopback,
//! so there is one implementation of each operation and one place where its
//! authorization rule lives. The `dp_` key it presents for that leg is
//! `MAILAPI_BACKEND_API_KEY` — a service credential, not the caller's.
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
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// A recipient list that may arrive either as a bare string or an array.
#[derive(Debug, Deserialize)]
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
    /// Mailboxes allowed the full management surface. Everyone else gets
    /// self-service; see `Principal`.
    admin_emails: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    /// One pooled client for the loopback calls into the panel backend.
    http: reqwest::Client,
}

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

        let admin_emails = get("MAILAPI_ADMIN_EMAILS")
            .map(|s| {
                s.split(',')
                    .map(|e| e.trim().to_lowercase())
                    .filter(|e| !e.is_empty())
                    .collect::<Vec<_>>()
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
            admin_emails,
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

/// The sender a token (or JWT) is allowed to send as.
fn resolve_identity(cfg: &Config, token: &str) -> Option<String> {
    // 1. JWT signed with the panel secret, carrying an email claim.
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
                            return Some(email.to_lowercase());
                        }
                    }
                }
            }
        }
    }

    // 2. Opaque API token created in Roundcube.
    let hash = sha256_hex(token);
    if let Some(email) = lookup_roundcube_token(cfg, &hash) {
        return Some(email);
    }

    // 3. Static host-local token.
    cfg.static_tokens
        .iter()
        .find(|(t, _)| t.as_str() == token)
        .map(|(_, e)| e.to_lowercase())
}

/// Look up `token_hash` in Roundcube's token table. Returns the mailbox email.
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

/// What a request's credential resolves to.
struct Principal {
    /// The mailbox the credential speaks for.
    email: String,
    /// May manage domains, other mailboxes and the mail queue.
    is_admin: bool,
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

/// Resolve a bearer credential into the mailbox it speaks for.
///
/// Three credential classes, and the difference between them is the whole
/// authorization story:
///   * a panel `dp_` key — the panel already knows what its user may do, so it
///     is forwarded untouched and the backend decides;
///   * a mailbox token (or the panel's JWT) — identifies a MAILBOX, and a
///     mailbox may always act on itself. Server-wide access is granted only by
///     `MAILAPI_ADMIN_EMAILS`, never inferred from the address.
async fn principal(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiErr> {
    let token = bearer_token(headers)
        .ok_or_else(|| ApiErr::unauthorized("Missing API token (Authorization: Bearer <token>)"))?;

    if token.starts_with("dp_") {
        let email = backend_me(state, &token).await?;
        return Ok(Principal {
            email,
            is_admin: true,
            passthrough_key: Some(token),
        });
    }

    let email = resolve_identity(&state.cfg, &token)
        .ok_or_else(|| ApiErr::unauthorized("Invalid or revoked API token"))?
        // The Roundcube path returns whatever case the plugin stored; the JWT and
        // static paths already lowercase. Normalising here means a mixed-case row
        // does not silently fall outside MAILAPI_ADMIN_EMAILS, nor fail the
        // sender check in `send`, which compares lowercased addresses.
        .to_lowercase();
    let is_admin = state.cfg.admin_emails.iter().any(|e| e == &email);
    Ok(Principal {
        email,
        is_admin,
        passthrough_key: None,
    })
}

/// Refuse a server-wide operation for a mailbox that may only manage itself.
fn require_admin(p: &Principal) -> Result<(), ApiErr> {
    if p.is_admin {
        return Ok(());
    }
    Err(ApiErr::forbidden(format!(
        "{} may only manage its own mailbox. Add it to MAILAPI_ADMIN_EMAILS for server-wide access.",
        p.email
    )))
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
        "admin": p.is_admin,
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
    "uid flags size.virtual date.sent hdr.subject hdr.from hdr.to hdr.cc hdr.date";

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

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    /// Defaults to `INBOX`.
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
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
/// `folder` defaults to `INBOX`. Newest first, with `limit` and `offset` applied
/// over that order.
async fn me_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MessagesQuery>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    let folder = q.folder.unwrap_or_else(|| "INBOX".to_string());
    known_folder(&p.email, &folder).await?;

    let rows = doveadm_json(&["fetch", "-u", &p.email, MESSAGE_FIELDS, "mailbox", &folder]).await?;

    // `doveadm fetch` walks the folder in uid order, which is oldest first, while
    // a mail client shows the newest. Sort rather than reverse, so the order does
    // not depend on how the storage backend happens to iterate.
    let mut messages: Vec<Value> = rows
        .as_array()
        .map(|a| a.iter().map(message_row).collect())
        .unwrap_or_default();
    messages.sort_by_key(|m| std::cmp::Reverse(m.get("uid").and_then(|v| v.as_u64()).unwrap_or(0)));

    let total = messages.len();
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(500);
    let page: Vec<Value> = messages.into_iter().skip(offset).take(limit).collect();

    Ok(Json(json!({
        "email": p.email,
        "folder": folder,
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
// Management handlers — server-wide, so `require_admin` gates each one.
// ---------------------------------------------------------------------------

/// `GET /v1/domains`
async fn domains_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_admin(&p)?;
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
    require_admin(&p)?;
    Ok(Json(backend_call(&state, &p, Method::POST, "/api/mail/domains", Some(body)).await?))
}

/// `GET /v1/domains/{domain}`
async fn domain_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    require_admin(&p)?;
    Ok(Json(backend_call(&state, &p, Method::GET, "/api/mail/queue", None).await?))
}

/// `POST /v1/queue/flush` — retry everything queued.
async fn queue_flush(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    let p = principal(&state, &headers).await?;
    require_admin(&p)?;
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
    require_admin(&p)?;
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
    let state = AppState { cfg, http };

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
