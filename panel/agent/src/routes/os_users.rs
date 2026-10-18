//! Agent-side endpoints for per-user OS (SSH) login accounts. Thin, like every
//! route module here: validation and response shaping only, with the real work
//! in `services::os_accounts`.

use axum::{extract::Path, http::StatusCode, routing::{delete, post}, Json, Router};
use serde::Deserialize;

use super::AppState;
use crate::services::os_accounts;

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(Deserialize)]
struct ProvisionRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct PasswordRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LockRequest {
    username: String,
    locked: bool,
}

/// The panel hashes the same password itself with Argon2, but its own floor is
/// eight characters; the OS account must not be weaker, so refuse anything the
/// panel would also have refused.
fn check_password(password: &str) -> Result<(), ApiErr> {
    if password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }
    if password.len() > 128 {
        return Err(err(StatusCode::BAD_REQUEST, "Password must be at most 128 characters"));
    }
    Ok(())
}

/// POST /os-users/provision
///
/// A name refusal (bad syntax, reserved, or already present) is the caller's
/// mistake and goes back as 400 with the reason; only a genuine system failure
/// is a 500. `validate_username` is what separates the two, so it runs here
/// first even though `provision` will run it again — the second call is cheap
/// and the first is what gives the honest status code.
async fn provision(Json(body): Json<ProvisionRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    check_password(&body.password)?;
    os_accounts::validate_username(&body.username)
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    os_accounts::provision(&body.username, &body.password)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true, "username": body.username })))
}

/// POST /os-users/password
async fn set_password(Json(body): Json<PasswordRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    check_password(&body.password)?;
    os_accounts::set_password(&body.username, &body.password)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /os-users/state — lock or unlock the account password.
async fn set_state(Json(body): Json<LockRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    os_accounts::set_locked(&body.username, body.locked)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true, "locked": body.locked })))
}

/// DELETE /os-users/{username}
async fn remove(Path(username): Path<String>) -> Result<Json<serde_json::Value>, ApiErr> {
    os_accounts::deprovision(&username)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/os-users/provision", post(provision))
        .route("/os-users/password", post(set_password))
        .route("/os-users/state", post(set_state))
        .route("/os-users/{username}", delete(remove))
}
