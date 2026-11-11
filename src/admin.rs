//! admin 側。公開側とは別の loopback ポートで待ち受け、nginx からは中継しない。
//!
//! - `POST /admin/drops`          発行（`text` で先入れ可、`ttl_secs` で TTL 指定可）
//! - `DELETE /admin/drops/<token>` 明示破棄

use crate::store::{IssueError, TextError};
use crate::web::{
    not_found, not_found_handler, plain, security_headers, token_in_path, AppState, MAX_BODY_BYTES,
};
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router};
use std::net::IpAddr;
use tokio::time::Instant;

const DROP_PATH_PREFIX: &str = "/admin/drops/";

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/admin/drops", post(issue).fallback(not_found_handler))
        .route(
            "/admin/drops/{token}",
            delete(remove).fallback(not_found_handler),
        )
        .fallback(not_found_handler)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(require_loopback_host))
        .layer(middleware::map_response(security_headers))
        .with_state(state)
}

/// DNS rebinding 対策。loopback で待ち受けていても、同じホスト上のブラウザ経由で
/// 他オリジンのページから叩かれうるので、Host が loopback 名でないリクエストは拒否する。
async fn require_loopback_host(request: Request, next: Next) -> Response {
    let allowed = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_loopback_host);
    if !allowed {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    next.run(request).await
}

fn is_loopback_host(value: &str) -> bool {
    let host = match value.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((host, _)) => host,
            None => return false,
        },
        None => value.split_once(':').map_or(value, |(host, _)| host),
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(serde::Serialize)]
struct IssueResponse {
    token: String,
    url_path: String,
    ttl_secs: u64,
}

async fn issue(
    State(state): State<AppState>,
    body: Result<Json<IssueRequest>, JsonRejection>,
) -> Response {
    let request = match body {
        Ok(Json(request)) => request,
        // serde のエラー文は入力値を含みうるので返さない
        Err(rejection) => return plain(rejection.status(), "invalid request\n"),
    };
    let prefilled = request.text.is_some();
    let issued = state
        .store()
        .issue(Instant::now(), request.ttl_secs, request.text);
    match issued {
        Ok((token, ttl)) => {
            tracing::info!(prefilled, ttl_secs = ttl.as_secs(), "drop issued");
            let token = token.encode();
            let body = IssueResponse {
                url_path: format!("/{token}"),
                token,
                ttl_secs: ttl.as_secs(),
            };
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(IssueError::InvalidTtl) => plain(StatusCode::BAD_REQUEST, "invalid ttl_secs\n"),
        Err(IssueError::Text(TextError::Empty)) => plain(StatusCode::BAD_REQUEST, "empty text\n"),
        Err(IssueError::Text(TextError::TooLong)) => plain(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too long (max 1024 characters)\n",
        ),
        Err(IssueError::TooManyDrops) => {
            tracing::warn!("drop count limit reached; issue rejected");
            plain(StatusCode::SERVICE_UNAVAILABLE, "too many drops\n")
        }
        Err(IssueError::StorageFull) => {
            tracing::warn!("storage limit reached; issue rejected");
            plain(StatusCode::SERVICE_UNAVAILABLE, "storage full\n")
        }
        Err(IssueError::Rng) => {
            tracing::error!("OS random number generator failed");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
        }
    }
}

async fn remove(State(state): State<AppState>, uri: Uri) -> Response {
    let Some(token) = token_in_path(uri.path(), DROP_PATH_PREFIX) else {
        return not_found();
    };
    let removed = state.store().remove(Instant::now(), &token);
    if removed {
        tracing::info!("drop deleted");
        StatusCode::NO_CONTENT.into_response()
    } else {
        not_found()
    }
}

#[cfg(test)]
mod tests {
    use super::is_loopback_host;

    #[test]
    fn loopback_hosts() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:8471",
            "127.1.2.3:1",
            "localhost",
            "LOCALHOST:8471",
            "[::1]",
            "[::1]:8471",
        ] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for ng in [
            "",
            "example.com",
            "evil.example:8471",
            "localhost.evil.example",
            "127.0.0.1.nip.io",
            "192.0.2.1:8471",
            "[::2]:8471",
            "[::1",
            "0.0.0.0",
        ] {
            assert!(!is_loopback_host(ng), "{ng}");
        }
    }
}
