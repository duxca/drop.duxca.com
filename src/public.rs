//! 公開側（`https://drop.duxca.com/<token>`）。トークン自体が capability。
//!
//! loopback admin のルートはここに入れない。nginx 中継後の送信元も loopback になるため、
//! 送信元 IP では公開と admin を区別できない。区別は待ち受けポート（= 別の Router）だけで行う。
//! 例外は遠隔 admin の発行（`POST /api/drops`）だけで、場所ではなく資格情報
//! （Bearer トークンの SHA-256 検証子）で守る。認証は本文を読む前にヘッダだけで行い、
//! 失敗は他の未知パスと同じ 404 を返す。

use crate::admin::{issue_drop, IssueRequest};
use crate::store::{FillError, Status, TakeError, TextError, MAX_TEXT_CHARS};
use crate::token::Token;
use crate::web::{
    escape_html, not_found, not_found_handler, plain, security_headers, token_in_path, AppState,
    RemoteAdminKey, MAX_BODY_BYTES,
};
use axum::extract::rejection::{FormRejection, JsonRejection};
use axum::extract::{DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, post};
use axum::{middleware, Extension, Form, Json, Router};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::time::Instant;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/{token}", any(dispatch))
        .route(
            "/api/drops",
            post(remote_issue)
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_remote_admin,
                ))
                .fallback(not_found_handler),
        )
        .fallback(not_found_handler)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::map_response(security_headers))
        .with_state(state)
}

/// 遠隔 admin の認証。Authorization ヘッダだけを見て、本文は読まない。
/// 検証子が未設定なら常に 404（遠隔 admin 無効）。
async fn require_remote_admin(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let fingerprint = bearer_token(request.headers()).and_then(|token| {
        let digest = Sha256::digest(token.as_bytes());
        state
            .remote_admin_hashes()
            .iter()
            .find(|hash| bool::from(digest.ct_eq(*hash)))
            .map(|hash| {
                hash[..4]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
    });
    match fingerprint {
        Some(fingerprint) => {
            request.extensions_mut().insert(RemoteAdminKey(fingerprint));
            next.run(request).await
        }
        None => {
            // 資格情報の有無・正否は応答では区別しない。本文もトークンもログに出さない。
            tracing::debug!("remote admin authentication failed");
            not_found()
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// 認証済みの遠隔発行。本文の形式と発行条件は loopback admin と同じ。
async fn remote_issue(
    State(state): State<AppState>,
    Extension(key): Extension<RemoteAdminKey>,
    body: Result<Json<IssueRequest>, JsonRejection>,
) -> Response {
    let request = match body {
        Ok(Json(request)) => request,
        Err(rejection) => return plain(rejection.status(), "invalid request\n"),
    };
    let response = issue_drop(&state, request);
    if response.status() == StatusCode::CREATED {
        tracing::info!(key_fingerprint = %key.0, "remote drop issued");
    }
    response
}

/// GET と POST だけを受ける。それ以外は 404（405 や Allow ヘッダも返さない）。
/// HEAD も 404。axum の get() は HEAD を GET ハンドラに回すため、そのままだと HEAD で take が走る。
async fn dispatch(State(state): State<AppState>, request: Request) -> Response {
    let uri = request.uri().clone();
    match *request.method() {
        Method::GET => show_or_take(&state, &uri),
        Method::POST => {
            let form = Form::<Submission>::from_request(request, &state).await;
            submit(&state, &uri, form)
        }
        _ => not_found(),
    }
}

#[derive(serde::Deserialize)]
struct Submission {
    text: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Show,
    Take,
    Invalid,
}

/// `take=1` のときだけ取り出し。`take` が他の値・重複なら 404。`take` 以外のクエリは無視する。
fn mode(query: Option<&str>) -> Mode {
    let mut take = None;
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "take" {
            if take.is_some() {
                return Mode::Invalid;
            }
            take = Some(value);
        }
    }
    match take {
        None => Mode::Show,
        Some("1") => Mode::Take,
        Some(_) => Mode::Invalid,
    }
}

fn show_or_take(state: &AppState, uri: &Uri) -> Response {
    let Some(token) = token_in_path(uri.path(), "/") else {
        return not_found();
    };
    let now = Instant::now();
    match mode(uri.query()) {
        Mode::Invalid => not_found(),
        Mode::Show => match state.store().status(now, &token) {
            None => not_found(),
            Some(Status::Empty) => Html(form_page(&token)).into_response(),
            Some(Status::Filled) => Html(RECEIVED_PAGE).into_response(),
        },
        Mode::Take => {
            let taken = state.store().take(now, &token);
            match taken {
                Ok(text) => {
                    tracing::info!("drop taken");
                    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response()
                }
                // VM 側が「まだ」と「消えた」を区別できるように 409 と 404 を分ける
                Err(TakeError::NotFilled) => plain(StatusCode::CONFLICT, "not submitted yet\n"),
                Err(TakeError::NotFound) => not_found(),
            }
        }
    }
}

fn submit(state: &AppState, uri: &Uri, form: Result<Form<Submission>, FormRejection>) -> Response {
    let Some(token) = token_in_path(uri.path(), "/") else {
        return not_found();
    };
    let now = Instant::now();
    let result = {
        let mut store = state.store();
        // 存在・書き込み済みの判定をボディの形式より先に返す
        match store.status(now, &token) {
            None => Err(FillError::NotFound),
            Some(Status::Filled) => Err(FillError::AlreadyFilled),
            Some(Status::Empty) => match form {
                Ok(Form(submission)) => store.fill(now, &token, submission.text),
                // 値を含みうるので rejection の本文は返さない
                Err(rejection) => return plain(rejection.status(), "invalid form\n"),
            },
        }
    };
    match result {
        Ok(()) => {
            tracing::info!("drop filled");
            Html(RECEIVED_PAGE).into_response()
        }
        Err(FillError::NotFound) => not_found(),
        Err(FillError::AlreadyFilled) => plain(StatusCode::GONE, "already submitted\n"),
        Err(FillError::Text(TextError::TooLong)) => plain(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too long (max 1024 characters)\n",
        ),
        Err(FillError::Text(TextError::Empty)) => plain(StatusCode::BAD_REQUEST, "empty text\n"),
        Err(FillError::StorageFull) => {
            tracing::warn!("storage limit reached; submission rejected");
            plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage full, try again later\n",
            )
        }
    }
}

const RECEIVED_PAGE: &str = r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>drop</title>
</head>
<body>
<p>受付済み</p>
</body>
</html>
"#;

fn form_page(token: &Token) -> String {
    let action = escape_html(&token.encode());
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>drop</title>
</head>
<body>
<form method="post" action="{action}" accept-charset="utf-8">
<p><label for="text">テキスト（送信は 1 回だけ・最大 {MAX_TEXT_CHARS} 字）</label></p>
<p><textarea id="text" name="text" rows="8" cols="60" maxlength="{MAX_TEXT_CHARS}" required autocomplete="off" autocapitalize="off" spellcheck="false"></textarea></p>
<p><button type="submit">送信</button></p>
</form>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_modes() {
        assert_eq!(mode(None), Mode::Show);
        assert_eq!(mode(Some("")), Mode::Show);
        assert_eq!(mode(Some("utm_source=x")), Mode::Show);
        assert_eq!(mode(Some("take=1")), Mode::Take);
        assert_eq!(mode(Some("x=y&take=1")), Mode::Take);
        assert_eq!(mode(Some("take=0")), Mode::Invalid);
        assert_eq!(mode(Some("take")), Mode::Invalid);
        assert_eq!(mode(Some("take=true")), Mode::Invalid);
        assert_eq!(mode(Some("take=1&take=1")), Mode::Invalid);
    }
}
