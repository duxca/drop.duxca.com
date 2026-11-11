//! 公開側・admin 側で共有する HTTP まわり。

use crate::store::Store;
use crate::token::Token;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// リクエストボディの上限。1024 字すべてを 4 バイト文字にして
/// フォームのパーセントエンコード（12 バイト/字）や JSON の \u エスケープ（12 バイト/字）にしても収まる。
pub const MAX_BODY_BYTES: usize = 16 * 1024;

const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// 単一スレッド（current_thread）で動かすが、axum のハンドラは Send を要求するので Mutex で包む。
/// ロックは await をまたがない。
#[derive(Clone)]
pub struct AppState(Arc<Mutex<Store>>);

impl AppState {
    pub fn new(store: Store) -> Self {
        Self(Arc::new(Mutex::new(store)))
    }

    pub fn store(&self) -> MutexGuard<'_, Store> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `prefix` の直後がちょうど正規形のトークンであるパスだけを受け付ける。
/// パーセントデコード前の生のパスで判定する。
pub fn token_in_path(path: &str, prefix: &str) -> Option<Token> {
    Token::parse(path.strip_prefix(prefix)?)
}

pub fn plain(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

pub fn not_found() -> Response {
    plain(StatusCode::NOT_FOUND, "not found\n")
}

/// 未知のパス・メソッドはすべて 404（405 や Allow ヘッダも出さない）。
pub async fn not_found_handler() -> Response {
    not_found()
}

/// 全レスポンスに付ける。本文は text/plain でしか返さないが、HTML 側も含めて
/// スクリプト実行・MIME 推測・キャッシュ・埋め込み・Referer 経由のトークン漏れを塞ぐ。
pub async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// HTML 属性値・テキスト用のエスケープ。
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_special_characters() {
        assert_eq!(
            escape_html(r#"/a"b'c<d>e&f"#),
            "/a&quot;b&#39;c&lt;d&gt;e&amp;f"
        );
        assert_eq!(escape_html("/AZaz09-_"), "/AZaz09-_");
    }

    #[test]
    fn token_in_path_requires_exact_prefix_and_token() {
        let token = Token::generate().unwrap();
        let s = token.encode();
        assert!(token_in_path(&format!("/{s}"), "/") == Some(token));
        assert!(token_in_path(&format!("/{s}/"), "/").is_none());
        assert!(token_in_path(&format!("//{s}"), "/").is_none());
        assert!(token_in_path(&format!("/x/{s}"), "/").is_none());
        assert!(token_in_path(&format!("/admin/drops/{s}"), "/admin/drops/") == Some(token));
        assert!(token_in_path(&s, "/").is_none());
    }
}
