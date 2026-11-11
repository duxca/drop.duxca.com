//! HTTP の振る舞いを tower::ServiceExt::oneshot で検証する。

use crate::store::{Limits, Store, MAX_TEXT_CHARS};
use crate::web::AppState;
use crate::{admin, public};
use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tower::ServiceExt;

const ADMIN_HOST: &str = "127.0.0.1:8471";
const PUBLIC_HOST: &str = "drop.example.test";
const CSP: &str = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn default_limits() -> Limits {
    Limits {
        max_drops: 1000,
        max_total_bytes: 1024 * 1024,
        default_ttl: Duration::from_secs(600),
        max_ttl: Duration::from_secs(3600),
    }
}

struct Harness {
    public: Router,
    admin: Router,
    state: AppState,
}

impl Harness {
    fn new() -> Self {
        Self::with_limits(default_limits())
    }

    fn with_limits(limits: Limits) -> Self {
        let state = AppState::new(Store::new(limits));
        Self {
            public: public::router(state.clone()),
            admin: admin::router(state.clone()),
            state,
        }
    }

    async fn public(&self, request: Request<Body>) -> Reply {
        send(&self.public, request).await
    }

    async fn admin(&self, request: Request<Body>) -> Reply {
        send(&self.admin, request).await
    }

    async fn issue(&self, body: Value) -> Reply {
        self.admin(admin_json(Method::POST, "/admin/drops", &body.to_string()))
            .await
    }

    /// 発行してトークンを返す。
    async fn issue_token(&self, body: Value) -> String {
        let reply = self.issue(body).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        let json: Value = serde_json::from_str(&reply.body).unwrap();
        let token = json["token"].as_str().unwrap().to_string();
        assert_eq!(json["url_path"], format!("/{token}"));
        token
    }

    async fn show(&self, token: &str) -> Reply {
        self.public(public_request(Method::GET, &format!("/{token}")))
            .await
    }

    async fn take(&self, token: &str) -> Reply {
        self.public(public_request(Method::GET, &format!("/{token}?take=1")))
            .await
    }

    async fn submit(&self, token: &str, text: &str) -> Reply {
        self.public(form_post(
            &format!("/{token}"),
            &format!("text={}", urlencode(text)),
        ))
        .await
    }

    async fn delete(&self, token: &str) -> Reply {
        self.admin(admin_request(
            Method::DELETE,
            &format!("/admin/drops/{token}"),
        ))
        .await
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn content_type(&self) -> &str {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    fn header(&self, name: header::HeaderName) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

fn public_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, PUBLIC_HOST)
        .body(Body::empty())
        .unwrap()
}

fn form_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, PUBLIC_HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn admin_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, ADMIN_HOST)
        .body(Body::empty())
        .unwrap()
}

fn admin_json(method: Method, uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, ADMIN_HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn assert_security_headers(reply: &Reply) {
    assert_eq!(reply.header(header::CONTENT_SECURITY_POLICY), CSP);
    assert_eq!(reply.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    assert_eq!(reply.header(header::REFERRER_POLICY), "no-referrer");
}

// ---- 公開側: 基本の流れ ----

#[tokio::test]
async fn full_flow_issue_show_submit_take() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    assert_eq!(token.len(), 22);

    let form = h.show(&token).await;
    assert_eq!(form.status, StatusCode::OK);
    assert_eq!(form.content_type(), "text/html; charset=utf-8");
    assert!(form.body.contains(r#"name="text""#));
    assert!(form.body.contains(r#"maxlength="1024""#));
    assert!(form.body.contains(&format!(r#"action="{token}""#)));
    assert!(form.body.contains(r#"method="post""#));
    assert!(!form.body.contains("<script"));
    assert_security_headers(&form);

    // まだ投稿されていない take は 409（値が無いだけで、ドロップは残る）
    let early = h.take(&token).await;
    assert_eq!(early.status, StatusCode::CONFLICT);
    assert_security_headers(&early);
    assert_eq!(h.show(&token).await.status, StatusCode::OK);

    let secret = "https://example.test/login?otp=ABC&x=<b>\"'";
    let accepted = h.submit(&token, secret).await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert!(accepted.body.contains("受付済み"));
    assert!(!accepted.body.contains("otp=ABC"));
    assert_security_headers(&accepted);

    // 投稿済みのページは「受付済み」だけで、値は出さない
    let shown = h.show(&token).await;
    assert_eq!(shown.status, StatusCode::OK);
    assert!(shown.body.contains("受付済み"));
    assert!(!shown.body.contains("otp=ABC"));
    assert!(!shown.body.contains("<form"));

    // 2 回目の書き込みは 410、値は最初のまま
    let second = h.submit(&token, "overwrite").await;
    assert_eq!(second.status, StatusCode::GONE);

    let taken = h.take(&token).await;
    assert_eq!(taken.status, StatusCode::OK);
    assert_eq!(taken.content_type(), "text/plain; charset=utf-8");
    assert_eq!(taken.body, secret);
    assert_security_headers(&taken);

    // 回収後は全部 404
    assert_eq!(h.take(&token).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.show(&token).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        h.submit(&token, "again").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.delete(&token).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn multibyte_text_is_counted_by_unicode_scalar_values() {
    let h = Harness::new();
    for unit in ["a", "あ", "🔑"] {
        let token = h.issue_token(json!({})).await;
        let max = unit.repeat(MAX_TEXT_CHARS);
        assert_eq!(
            h.submit(&token, &max).await.status,
            StatusCode::OK,
            "{unit}"
        );
        assert_eq!(h.take(&token).await.body, max);
    }
}

#[tokio::test]
async fn over_1024_chars_is_413_and_not_stored() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    for unit in ["a", "あ", "🔑"] {
        let too_long = unit.repeat(MAX_TEXT_CHARS + 1);
        let reply = h.submit(&token, &too_long).await;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE, "{unit}");
        assert_security_headers(&reply);
    }
    // 保存されていないので、まだ未投稿のまま。正しい長さなら書ける
    assert_eq!(h.take(&token).await.status, StatusCode::CONFLICT);
    assert_eq!(h.submit(&token, "ok").await.status, StatusCode::OK);
    assert_eq!(h.take(&token).await.body, "ok");
}

#[tokio::test]
async fn oversized_body_is_413() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    let body = format!("text={}", "a".repeat(17 * 1024));
    let reply = h.public(form_post(&format!("/{token}"), &body)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.take(&token).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn crlf_and_plus_are_preserved() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    let reply = h
        .public(form_post(&format!("/{token}"), "text=a+b%0D%0Ac%2B"))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.take(&token).await.body, "a b\r\nc+");
}

#[tokio::test]
async fn invalid_forms_are_rejected_without_storing() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    let path = format!("/{token}");

    assert_eq!(
        h.submit(&token, "").await.status,
        StatusCode::BAD_REQUEST,
        "empty text"
    );
    let missing = h.public(form_post(&path, "other=x")).await;
    assert!(missing.status.is_client_error());
    let duplicated = h.public(form_post(&path, "text=a&text=b")).await;
    assert!(duplicated.status.is_client_error());

    let json_body = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(header::HOST, PUBLIC_HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"text":"x"}"#))
        .unwrap();
    assert_eq!(
        h.public(json_body).await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    // エラー応答に入力値を反射しない
    let reflected = h.public(form_post(&path, "text=a&text=REFLECTED")).await;
    assert!(!reflected.body.contains("REFLECTED"));

    assert_eq!(h.take(&token).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn existence_and_gone_take_priority_over_body_errors() {
    let h = Harness::new();
    let unknown = crate::token::Token::generate().unwrap().encode();
    let bad = h.public(form_post(&format!("/{unknown}"), "garbage")).await;
    assert_eq!(bad.status, StatusCode::NOT_FOUND);

    let token = h.issue_token(json!({"text": "v"})).await;
    let bad = h.public(form_post(&format!("/{token}"), "garbage")).await;
    assert_eq!(bad.status, StatusCode::GONE);
}

#[tokio::test]
async fn html_payload_is_returned_only_as_plain_text() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    let payload = "<script>alert(1)</script><img src=x onerror=alert(2)>";
    assert_eq!(h.submit(&token, payload).await.status, StatusCode::OK);
    let shown = h.show(&token).await;
    assert!(!shown.body.contains("alert"));
    let taken = h.take(&token).await;
    assert_eq!(taken.content_type(), "text/plain; charset=utf-8");
    assert_eq!(taken.body, payload);
    assert_eq!(taken.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
}

// ---- 公開側: 404 になるべきもの ----

#[tokio::test]
async fn unknown_and_malformed_tokens_are_404() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    let unknown = crate::token::Token::generate().unwrap().encode();
    let percent_encoded_first = format!("/%{:02X}{}", token.as_bytes()[0], &token[1..]);
    let non_canonical = {
        // 最終字の下位ビットを立てた同じ長さの文字列（正規形ではない）
        let mut s = token[..21].to_string();
        s.push('B');
        s
    };
    for path in [
        format!("/{unknown}"),
        format!("/{unknown}?take=1"),
        format!("/{}", &token[..21]),
        format!("/{token}A"),
        format!("/{token}/"),
        format!("/{token}/x"),
        format!("/{}=", &token[..21]),
        format!("/{non_canonical}"),
        percent_encoded_first,
        "/".to_string(),
        "/index.html".to_string(),
        "/favicon.ico".to_string(),
        "/robots.txt".to_string(),
    ] {
        let reply = h.public(public_request(Method::GET, &path)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_security_headers(&reply);
    }
    // 生きているトークンはどれにも巻き込まれていない
    assert_eq!(h.show(&token).await.status, StatusCode::OK);
}

#[tokio::test]
async fn admin_routes_do_not_exist_on_public_port() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    let create = Request::builder()
        .method(Method::POST)
        .uri("/admin/drops")
        .header(header::HOST, "127.0.0.1:8470")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(h.public(create).await.status, StatusCode::NOT_FOUND);
    for (method, path) in [
        (Method::GET, "/admin/drops".to_string()),
        (Method::GET, "/admin".to_string()),
        (Method::DELETE, format!("/admin/drops/{token}")),
        (Method::GET, format!("/admin/drops/{token}")),
    ] {
        let reply = h.public(public_request(method.clone(), &path)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
    // DELETE が公開側で効いていないこと
    assert_eq!(h.show(&token).await.status, StatusCode::OK);
}

#[tokio::test]
async fn other_methods_are_404_and_head_never_takes() {
    let h = Harness::new();
    let token = h.issue_token(json!({"text": "keep"})).await;
    for method in [
        Method::HEAD,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::OPTIONS,
    ] {
        for path in [format!("/{token}"), format!("/{token}?take=1")] {
            let reply = h.public(public_request(method.clone(), &path)).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
            assert!(reply.headers.get(header::ALLOW).is_none());
        }
    }
    assert_eq!(h.take(&token).await.body, "keep");
}

#[tokio::test]
async fn take_query_must_be_exactly_1() {
    let h = Harness::new();
    let token = h.issue_token(json!({"text": "v"})).await;
    for query in ["take=0", "take=true", "take", "take=1&take=1"] {
        let reply = h
            .public(public_request(Method::GET, &format!("/{token}?{query}")))
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{query}");
    }
    // take 以外のクエリは無視される（ページ表示）
    let shown = h
        .public(public_request(Method::GET, &format!("/{token}?utm=x")))
        .await;
    assert_eq!(shown.status, StatusCode::OK);
    assert_eq!(h.take(&token).await.body, "v");
}

#[tokio::test(start_paused = true)]
async fn expired_drops_are_404_everywhere() {
    let h = Harness::new();
    let empty = h.issue_token(json!({})).await;
    let filled = h.issue_token(json!({"text": "v", "ttl_secs": 60})).await;
    let to_delete = h.issue_token(json!({"ttl_secs": 60})).await;

    tokio::time::advance(Duration::from_secs(59)).await;
    assert_eq!(h.show(&filled).await.status, StatusCode::OK);

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(h.take(&filled).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.delete(&to_delete).await.status, StatusCode::NOT_FOUND);
    // 既定 TTL は 600 秒
    assert_eq!(h.show(&empty).await.status, StatusCode::OK);

    tokio::time::advance(Duration::from_secs(540)).await;
    assert_eq!(h.show(&empty).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.submit(&empty, "late").await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.take(&empty).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.state.store().len(), 0);
}

// ---- admin 側 ----

#[tokio::test]
async fn admin_issue_response_shape() {
    let h = Harness::new();
    let reply = h.issue(json!({"ttl_secs": 120})).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert!(reply.content_type().starts_with("application/json"));
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    let json: Value = serde_json::from_str(&reply.body).unwrap();
    let token = json["token"].as_str().unwrap();
    assert_eq!(token.len(), 22);
    assert_eq!(json["url_path"], format!("/{token}"));
    assert_eq!(json["ttl_secs"], 120);
    assert_eq!(
        json.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["token", "ttl_secs", "url_path"]
    );

    let defaulted: Value = serde_json::from_str(&h.issue(json!({})).await.body).unwrap();
    assert_eq!(defaulted["ttl_secs"], 600);
}

#[tokio::test]
async fn prefilled_drop_is_take_once_and_rejects_public_post() {
    let h = Harness::new();
    let token = h.issue_token(json!({"text": "api-key-🔑"})).await;
    let shown = h.show(&token).await;
    assert_eq!(shown.status, StatusCode::OK);
    assert!(shown.body.contains("受付済み"));
    assert!(!shown.body.contains("api-key"));
    assert_eq!(h.submit(&token, "x").await.status, StatusCode::GONE);
    let taken = h.take(&token).await;
    assert_eq!(taken.status, StatusCode::OK);
    assert_eq!(taken.body, "api-key-🔑");
    assert_eq!(h.take(&token).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_rejects_bad_issue_requests() {
    let h = Harness::new();
    let too_long = "あ".repeat(MAX_TEXT_CHARS + 1);
    for (body, expected) in [
        (json!({"text": too_long}), StatusCode::PAYLOAD_TOO_LARGE),
        (json!({"text": ""}), StatusCode::BAD_REQUEST),
        (json!({"ttl_secs": 0}), StatusCode::BAD_REQUEST),
        (json!({"ttl_secs": 3601}), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(h.issue(body.clone()).await.status, expected, "{body}");
    }
    for body in [
        r#"{"text": 1}"#,
        r#"{"ttl_secs": -1}"#,
        r#"{"ttl_secs": "600"}"#,
        r#"{"unknown": true}"#,
        r#"{"text": "SECRET-ECHO", "extra": 1}"#,
        "not json",
        "",
    ] {
        let reply = h
            .admin(admin_json(Method::POST, "/admin/drops", body))
            .await;
        assert!(reply.status.is_client_error(), "{body}");
        assert!(!reply.body.contains("SECRET-ECHO"));
    }
    let no_content_type = Request::builder()
        .method(Method::POST)
        .uri("/admin/drops")
        .header(header::HOST, ADMIN_HOST)
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        h.admin(no_content_type).await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let huge = format!(r#"{{"text":"{}"}}"#, "a".repeat(17 * 1024));
    assert_eq!(
        h.admin(admin_json(Method::POST, "/admin/drops", &huge))
            .await
            .status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(h.state.store().len(), 0);
}

#[tokio::test]
async fn admin_accepts_max_length_text_even_with_json_escapes() {
    let h = Harness::new();
    let text = "🔑".repeat(MAX_TEXT_CHARS);
    // 全部 \uXXXX\uXXXX（サロゲートペア）で書いてもボディ上限に収まる
    let escaped: String = text.encode_utf16().map(|u| format!("\\u{u:04x}")).collect();
    let body = format!(r#"{{"text":"{escaped}"}}"#);
    let reply = h
        .admin(admin_json(Method::POST, "/admin/drops", &body))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let token = serde_json::from_str::<Value>(&reply.body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(h.take(&token).await.body, text);
}

#[tokio::test]
async fn admin_delete() {
    let h = Harness::new();
    let token = h.issue_token(json!({"text": "v"})).await;
    let deleted = h.delete(&token).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert!(deleted.body.is_empty());
    assert_eq!(h.delete(&token).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.take(&token).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.show(&token).await.status, StatusCode::NOT_FOUND);

    let unknown = crate::token::Token::generate().unwrap().encode();
    assert_eq!(h.delete(&unknown).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.delete("short").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_unknown_routes_and_methods_are_404() {
    let h = Harness::new();
    let token = h.issue_token(json!({})).await;
    for (method, path) in [
        (Method::GET, "/".to_string()),
        (Method::GET, "/admin/drops".to_string()),
        (Method::PUT, "/admin/drops".to_string()),
        (Method::GET, format!("/admin/drops/{token}")),
        (Method::POST, format!("/admin/drops/{token}")),
        (Method::GET, format!("/{token}")),
        (Method::GET, format!("/{token}?take=1")),
    ] {
        let reply = h.admin(admin_request(method.clone(), &path)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[tokio::test]
async fn admin_requires_loopback_host_header() {
    let h = Harness::new();
    for host in [None, Some("evil.example:8471"), Some("drop.duxca.com")] {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/admin/drops")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        let reply = h.admin(builder.body(Body::from("{}")).unwrap()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{host:?}");
    }
    for host in ["localhost:8471", "[::1]:8471", "127.0.0.1"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/drops")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(h.admin(request).await.status, StatusCode::CREATED, "{host}");
    }
}

// ---- 上限 ----

#[tokio::test]
async fn drop_count_limit_is_503() {
    let h = Harness::with_limits(Limits {
        max_drops: 2,
        ..default_limits()
    });
    h.issue_token(json!({})).await;
    h.issue_token(json!({})).await;
    assert_eq!(
        h.issue(json!({})).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn total_bytes_limit_is_503_and_not_stored() {
    let h = Harness::with_limits(Limits {
        max_total_bytes: 4096,
        ..default_limits()
    });
    let a = h.issue_token(json!({"text": "x".repeat(1000)})).await;
    let b = h.issue_token(json!({"text": "あ".repeat(1000)})).await;
    let c = h.issue_token(json!({})).await;
    // 1000 + 3000 = 4000 バイト。残り 96 バイトに 100 バイトは入らない
    assert_eq!(
        h.submit(&c, &"y".repeat(100)).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(h.take(&c).await.status, StatusCode::CONFLICT);
    h.take(&a).await;
    assert_eq!(h.submit(&c, &"y".repeat(100)).await.status, StatusCode::OK);
    h.take(&b).await;
    assert_eq!(h.state.store().text_bytes(), 100);
}

// ---- ログ ----

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// テストプロセス全体のログを捕捉する。
/// tracing の scoped dispatcher（set_default）だと、他のテストスレッドが先に登録した callsite が
/// 「無効」のままキャッシュされて取りこぼすので、グローバル subscriber にする。
fn global_log_capture() -> &'static Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let writer = capture.clone();
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .try_init()
            .expect("global subscriber");
        tracing::callsite::rebuild_interest_cache();
        capture
    })
}

#[tokio::test]
async fn logs_never_contain_text_or_token() {
    let capture = global_log_capture();

    let h = Harness::new();
    const SECRET: &str = "very-secret-value-0123456789";
    let posted = h.issue_token(json!({})).await;
    h.submit(&posted, SECRET).await;
    h.submit(&posted, SECRET).await;
    h.take(&posted).await;
    let prefilled = h.issue_token(json!({"text": SECRET})).await;
    h.delete(&prefilled).await;
    h.submit(&prefilled, SECRET).await;
    let too_long = h.issue_token(json!({})).await;
    h.submit(&too_long, &SECRET.repeat(100)).await;
    h.public(form_post(
        &format!("/{too_long}"),
        &format!("text={SECRET}&text={SECRET}"),
    ))
    .await;
    h.admin(admin_json(
        Method::POST,
        "/admin/drops",
        &format!(r#"{{"ttl_secs":"{SECRET}"}}"#),
    ))
    .await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // キャプチャが効いていること自体を確認（他テストのログも混ざるが、どれにも値・トークンは出ない）
    assert!(logs.contains("drop issued"), "{logs}");
    assert!(logs.contains("drop filled"), "{logs}");
    assert!(logs.contains("drop taken"), "{logs}");
    assert!(logs.contains("drop deleted"), "{logs}");
    assert!(!logs.contains(SECRET), "{logs}");
    for token in [&posted, &prefilled, &too_long] {
        assert!(!logs.contains(token.as_str()), "{logs}");
    }
}
