//! HTTP API v2/Lambda Function URL adapter: no real AWS account or sockets.
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use tally_core::{
    authentication::{
        AdminEmail, AuthError, Authentication, EmailSender, InMemoryAuthenticationStore,
        SecureTokenSource,
    },
    identity::{DomainName, DomainSet, ReportIdentity, StoredReport},
    model::DateRange,
    ports::{Cursor, PersistOutcome, ReportPage, ReportRepository, StoreError},
};
use tally_lambda::web_event::handle_http_v2;
use tally_web::http::SiteOrigin;

const NOW: i64 = 1_800_000_000;
const HOSTILE_TOKEN: &str = "very-private-token-should-not-be-echoed";

fn event(method: &str, path: &str, body: &str) -> Value {
    json!({
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"host": "evil.example", "origin": "https://private.example",
            "content-type": "application/x-www-form-urlencoded"},
        "requestContext": {"http": {"method": method}},
        "isBase64Encoded": false,
        "body": body
    })
}

struct TestEntropy(AtomicU8);
impl SecureTokenSource for TestEntropy {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError> {
        Ok([self.0.fetch_add(1, Ordering::SeqCst); 32])
    }
}

#[derive(Default)]
struct TestSender(Mutex<Vec<String>>);
#[async_trait]
impl EmailSender for TestSender {
    async fn send_sign_in_link(&self, _: &str, token: &str) -> Result<(), AuthError> {
        self.0.lock().unwrap().push(token.into());
        Ok(())
    }
}

#[derive(Default)]
struct ReportSpy { reads: AtomicUsize }
#[async_trait]
impl ReportRepository for ReportSpy {
    async fn persist_report(&self, _: &StoredReport) -> Result<PersistOutcome, StoreError> {
        panic!("HTTP adapter must never persist reports")
    }
    async fn list_for_domain(
        &self, _: &DomainName, _: DateRange, _: Option<Cursor>,
    ) -> Result<ReportPage, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReportPage { reports: vec![], next_cursor: None })
    }
    async fn get_report(&self, _: &ReportIdentity) -> Result<Option<StoredReport>, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

struct Fixture {
    admin: AdminEmail,
    store: InMemoryAuthenticationStore,
    sender: TestSender,
    entropy: TestEntropy,
    reports: ReportSpy,
    domains: DomainSet,
    site: SiteOrigin,
}
impl Default for Fixture {
    fn default() -> Self {
        Self {
            admin: AdminEmail::parse("admin@example.com").unwrap(),
            store: InMemoryAuthenticationStore::default(),
            sender: TestSender::default(),
            entropy: TestEntropy(AtomicU8::new(1)),
            reports: ReportSpy::default(),
            domains: DomainSet::new(["example.com"]).unwrap(),
            site: SiteOrigin::parse("https://private.example").unwrap(),
        }
    }
}
impl Fixture {
    async fn send(&self, input: &Value) -> Value {
        let auth = Authentication::new(&self.admin, &self.store, &self.sender, &self.entropy);
        handle_http_v2(input, &auth, &self.reports, &self.domains, &self.site, NOW).await
    }
    fn token(&self) -> String {
        self.sender.0.lock().unwrap().last().unwrap().clone()
    }
}
fn status(result: &Value) -> u64 { result["statusCode"].as_u64().unwrap() }

#[tokio::test]
async fn missing_session_cannot_read_reports_even_with_a_hostile_host_header() {
    let f = Fixture::default();
    let response = f.send(&event("GET", "/", "")).await;
    assert_eq!(status(&response), 303);
    assert_eq!(response["headers"]["Location"], "/auth/login");
    assert_eq!(response["headers"]["Cache-Control"], "no-store");
    assert_eq!(response["headers"]["Referrer-Policy"], "no-referrer");
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);
    for path in ["/reports/abc", "/reports/abc/original"] {
        assert_eq!(status(&f.send(&event("GET", path, "")).await), 303);
    }
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn form_login_link_get_does_not_redeem_but_post_creates_revocable_cookie() {
    let f = Fixture::default();
    let request = event("POST", "/auth/request", "email=admin%40example.com");
    assert_eq!(status(&f.send(&request).await), 200);
    let token = f.token();

    let mut visit = event("GET", "/auth/confirm", "");
    visit["rawQueryString"] = json!(format!("token={token}"));
    assert_eq!(status(&f.send(&visit).await), 200);
    assert_eq!(status(&f.send(&visit).await), 200); // GET email scanner safe.

    let mut confirm = event("POST", "/auth/confirm", "");
    confirm["isBase64Encoded"] = json!(true);
    confirm["body"] = json!(STANDARD.encode(format!("token={token}")));
    let response = f.send(&confirm).await;
    assert_eq!(status(&response), 303);
    assert_eq!(response["headers"]["Location"], "/");
    assert!(response["headers"].get("Set-Cookie").is_none());
    let cookie = response["cookies"][0].as_str().unwrap();
    assert!(cookie.starts_with("__Host-dmarc-session="));
    assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
    assert!(!response.to_string().contains(&token));

    let credential = cookie.split(';').next().unwrap();
    let mut private = event("GET", "/", "");
    private["cookies"] = json!([credential]);
    assert_eq!(status(&f.send(&private).await), 200);
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 1);

    let mut logout = event("POST", "/auth/logout", "");
    logout["cookies"] = json!([credential]);
    let signed_out = f.send(&logout).await;
    assert_eq!(status(&signed_out), 303);
    assert!(signed_out["cookies"][0].as_str().unwrap().contains("Max-Age=0"));
    assert_eq!(status(&f.send(&private).await), 303);
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cookie_header_is_supported_but_ambiguous_cookies_are_rejected() {
    let f = Fixture::default();
    f.send(&event("POST", "/auth/request", "email=admin%40example.com")).await;
    let token = f.token();
    let response = f.send(&event("POST", "/auth/confirm", &format!("token={token}"))).await;
    let cookie = response["cookies"][0].as_str().unwrap().split(';').next().unwrap();
    let mut req = event("GET", "/", "");
    req["headers"]["cookie"] = json!(cookie);
    assert_eq!(status(&f.send(&req).await), 200);
    req["cookies"] = json!([cookie]);
    assert_eq!(status(&f.send(&req).await), 400);
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_or_ambiguous_transport_envelopes_fail_closed() {
    let f = Fixture::default();
    let mut probes = vec![
        json!({"version":"1.0", "httpMethod":"GET", "path":"/"}),
        json!({"version":"2.0","rawPath":"/","headers":{}}),
        event("GET", "relative/reports", ""),
        event("POST", "/auth/request", &"x".repeat(3_000)),
    ];
    let mut bad_b64 = event("POST", "/auth/confirm", HOSTILE_TOKEN);
    bad_b64["isBase64Encoded"] = json!(true);
    probes.push(bad_b64);
    let mut duplicate_origin = event("POST", "/auth/request", "email=admin%40example.com");
    duplicate_origin["headers"]["Origin"] = json!("https://private.example");
    probes.push(duplicate_origin);
    let mut wrong_type = event("POST", "/auth/request", "email=admin%40example.com");
    wrong_type["headers"]["content-type"] = json!(["application/x-www-form-urlencoded"]);
    probes.push(wrong_type);
    let mut cookie_too_big = event("GET", "/", "");
    cookie_too_big["headers"]["cookie"] = json!("x".repeat(5_000));
    probes.push(cookie_too_big);
    for input in probes {
        let response = f.send(&input).await;
        assert_eq!(status(&response), 400, "unexpected: {response:?}");
        assert_eq!(response["headers"]["Cache-Control"], "no-store");
        assert!(!response.to_string().contains(HOSTILE_TOKEN));
    }
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);
    assert!(f.sender.0.lock().unwrap().is_empty());
    // A syntactically valid but unsafe URL path reaches the portable router,
    // which deliberately returns an uninformative 404 rather than reporting.
    assert_eq!(status(&f.send(&event("GET", "/../reports", "")).await), 404);
    assert_eq!(
        status(&f.send(&event("POST", "/auth/confirm", "token=bad%xx")).await),
        200 // Invalid link is an application response, not a bad AWS envelope.
    );
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_origin_rejected_even_if_host_is_trusted() {
    let f = Fixture::default();
    let mut post = event("POST", "/auth/request", "email=admin%40example.com");
    post["headers"]["origin"] = json!("https://evil.example");
    post["headers"]["host"] = json!("private.example");
    assert_eq!(status(&f.send(&post).await), 403);
    assert!(f.sender.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn read_only_requests_do_not_require_an_origin_header() {
    let f = Fixture::default();
    let mut login = event("GET", "/auth/login", "");
    login["headers"].as_object_mut().unwrap().remove("origin");
    login["headers"].as_object_mut().unwrap().remove("content-type");
    assert_eq!(status(&f.send(&login).await), 200);
    assert_eq!(status(&f.send(&event("GET", "/auth/request", "")).await), 405);
}
