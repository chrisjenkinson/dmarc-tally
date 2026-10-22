//! Contract for portable HTTP routing: no AWS, web server or public endpoint.
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use tally_core::{
    authentication::{
        AdminEmail, AuthError, Authentication, EmailSender, InMemoryAuthenticationStore,
        SecureTokenSource, LOGIN_TTL_SECONDS, SESSION_TTL_SECONDS,
    },
    identity::{DomainName, DomainSet, ReportIdentity, StoredReport},
    model::DateRange,
    ports::{Cursor, PersistOutcome, ReportPage, ReportRepository, StoreError},
};
use tally_web::http::{handle, Request, SiteOrigin};

const NOW: i64 = 1_800_000_000;

struct FakeEntropy(AtomicU8);
impl SecureTokenSource for FakeEntropy {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError> {
        Ok([self.0.fetch_add(1, Ordering::SeqCst); 32])
    }
}

#[derive(Default)]
struct SpySender {
    tokens: Mutex<Vec<String>>,
    fail: AtomicBool,
}
#[async_trait]
impl EmailSender for SpySender {
    async fn send_sign_in_link(&self, _: &str, token: &str) -> Result<(), AuthError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuthError::Delivery);
        }
        self.tokens.lock().unwrap().push(token.to_owned());
        Ok(())
    }
}
impl SpySender {
    fn token(&self) -> String {
        self.tokens.lock().unwrap().last().unwrap().clone()
    }
    fn count(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }
}

#[derive(Default)]
struct SpyReports {
    reads: AtomicUsize,
}
#[async_trait]
impl ReportRepository for SpyReports {
    async fn persist_report(&self, _: &StoredReport) -> Result<PersistOutcome, StoreError> {
        panic!("HTTP handlers must not persist reporting data")
    }
    async fn list_for_domain(
        &self,
        _: &DomainName,
        _: DateRange,
        _: Option<Cursor>,
    ) -> Result<ReportPage, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReportPage { reports: vec![], next_cursor: None })
    }
    async fn get_report(
        &self,
        _: &ReportIdentity,
    ) -> Result<Option<StoredReport>, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

struct Fixture {
    admin: AdminEmail,
    store: InMemoryAuthenticationStore,
    email: SpySender,
    entropy: FakeEntropy,
    reports: SpyReports,
    domains: DomainSet,
    site: SiteOrigin,
}
impl Default for Fixture {
    fn default() -> Self {
        Self {
            admin: AdminEmail::parse("admin@example.com").unwrap(),
            store: InMemoryAuthenticationStore::default(),
            email: SpySender::default(),
            entropy: FakeEntropy(AtomicU8::new(1)),
            reports: SpyReports::default(),
            domains: DomainSet::new(["example.com"]).unwrap(),
            site: SiteOrigin::parse("https://private.example").unwrap(),
        }
    }
}
impl Fixture {
    fn auth(&self) -> Authentication<'_> {
        Authentication::new(&self.admin, &self.store, &self.email, &self.entropy)
    }
    async fn request(&self, req: Request<'_>, now: i64) -> tally_web::http::Response {
        handle(&req, &self.auth(), &self.reports, &self.domains, &self.site, now).await
    }
    fn post<'a>(&self, path: &'a str, body: &'a str) -> Request<'a> {
        let mut req = Request::new("POST", path);
        req.origin = Some("https://private.example");
        req.content_type = Some("application/x-www-form-urlencoded");
        req.body = body;
        req
    }
    async fn login(&self) -> String {
        self.request(self.post("/auth/request", "email=admin%40example.com"), NOW)
            .await;
        self.email.token()
    }
    async fn redeem(&self, token: &str, now: i64) -> String {
        let body = format!("token={token}");
        let result = self.request(self.post("/auth/confirm", &body), now).await;
        assert_eq!(result.status, 303);
        result.header("Set-Cookie").unwrap().to_string()
    }
}

#[test]
fn configured_site_origin_rejects_open_redirects_credentials_or_insecure_urls() {
    for bad in [
        "",
        "http://private.example",
        "https://user@private.example",
        "https://private.example@evil.example",
        "https://private.example/extra",
        "https://private.example/?x=y",
        "https://private.example/#fragment",
        "https://private.example\\@evil.example",
        "https://private.example %0a",
        "https://private.example:bad",
    ] {
        assert!(SiteOrigin::parse(bad).is_err(), "accepted {bad:?}");
    }
    let site = SiteOrigin::parse("https://PRIVATE.example:443/").unwrap();
    assert_eq!(site.as_str(), "https://private.example");
    assert_eq!(
        site.login_link(&"ab".repeat(32)).unwrap(),
        format!("https://private.example/auth/confirm?token={}", "ab".repeat(32)),
    );
    assert!(site.login_link("<script>").is_none());
}

#[tokio::test]
async fn every_reporting_route_deny_access_before_any_repository_read() {
    let f = Fixture::default();
    for route in ["/", "/reports/012345/detail", "/reports/abc/original"] {
        let response = f.request(Request::new("GET", route), NOW).await;
        assert_eq!(response.status, 303, "route: {route}");
        assert_eq!(response.header("Location"), Some("/auth/login"));
        assert!(!response.body.contains("Reporting organisations"));
        assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn login_get_does_not_consume_token_and_explicit_post_starts_revocable_session() {
    let f = Fixture::default();
    let token = f.login().await;
    for _ in 0..2 {
        let mut landing = Request::new("GET", "/auth/confirm");
        let query = format!("token={token}");
        landing.query = &query;
        let html = f.request(landing, NOW).await;
        assert_eq!(html.status, 200);
        assert!(html.body.contains("Confirm sign-in"));
    }
    let cookie = f.redeem(&token, NOW + 1).await;
    assert!(cookie.starts_with("__Host-dmarc-session="));
    for part in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=604800"] {
        assert!(cookie.contains(part), "missing cookie attribute: {part}");
    }
    assert!(!cookie.contains("Domain="));
    let mut private = Request::new("GET", "/");
    private.cookie = Some(cookie.split(';').next().unwrap());
    let page = f.request(private, NOW + 1).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Report overview"));
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 1);
    let replay = f.request(f.post("/auth/confirm", &format!("token={token}")), NOW + 1).await;
    assert_ne!(replay.status, 303, "link may only be redeemed once");
}

#[tokio::test]
async fn expired_and_revoked_session_both_deny_private_data() {
    let f = Fixture::default();
    let token = f.login().await;
    let cookie = f.redeem(&token, NOW).await;
    let header = cookie.split(';').next().unwrap();
    let mut req = Request::new("GET", "/");
    req.cookie = Some(header);
    assert_eq!(f.request(req, NOW + SESSION_TTL_SECONDS).await.status, 303);
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);

    let mut logout = f.post("/auth/logout", "");
    logout.cookie = Some(header);
    let response = f.request(logout, NOW + 1).await;
    assert_eq!(response.status, 303);
    assert!(response.header("Set-Cookie").unwrap().contains("Max-Age=0"));

    let mut req = Request::new("GET", "/");
    req.cookie = Some(header);
    assert_eq!(f.request(req, NOW + 1).await.status, 303);
    assert_eq!(f.reports.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unrecognised_addresses_and_email_failures_get_same_acknowledgement() {
    let f = Fixture::default();
    let unknown = f.request(f.post("/auth/request", "email=unknown%40example.com"), NOW).await;
    assert_eq!(unknown.status, 200);
    assert_eq!(f.email.count(), 0);
    f.email.fail.store(true, Ordering::SeqCst);
    let rejected = f.request(f.post("/auth/request", "email=admin%40example.com"), NOW).await;
    assert_eq!(rejected.status, 200);
    assert_eq!(rejected.body, unknown.body);
    assert_eq!(f.email.count(), 0);
}

#[tokio::test]
async fn cross_origin_posts_cannot_send_email_consume_tokens_or_sign_out() {
    let f = Fixture::default();
    let mut req = f.post("/auth/request", "email=admin%40example.com");
    req.origin = Some("https://evil.example");
    assert_eq!(f.request(req, NOW).await.status, 403);
    assert_eq!(f.email.count(), 0);

    let token = f.login().await;
    let mut request = f.post("/auth/confirm", &format!("token={token}"));
    request.origin = Some("null");
    assert_eq!(f.request(request, NOW).await.status, 403);
    let cookie = f.redeem(&token, NOW).await;
    let session = cookie.split(';').next().unwrap();

    let mut req = f.post("/auth/logout", "");
    req.cookie = Some(session);
    req.origin = Some("https://evil.example");
    assert_eq!(f.request(req, NOW + 1).await.status, 403);

    let mut req = Request::new("GET", "/");
    req.cookie = Some(session);
    assert_eq!(f.request(req, NOW + 1).await.status, 200);
}

#[tokio::test]
async fn duplicate_form_keys_and_unexpected_methods_are_rejected() {
    let f = Fixture::default();
    for body in [
        "email=admin%40example.com&email=other%40example.com",
        "email=admin%ZZexample.com",
        "email=admin%40example.com&next=https%3A%2F%2Fevil.example",
    ] {
        assert_eq!(f.request(f.post("/auth/request", body), NOW).await.status, 400);
    }
    assert_eq!(f.email.count(), 0);
    assert_eq!(f.request(Request::new("GET", "/auth/request"), NOW).await.status, 405);
}

#[tokio::test]
async fn confirm_expiry_and_malformed_tokens_never_create_sessions() {
    let f = Fixture::default();
    let token = f.login().await;
    let expired = f.request(f.post("/auth/confirm", &format!("token={token}")), NOW + LOGIN_TTL_SECONDS).await;
    assert_eq!(expired.status, 200);
    assert!(expired.header("Set-Cookie").is_none());
    let malformed = f.request(f.post("/auth/confirm", "token=missing"), NOW).await;
    assert_eq!(malformed.status, 200);
    assert!(malformed.header("Set-Cookie").is_none());
}

#[tokio::test]
async fn all_responses_prevent_caching_and_referrer_leakage() {
    let f = Fixture::default();
    for req in [
        Request::new("GET", "/auth/login"),
        Request::new("GET", "/"),
        Request::new("GET", "/not-found"),
    ] {
        let response = f.request(req, NOW).await;
        assert_eq!(response.header("Cache-Control"), Some("no-store"));
        assert_eq!(response.header("Referrer-Policy"), Some("no-referrer"));
        assert!(response.header("Content-Security-Policy").unwrap().contains("form-action 'self'"));
    }
}
