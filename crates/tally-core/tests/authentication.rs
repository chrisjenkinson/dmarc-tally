//! Behavioural contract for one-administrator, provider-independent sign-in.
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use tally_core::authentication::{
    AdminEmail, AuthError, Authentication, AuthenticationStore, EmailSender,
    InMemoryAuthenticationStore, SecureTokenSource, TokenDigest, LOGIN_COOLDOWN_SECONDS,
    LOGIN_TTL_SECONDS, SESSION_TTL_SECONDS,
};

const NOW: i64 = 1_800_000_000;

struct FixedSecrets(AtomicU8);

impl Default for FixedSecrets {
    fn default() -> Self {
        Self(AtomicU8::new(1))
    }
}

impl SecureTokenSource for FixedSecrets {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError> {
        // Deterministic fake for tests only. The real adapter MUST use a CSPRNG.
        let value = self.0.fetch_add(1, Ordering::SeqCst);
        Ok([value; 32])
    }
}

#[derive(Default)]
struct SpySender {
    sent: Mutex<Vec<(String, String)>>,
    fail: AtomicBool,
}

impl SpySender {
    fn sent(&self) -> Vec<(String, String)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl EmailSender for SpySender {
    async fn send_sign_in_link(&self, recipient: &str, token: &str) -> Result<(), AuthError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuthError::Delivery);
        }
        self.sent
            .lock()
            .unwrap()
            .push((recipient.to_owned(), token.to_owned()));
        Ok(())
    }
}

struct Fixture {
    administrator: AdminEmail,
    storage: InMemoryAuthenticationStore,
    sender: SpySender,
    secrets: FixedSecrets,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            administrator: AdminEmail::parse("Admin+DMARC@Example.com").unwrap(),
            storage: InMemoryAuthenticationStore::default(),
            sender: SpySender::default(),
            secrets: FixedSecrets::default(),
        }
    }
}

impl Fixture {
    fn auth(&self) -> Authentication<'_> {
        Authentication::new(
            &self.administrator,
            &self.storage,
            &self.sender,
            &self.secrets,
        )
    }

    fn most_recent_token(&self) -> String {
        self.sender.sent().last().unwrap().1.clone()
    }
}

#[test]
fn admin_email_is_validated_and_normalised_without_accepting_header_injection() {
    let good = AdminEmail::parse("  AdMin+DMARC@EXAMPLE.COM  ").unwrap();
    assert_eq!(good.as_str(), "AdMin+DMARC@example.com");
    assert!(good.matches("admin+dmarc@EXAMPLE.com"));
    for bad in [
        "",
        "admin",
        "admin@@example.com",
        "@example.com",
        "admin@localhost",
        "admin@example..com",
        "admin@example.com\r\nBcc:attacker@example.net",
        "admin@example.com foo",
        "bad<email>@example.com",
    ] {
        assert!(
            AdminEmail::parse(bad).is_err(),
            "accepted invalid address {bad:?}"
        );
    }
}

#[tokio::test]
async fn login_requests_are_indistinguishable_and_only_configured_admin_is_emailed() {
    let f = Fixture::default();
    let auth = f.auth();
    assert_eq!(
        auth.request_sign_in("attacker@example.net", NOW).await,
        Ok(())
    );
    assert_eq!(f.sender.sent().len(), 0);
    assert_eq!(
        auth.request_sign_in("admin+dmarc@EXAMPLE.COM", NOW).await,
        Ok(())
    );
    let sent = f.sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "Admin+DMARC@example.com"); // configured address, not user input
    assert_eq!(sent[0].1.len(), 64);
    assert!(sent[0].1.as_bytes().iter().all(u8::is_ascii_hexdigit));
}

#[tokio::test]
async fn repeated_requests_are_throttled_and_new_links_invalidate_old_ones() {
    let f = Fixture::default();
    let auth = f.auth();
    auth.request_sign_in(f.administrator.as_str(), NOW)
        .await
        .unwrap();
    let first = f.most_recent_token();
    auth.request_sign_in(f.administrator.as_str(), NOW + LOGIN_COOLDOWN_SECONDS - 1)
        .await
        .unwrap();
    assert_eq!(f.sender.sent().len(), 1);
    auth.request_sign_in(f.administrator.as_str(), NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap();
    assert_eq!(f.sender.sent().len(), 2);
    let second = f.most_recent_token();
    assert_ne!(first, second);
    assert!(auth
        .redeem_sign_in(&first, NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap()
        .is_none());
    assert!(auth
        .redeem_sign_in(&second, NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn redeeming_a_link_does_not_reset_the_request_cooldown() {
    let f = Fixture::default();
    let auth = f.auth();
    auth.request_sign_in(f.administrator.as_str(), NOW)
        .await
        .unwrap();
    let first = f.most_recent_token();
    assert!(auth
        .redeem_sign_in(&first, NOW + 1)
        .await
        .unwrap()
        .is_some());
    // Consuming a challenge must retain the last-issue timestamp, even when
    // the one-time token itself is no longer valid.
    auth.request_sign_in(f.administrator.as_str(), NOW + LOGIN_COOLDOWN_SECONDS - 1)
        .await
        .unwrap();
    assert_eq!(f.sender.sent().len(), 1);
    auth.request_sign_in(f.administrator.as_str(), NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap();
    assert_eq!(f.sender.sent().len(), 2);
}

#[tokio::test]
async fn magic_link_is_single_use_and_expires_at_exact_boundary() {
    let f = Fixture::default();
    let auth = f.auth();
    auth.request_sign_in(f.administrator.as_str(), NOW)
        .await
        .unwrap();
    let token = f.most_recent_token();
    let session = auth
        .redeem_sign_in(&token, NOW + LOGIN_TTL_SECONDS - 1)
        .await
        .unwrap()
        .expect("link should work until expiry");
    assert!(!format!("{session:?}").contains(&session.cookie_value()));
    assert!(auth
        .redeem_sign_in(&token, NOW + LOGIN_TTL_SECONDS - 1)
        .await
        .unwrap()
        .is_none());

    auth.request_sign_in(f.administrator.as_str(), NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap();
    let expired = f.most_recent_token();
    assert!(auth
        .redeem_sign_in(&expired, NOW + LOGIN_COOLDOWN_SECONDS + LOGIN_TTL_SECONDS)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_successful_session_can_be_validated_revoked_and_expires() {
    let f = Fixture::default();
    let auth = f.auth();
    auth.request_sign_in(f.administrator.as_str(), NOW)
        .await
        .unwrap();
    let session = auth
        .redeem_sign_in(&f.most_recent_token(), NOW)
        .await
        .unwrap()
        .unwrap();
    let cookie = session.cookie_value();
    assert_eq!(session.expires_at(), NOW + SESSION_TTL_SECONDS);
    assert!(auth.is_authenticated(&cookie, NOW).await.unwrap());
    assert!(auth
        .is_authenticated(&cookie, NOW + SESSION_TTL_SECONDS - 1)
        .await
        .unwrap());
    assert!(!auth
        .is_authenticated(&cookie, NOW + SESSION_TTL_SECONDS)
        .await
        .unwrap());
    auth.sign_out(&cookie).await.unwrap();
    auth.sign_out(&cookie).await.unwrap(); // logout is idempotent
    assert!(!auth.is_authenticated(&cookie, NOW).await.unwrap());
}

#[tokio::test]
async fn malformed_tokens_never_grant_access() {
    let f = Fixture::default();
    let auth = f.auth();
    for token in [
        "",
        "bad",
        " 00",
        "0".repeat(64).as_str(),
        "../".repeat(22).as_str(),
    ] {
        assert!(auth.redeem_sign_in(token, NOW).await.unwrap().is_none());
        assert!(!auth.is_authenticated(token, NOW).await.unwrap());
        auth.sign_out(token).await.unwrap();
    }
}

#[tokio::test]
async fn concurrent_redemption_allows_at_most_one_session() {
    let f = Fixture::default();
    let auth = f.auth();
    auth.request_sign_in(f.administrator.as_str(), NOW)
        .await
        .unwrap();
    let token = f.most_recent_token();
    let (a, b) = tokio::join!(
        auth.redeem_sign_in(&token, NOW),
        auth.redeem_sign_in(&token, NOW)
    );
    assert_eq!(
        usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
        1
    );
}

#[tokio::test]
async fn concurrent_login_requests_send_only_one_link_during_cooldown() {
    let f = Fixture::default();
    let auth = f.auth();
    let (a, b) = tokio::join!(
        auth.request_sign_in(f.administrator.as_str(), NOW),
        auth.request_sign_in(f.administrator.as_str(), NOW)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(f.sender.sent().len(), 1);
}

#[tokio::test]
async fn failed_email_send_is_an_internal_error_not_a_session() {
    let f = Fixture::default();
    f.sender.fail.store(true, Ordering::SeqCst);
    let auth = f.auth();
    assert_eq!(
        auth.request_sign_in(f.administrator.as_str(), NOW).await,
        Err(AuthError::Delivery)
    );
    assert!(f.sender.sent().is_empty());
    f.sender.fail.store(false, Ordering::SeqCst);
    auth.request_sign_in(f.administrator.as_str(), NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap();
    assert_eq!(f.sender.sent().len(), 1);
}

struct UnavailableStore;

#[async_trait]
impl AuthenticationStore for UnavailableStore {
    async fn issue_login_challenge(
        &self,
        _: TokenDigest,
        _: i64,
        _: i64,
        _: i64,
    ) -> Result<bool, AuthError> {
        Err(AuthError::Storage)
    }

    async fn consume_login_challenge(&self, _: &TokenDigest, _: i64) -> Result<bool, AuthError> {
        Err(AuthError::Storage)
    }

    async fn issue_session(&self, _: TokenDigest, _: i64) -> Result<(), AuthError> {
        Err(AuthError::Storage)
    }

    async fn is_session_valid(&self, _: &TokenDigest, _: i64) -> Result<bool, AuthError> {
        Err(AuthError::Storage)
    }

    async fn revoke_session(&self, _: &TokenDigest) -> Result<(), AuthError> {
        Err(AuthError::Storage)
    }
}

struct NoEntropy;

impl SecureTokenSource for NoEntropy {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError> {
        Err(AuthError::Entropy)
    }
}

#[tokio::test]
async fn store_outages_deny_authorization_and_login_issuance() {
    let f = Fixture::default();
    let storage = UnavailableStore;
    let auth = Authentication::new(&f.administrator, &storage, &f.sender, &f.secrets);
    assert_eq!(
        auth.request_sign_in(f.administrator.as_str(), NOW).await,
        Err(AuthError::Storage)
    );
    assert_eq!(
        auth.request_sign_in("someone-else@example.net", NOW).await,
        Ok(())
    );
    assert_eq!(f.sender.sent().len(), 0);
    let well_formed = "ab".repeat(32);
    assert!(matches!(
        auth.redeem_sign_in(&well_formed, NOW).await,
        Err(AuthError::Storage)
    ));
    assert_eq!(
        auth.is_authenticated(&well_formed, NOW).await,
        Err(AuthError::Storage)
    );
    assert_eq!(auth.sign_out(&well_formed).await, Err(AuthError::Storage));
}

#[tokio::test]
async fn unavailable_secure_random_source_never_sends_a_link() {
    let f = Fixture::default();
    let source = NoEntropy;
    let auth = Authentication::new(&f.administrator, &f.storage, &f.sender, &source);
    assert_eq!(
        auth.request_sign_in(f.administrator.as_str(), NOW).await,
        Err(AuthError::Entropy)
    );
    assert!(f.sender.sent().is_empty());
}

#[tokio::test]
async fn invalid_time_fails_before_modifying_storage() {
    let f = Fixture::default();
    let auth = f.auth();
    assert_eq!(
        auth.request_sign_in(f.administrator.as_str(), i64::MAX)
            .await,
        Err(AuthError::Clock)
    );
    assert!(f.sender.sent().is_empty());
}
