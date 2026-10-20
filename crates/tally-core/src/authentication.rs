//! Provider-independent, one-administrator magic-link authentication.
//!
//! A storage adapter must atomically condition and consume the one active
//! challenge, and it must enforce session expiry on every read. Do not rely on
//! eventually consistent database TTL deletion. Only token *digests* are stored.
//!
//! The HTTPS callback URL, rate-limiting of HTTP requests, safe cookies and
//! secure random bytes belong to the hosting adapters, never caller input.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use crate::identity::DomainName;

/// Short-lived, single-use login links; new requests replace the old token.
pub const LOGIN_TTL_SECONDS: i64 = 15 * 60;
/// At most one issued email per administrator per minute.
pub const LOGIN_COOLDOWN_SECONDS: i64 = 60;
/// After redemption, persistent, revocable sessions last one week.
pub const SESSION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAdminEmail;

impl fmt::Display for InvalidAdminEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid administrator email configuration")
    }
}
impl std::error::Error for InvalidAdminEmail {}

/// A single configured recipient: request input cannot choose an email target.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminEmail(String);

impl AdminEmail {
    pub fn parse(input: &str) -> Result<Self, InvalidAdminEmail> {
        let email = input.trim();
        if email.is_empty() || email.len() > 254 || !email.is_ascii() {
            return Err(InvalidAdminEmail);
        }
        let (local, domain) = email.split_once('@').ok_or(InvalidAdminEmail)?;
        // Support common unquoted addresses. Disallow whitespace, CRLF,
        // header delimiters and ambiguous quoted local-parts.
        if local.is_empty()
            || local.len() > 64
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || !local.bytes().all(|ch| {
                ch.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&ch)
            })
        {
            return Err(InvalidAdminEmail);
        }
        let domain = DomainName::parse(domain).map_err(|_| InvalidAdminEmail)?;
        Ok(Self(format!("{local}@{}", domain.as_str())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, requested_email: &str) -> bool {
        Self::parse(requested_email)
            .is_ok_and(|other| self.0.eq_ignore_ascii_case(&other.0))
    }
}

impl fmt::Debug for AdminEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminEmail([REDACTED])")
    }
}

/// Fail closed on credential-system errors. HTTP callers must give the same
/// generic request acknowledgement regardless of email or internal failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    Storage,
    Delivery,
    Entropy,
    Clock,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self {
            Self::Storage => "authentication storage unavailable",
            Self::Delivery => "authentication email delivery failed",
            Self::Entropy => "authentication secret generation failed",
            Self::Clock => "authentication clock out of range",
        };
        f.write_str(category)
    }
}
impl std::error::Error for AuthError {}

/// Hash of a 256-bit bearer secret. Never store raw tokens in durable storage
/// or include either raw tokens or digests in application logs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// An opaque, stable key for persistence in DynamoDB or another adapter.
    pub fn hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenDigest([REDACTED])")
    }
}

struct Secret([u8; 32]);

impl Secret {
    fn hex(&self) -> String {
        encode_hex(&self.0)
    }

    fn digest(&self) -> TokenDigest {
        TokenDigest(Sha256::digest(self.0).into())
    }

    fn parse(input: &str) -> Option<Self> {
        if input.len() != 64 || !input.is_ascii() {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (i, pair) in input.as_bytes().chunks_exact(2).enumerate() {
            fn digit(value: u8) -> Option<u8> {
                match value {
                    b'0'..=b'9' => Some(value - b'0'),
                    b'a'..=b'f' => Some(value - b'a' + 10),
                    b'A'..=b'F' => Some(value - b'A' + 10),
                    _ => None,
                }
            }
            bytes[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        Some(Self(bytes))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0xf) as usize] as char);
    }
    text
}

/// Value to set as the opaque, secure HttpOnly session cookie by the HTTP
/// adapter; the raw token must never go to logs or persistence.
pub struct SessionCredential {
    secret: Secret,
    expires_at: i64,
}

impl SessionCredential {
    pub fn cookie_value(&self) -> String {
        self.secret.hex()
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl fmt::Debug for SessionCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCredential([REDACTED])")
    }
}

/// Generate fresh cryptographically unpredictable bytes from an operating
/// system CSPRNG in the runtime adapter. Do NOT use timestamps, counters,
/// UUIDv4 substitutes or `DefaultHasher` for production tokens.
pub trait SecureTokenSource: Send + Sync {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError>;
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Format a trusted, configured HTTPS sign-in URL; never use the request's
    /// Host/Forwarded header. Ensure raw tokens are not logged.
    async fn send_sign_in_link(&self, recipient: &str, token: &str) -> Result<(), AuthError>;
}

/// Portable storage contract. Implement both challenge operations atomically.
/// Only one challenge per installation is needed (one administrator).
#[async_trait]
pub trait AuthenticationStore: Send + Sync {
    /// Conditionally save the *latest* digest and expiry. If a previous link
    /// was issued within the cooldown, return false without replacing it.
    /// A successfully stored new token invalidates all prior login links.
    async fn issue_login_challenge(
        &self,
        digest: TokenDigest,
        issued_at: i64,
        expires_at: i64,
        cooldown_seconds: i64,
    ) -> Result<bool, AuthError>;

    /// Atomically compare digest and unexpired timestamp, then remove it.
    /// At most one concurrent invocation may return true for a given link.
    async fn consume_login_challenge(
        &self,
        digest: &TokenDigest,
        now: i64,
    ) -> Result<bool, AuthError>;

    /// Create a session if its digest is not already present.
    async fn issue_session(
        &self,
        digest: TokenDigest,
        expires_at: i64,
    ) -> Result<(), AuthError>;

    /// Check both digest presence and the strict expiry (expires_at > now).
    async fn is_session_valid(
        &self,
        digest: &TokenDigest,
        now: i64,
    ) -> Result<bool, AuthError>;

    /// Remove a session if it exists; revoking an unknown digest succeeds.
    async fn revoke_session(&self, digest: &TokenDigest) -> Result<(), AuthError>;
}

pub struct Authentication<'a> {
    administrator: &'a AdminEmail,
    store: &'a dyn AuthenticationStore,
    sender: &'a dyn EmailSender,
    secrets: &'a dyn SecureTokenSource,
}

impl<'a> Authentication<'a> {
    pub fn new(
        administrator: &'a AdminEmail,
        store: &'a dyn AuthenticationStore,
        sender: &'a dyn EmailSender,
        secrets: &'a dyn SecureTokenSource,
    ) -> Self {
        Self {
            administrator,
            store,
            sender,
            secrets,
        }
    }

    /// Deliberately no returned `unknown email`/throttled status. The HTTP
    /// layer must give a uniform acknowledgement even for internal failures.
    pub async fn request_sign_in(
        &self,
        requested_email: &str,
        now: i64,
    ) -> Result<(), AuthError> {
        if !self.administrator.matches(requested_email) {
            return Ok(());
        }
        let expires_at = now.checked_add(LOGIN_TTL_SECONDS).ok_or(AuthError::Clock)?;
        let secret = Secret(self.secrets.fresh_secret()?);
        let issued = self
            .store
            .issue_login_challenge(
                secret.digest(),
                now,
                expires_at,
                LOGIN_COOLDOWN_SECONDS,
            )
            .await?;
        if issued {
            // May fail after the challenge is persisted. The token then
            // expires naturally and a new link may be requested after cooldown.
            self.sender
                .send_sign_in_link(self.administrator.as_str(), &secret.hex())
                .await?;
        }
        Ok(())
    }

    /// Accept a link only after an explicit browser action (POST); email
    /// security scanners may prefetch the GET link. Consume once, then issue
    /// a separate session credential. Storage failure after consumption does
    /// not restore the link; the administrator can request another one.
    pub async fn redeem_sign_in(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<SessionCredential>, AuthError> {
        let Some(secret) = Secret::parse(token) else {
            return Ok(None);
        };
        let expires_at = now.checked_add(SESSION_TTL_SECONDS).ok_or(AuthError::Clock)?;
        if !self.store.consume_login_challenge(&secret.digest(), now).await? {
            return Ok(None);
        }
        let session = Secret(self.secrets.fresh_secret()?);
        self.store.issue_session(session.digest(), expires_at).await?;
        Ok(Some(SessionCredential {
            secret: session,
            expires_at,
        }))
    }

    pub async fn is_authenticated(&self, cookie: &str, now: i64) -> Result<bool, AuthError> {
        let Some(secret) = Secret::parse(cookie) else {
            return Ok(false);
        };
        self.store.is_session_valid(&secret.digest(), now).await
    }

    pub async fn sign_out(&self, cookie: &str) -> Result<(), AuthError> {
        if let Some(secret) = Secret::parse(cookie) {
            self.store.revoke_session(&secret.digest()).await?;
        }
        Ok(())
    }
}

struct LoginChallenge {
    digest: TokenDigest,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Default)]
struct MemoryAuthState {
    login: Option<LoginChallenge>,
    sessions: HashMap<TokenDigest, i64>,
}

/// In-process reference adapter / test double. Never deploy this as the
/// authentication store in Lambda (cold starts and instances are ephemeral).
#[derive(Default)]
pub struct InMemoryAuthenticationStore {
    state: Mutex<MemoryAuthState>,
}

#[async_trait]
impl AuthenticationStore for InMemoryAuthenticationStore {
    async fn issue_login_challenge(
        &self,
        digest: TokenDigest,
        issued_at: i64,
        expires_at: i64,
        cooldown_seconds: i64,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().map_err(|_| AuthError::Storage)?;
        if state
            .login
            .as_ref()
            .is_some_and(|link| issued_at.saturating_sub(link.issued_at) < cooldown_seconds)
        {
            return Ok(false);
        }
        state.login = Some(LoginChallenge {
            digest,
            issued_at,
            expires_at,
        });
        Ok(true)
    }

    async fn consume_login_challenge(
        &self,
        digest: &TokenDigest,
        now: i64,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().map_err(|_| AuthError::Storage)?;
        if state
            .login
            .as_ref()
            .is_some_and(|link| &link.digest == digest && link.expires_at > now)
        {
            state.login = None;
            return Ok(true);
        }
        Ok(false)
    }

    async fn issue_session(
        &self,
        digest: TokenDigest,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().map_err(|_| AuthError::Storage)?;
        if state.sessions.contains_key(&digest) {
            return Err(AuthError::Storage); // random collision: fail closed
        }
        state.sessions.insert(digest, expires_at);
        Ok(())
    }

    async fn is_session_valid(
        &self,
        digest: &TokenDigest,
        now: i64,
    ) -> Result<bool, AuthError> {
        let state = self.state.lock().map_err(|_| AuthError::Storage)?;
        Ok(state
            .sessions
            .get(digest)
            .is_some_and(|expires_at| *expires_at > now))
    }

    async fn revoke_session(&self, digest: &TokenDigest) -> Result<(), AuthError> {
        let mut state = self.state.lock().map_err(|_| AuthError::Storage)?;
        state.sessions.remove(digest);
        Ok(())
    }
}
