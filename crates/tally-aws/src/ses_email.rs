//! SES v2 outbound magic-link emails for the single administrator.
//!
//! Only trusted installation configuration determines the sender, recipient
//! and HTTPS callback origin. Never derive links from a request Host header
//! and never log the SES request body or raw bearer token.

use async_trait::async_trait;
use aws_sdk_sesv2::{
    types::{Body, Content, Destination, EmailContent, Message},
    Client,
};
use tally_core::authentication::{AdminEmail, AuthError, EmailSender, LOGIN_TTL_SECONDS};
use url::Url;

/// A validated installation-level HTTPS origin, not a request-derived URL.
#[derive(Clone)]
pub struct SignInOrigin(String);

impl SignInOrigin {
    pub fn parse(value: &str) -> Result<Self, InvalidSignInOrigin> {
        if value.contains(['\\', '%', '?', '#']) || value.chars().any(char::is_whitespace) {
            return Err(InvalidSignInOrigin);
        }
        let url = Url::parse(value).map_err(|_| InvalidSignInOrigin)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(InvalidSignInOrigin);
        }
        Ok(Self(url.origin().ascii_serialization()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Safe configuration errors never echo an untrusted URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSignInOrigin;

impl std::fmt::Display for InvalidSignInOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid configured HTTPS origin for sign-in email")
    }
}
impl std::error::Error for InvalidSignInOrigin {}

/// No Debug implementation: this value contains a one-time sign-in link.
struct PreparedEmail {
    sender: String,
    recipient: String,
    subject: &'static str,
    text_body: String,
}

/// Pure preflight called before any SES operation. A caller cannot redirect
/// a sign-in token to an address other than the configured administrator.
fn prepare_email(
    from: &AdminEmail,
    administrator: &AdminEmail,
    site: &SignInOrigin,
    requested_recipient: &str,
    token: &str,
) -> Result<PreparedEmail, AuthError> {
    if !administrator.matches(requested_recipient)
        || token.len() != 64
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AuthError::Delivery);
    }

    let sign_in_url = format!("{}/auth/confirm?token={token}", site.as_str());
    Ok(PreparedEmail {
        sender: from.as_str().to_owned(),
        recipient: administrator.as_str().to_owned(),
        subject: "Your DMARC Tally sign-in link",
        text_body: format!(
            "A sign-in link was requested for DMARC Tally.\n\n\
             Open this link to continue:\n{sign_in_url}\n\n\
             This link can only be used once and expires after {} minutes.\n\
             If you did not request it, you can ignore this email.\n",
            LOGIN_TTL_SECONDS / 60
        ),
    })
}

/// AWS SDK infrastructure implementation of the portable EmailSender port.
#[derive(Clone)]
pub struct SesEmailSender {
    client: Client,
    from: AdminEmail,
    administrator: AdminEmail,
    site: SignInOrigin,
}

impl SesEmailSender {
    pub fn new(
        client: Client,
        from: AdminEmail,
        administrator: AdminEmail,
        site: SignInOrigin,
    ) -> Self {
        Self {
            client,
            from,
            administrator,
            site,
        }
    }
}

#[async_trait]
impl EmailSender for SesEmailSender {
    async fn send_sign_in_link(&self, recipient: &str, token: &str) -> Result<(), AuthError> {
        let email = prepare_email(
            &self.from,
            &self.administrator,
            &self.site,
            recipient,
            token,
        )?;
        let subject = Content::builder()
            .data(email.subject)
            .charset("UTF-8")
            .build()
            .map_err(|_| AuthError::Delivery)?;
        let body = Content::builder()
            .data(email.text_body)
            .charset("UTF-8")
            .build()
            .map_err(|_| AuthError::Delivery)?;
        let content = EmailContent::builder()
            .simple(
                Message::builder()
                    .subject(subject)
                    .body(Body::builder().text(body).build())
                    .build(),
            )
            .build();
        self.client
            .send_email()
            .from_email_address(email.sender)
            .destination(Destination::builder().to_addresses(email.recipient).build())
            .content(content)
            .send()
            .await
            .map_err(|_| AuthError::Delivery)?;
        // Do not print the SES request, message ID, recipient or raw URL.
        Ok(())
    }
}

// Tests for single-recipient SES magic-link mail formatting.
#[cfg(test)]
mod tests {
    use super::{prepare_email, SesEmailSender, SignInOrigin};
    use tally_core::authentication::{AdminEmail, AuthError, EmailSender};

    fn addresses() -> (AdminEmail, AdminEmail) {
        (
            AdminEmail::parse("sign-in@mailer.example.com").unwrap(),
            AdminEmail::parse("Admin@example.com").unwrap(),
        )
    }

    #[test]
    fn implements_port_without_new_core_dependencies() {
        fn require_port<T: EmailSender + Send + Sync>() {}
        require_port::<SesEmailSender>();
    }

    #[test]
    fn configured_site_must_be_https_and_cannot_choose_another_destination() {
        for invalid in [
            "",
            "http://private.example",
            "https://someone@private.example",
            "https://private.example/path",
            "https://private.example?next=other",
            "https://private.example/#part",
        ] {
            assert!(SignInOrigin::parse(invalid).is_err());
        }
        let origin = SignInOrigin::parse("https://PRIVATE.example:443/").unwrap();
        assert_eq!(origin.as_str(), "https://private.example");
    }

    #[test]
    fn one_plain_text_message_goes_only_to_the_configured_admin() {
        let (from, admin) = addresses();
        let site = SignInOrigin::parse("https://private.example").unwrap();
        let token = "a0".repeat(32);
        let email = prepare_email(&from, &admin, &site, "admin@example.com", &token).unwrap();
        assert_eq!(email.sender, "sign-in@mailer.example.com");
        assert_eq!(email.recipient, "Admin@example.com");
        assert_eq!(email.subject, "Your DMARC Tally sign-in link");
        assert!(email
            .text_body
            .contains("https://private.example/auth/confirm?token="));
        assert!(email.text_body.contains(&token));
        assert!(email.text_body.contains("15 minutes"));
    }

    #[test]
    fn unconfigured_recipient_and_bad_token_are_rejected_without_delivery() {
        let (from, admin) = addresses();
        let site = SignInOrigin::parse("https://private.example").unwrap();
        assert!(matches!(
            prepare_email(&from, &admin, &site, "other@example.com", &"a0".repeat(32)),
            Err(AuthError::Delivery)
        ));
        assert!(matches!(
            prepare_email(&from, &admin, &site, admin.as_str(), "bad"),
            Err(AuthError::Delivery)
        ));
    }
}
