//! On-demand, read-only SES identity evidence for the private setup page.
//! Never log SDK errors or identity inputs; no AWS call runs before HTTP auth.

use aws_sdk_sesv2::{types::VerificationStatus, Client};

/// Evidence about one exact SES domain/email identity, not about mail delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityEvidence {
    Verified,
    NotVerified,
    UnableToCheck,
}

#[derive(Clone)]
pub struct SesIdentityReader {
    client: Client,
}

impl SesIdentityReader {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn inspect(&self, identity: &str, require_sending: bool) -> IdentityEvidence {
        // Only installation-controlled identities may be supplied by the
        // composition root, never an HTTP query field.
        match self
            .client
            .get_email_identity()
            .email_identity(identity)
            .send()
            .await
        {
            Ok(output) => classify(
                output.verification_status(),
                output.verified_for_sending_status(),
                require_sending,
            ),
            // Missing identity, permissions, throttling and network errors
            // are indistinguishable without inspecting error detail.
            Err(_) => IdentityEvidence::UnableToCheck,
        }
    }
}

fn classify(
    verification: Option<&VerificationStatus>,
    sending_enabled: bool,
    require_sending: bool,
) -> IdentityEvidence {
    match verification {
        Some(VerificationStatus::Success) if !require_sending || sending_enabled => {
            IdentityEvidence::Verified
        }
        Some(_) => IdentityEvidence::NotVerified,
        None => IdentityEvidence::UnableToCheck,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, IdentityEvidence};
    use aws_sdk_sesv2::types::VerificationStatus;

    #[test]
    fn only_positive_ses_evidence_is_ready() {
        assert_eq!(
            classify(Some(&VerificationStatus::Success), false, false),
            IdentityEvidence::Verified
        );
        assert_eq!(
            classify(Some(&VerificationStatus::Success), true, true),
            IdentityEvidence::Verified
        );
        assert_eq!(
            classify(Some(&VerificationStatus::Success), false, true),
            IdentityEvidence::NotVerified
        );
        for status in [
            VerificationStatus::Pending,
            VerificationStatus::Failed,
            VerificationStatus::TemporaryFailure,
            VerificationStatus::NotStarted,
        ] {
            assert_eq!(
                classify(Some(&status), true, false),
                IdentityEvidence::NotVerified
            );
        }
        assert_eq!(
            classify(None, true, false),
            IdentityEvidence::UnableToCheck
        );
    }
}
