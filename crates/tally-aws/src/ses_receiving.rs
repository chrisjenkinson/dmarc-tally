//! Read-only, on-demand evidence about the *active* SES receiving rule.
//! SES classic DescribeActiveReceiptRuleSet is limited to once per second.
//! Configuration values are trusted local installation parameters, not input
//! taken from an HTTP request. Never log raw AWS results or SDK errors.

use aws_sdk_ses::{types::ReceiptRule, Client};

/// Evidence about one rule's configuration, not proof of incoming delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptEvidence {
    Ready,
    ActionRequired(&'static str),
    UnableToCheck,
}

#[derive(Clone)]
pub struct SesReceiptReader {
    client: Client,
}

impl SesReceiptReader {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn inspect(
        &self,
        expected_set: &str,
        expected_rule: &str,
        receiving_address: &str,
        intake_bucket: &str,
    ) -> ReceiptEvidence {
        match self.client.describe_active_receipt_rule_set().send().await {
            Ok(response) => assess(
                response.metadata().and_then(|metadata| metadata.name()),
                response.rules(),
                expected_set,
                expected_rule,
                receiving_address,
                intake_bucket,
            ),
            Err(_) => ReceiptEvidence::UnableToCheck,
        }
    }
}

/// Pure, bounded assessment of the response returned by SES. Missing
/// properties are never interpreted as successful evidence.
fn assess(
    active_set: Option<&str>,
    rules: &[ReceiptRule],
    expected_set: &str,
    expected_rule: &str,
    receiving_address: &str,
    intake_bucket: &str,
) -> ReceiptEvidence {
    if active_set.is_none() {
        return ReceiptEvidence::ActionRequired(
            "No SES receipt rule set is active in this region.",
        );
    }
    if active_set != Some(expected_set) {
        return ReceiptEvidence::ActionRequired(
            "A different SES receipt rule set is active. Review it before any activation change.",
        );
    }
    let Some(rule) = rules.iter().find(|rule| rule.name() == expected_rule) else {
        return ReceiptEvidence::ActionRequired(
            "The intended receipt rule is missing from the active SES rule set.",
        );
    };
    if !rule.enabled() {
        return ReceiptEvidence::ActionRequired("The intended SES receipt rule is disabled.");
    }
    // Domain-wide or catch-all rules would accept more mail than the
    // installer intends; an empty recipients list matches every address.
    if rule.recipients().len() != 1 || rule.recipients()[0] != receiving_address
    {
        return ReceiptEvidence::ActionRequired(
            "The receipt rule does not specify exactly the configured receiving address.",
        );
    }
    if !rule.scan_enabled() {
        return ReceiptEvidence::ActionRequired(
            "The receipt rule does not have SES spam and malware scanning enabled.",
        );
    }
    if rule.actions().len() != 1 {
        return ReceiptEvidence::ActionRequired(
            "The receipt rule must contain only the intended S3 delivery action.",
        );
    }
    let Some(s3) = rule.actions()[0].s3_action() else {
        return ReceiptEvidence::ActionRequired("The receipt rule has no S3 delivery action.");
    };
    if s3.bucket_name() != intake_bucket || s3.object_key_prefix() != Some("incoming/") {
        return ReceiptEvidence::ActionRequired(
            "The SES S3 destination does not match the production intake bucket and incoming/ prefix.",
        );
    }
    if s3.kms_key_arn().is_some() {
        return ReceiptEvidence::ActionRequired(
            "SES client-side KMS encryption is enabled but the importer cannot decrypt it.",
        );
    }
    if s3.iam_role_arn().is_none() {
        return ReceiptEvidence::ActionRequired(
            "The receipt rule is missing the dedicated SES S3 delivery IAM role.",
        );
    }
    ReceiptEvidence::Ready
}

#[cfg(test)]
mod tests {
    use super::{assess, ReceiptEvidence};
    use aws_sdk_ses::types::{ReceiptAction, ReceiptRule, S3Action};

    fn rule() -> ReceiptRule {
        ReceiptRule::builder()
            .name("dmarc-tally-reports")
            .enabled(true)
            .scan_enabled(true)
            .recipients("reports@dmarc.example.net")
            .actions(
                ReceiptAction::builder()
                    .s3_action(
                        S3Action::builder()
                            .bucket_name("intake-bucket")
                            .object_key_prefix("incoming/")
                            .iam_role_arn("arn:aws:iam::123456789012:role/delivery")
                            .build()
                            .expect("valid S3 action"),
                    )
                    .build(),
            )
            .build()
            .expect("valid receipt rule")
    }

    fn check(set: Option<&str>, rules: &[ReceiptRule]) -> ReceiptEvidence {
        assess(
            set,
            rules,
            "production",
            "dmarc-tally-reports",
            "reports@dmarc.example.net",
            "intake-bucket",
        )
    }

    #[test]
    fn only_expected_active_rule_and_s3_action_are_ready() {
        assert_eq!(check(Some("production"), &[rule()]), ReceiptEvidence::Ready);
        assert!(matches!(
            check(None, &[rule()]),
            ReceiptEvidence::ActionRequired(_)
        ));
        assert!(matches!(
            check(Some("staging"), &[rule()]),
            ReceiptEvidence::ActionRequired(_)
        ));
        assert!(matches!(
            check(Some("production"), &[]),
            ReceiptEvidence::ActionRequired(_)
        ));
    }

    #[test]
    fn disabled_or_overbroad_rule_requires_action() {
        let disabled = ReceiptRule::builder()
            .name("dmarc-tally-reports")
            .enabled(false)
            .build()
            .unwrap();
        assert!(matches!(
            check(Some("production"), &[disabled]),
            ReceiptEvidence::ActionRequired(_)
        ));
        let catchall = ReceiptRule::builder()
            .name("dmarc-tally-reports")
            .enabled(true)
            .scan_enabled(true)
            .actions(
                ReceiptAction::builder()
                    .s3_action(
                        S3Action::builder()
                            .bucket_name("intake-bucket")
                            .object_key_prefix("incoming/")
                            .iam_role_arn("role")
                            .build()
                            .unwrap(),
                    )
                    .build(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            check(Some("production"), &[catchall]),
            ReceiptEvidence::ActionRequired(_)
        ));
    }

    #[test]
    fn incorrect_destination_and_kms_encryption_are_rejected() {
        let wrong = ReceiptRule::builder()
            .name("dmarc-tally-reports")
            .enabled(true)
            .scan_enabled(true)
            .recipients("reports@dmarc.example.net")
            .actions(
                ReceiptAction::builder()
                    .s3_action(
                        S3Action::builder()
                            .bucket_name("other-bucket")
                            .object_key_prefix("incoming/")
                            .iam_role_arn("role")
                            .build()
                            .unwrap(),
                    )
                    .build(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            check(Some("production"), &[wrong]),
            ReceiptEvidence::ActionRequired(_)
        ));
        let encrypted = ReceiptRule::builder()
            .name("dmarc-tally-reports")
            .enabled(true)
            .scan_enabled(true)
            .recipients("reports@dmarc.example.net")
            .actions(
                ReceiptAction::builder()
                    .s3_action(
                        S3Action::builder()
                            .bucket_name("intake-bucket")
                            .object_key_prefix("incoming/")
                            .iam_role_arn("role")
                            .kms_key_arn("kms-key")
                            .build()
                            .unwrap(),
                    )
                    .build(),
            )
            .build()
            .unwrap();
        assert!(matches!(
            check(Some("production"), &[encrypted]),
            ReceiptEvidence::ActionRequired(_)
        ));
    }
}
