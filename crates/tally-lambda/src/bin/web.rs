//! Private HTTP API Gateway v2 / Lambda Function URL composition root.
//!
//! Configuration, SDK clients and the web-to-HTTP translation stay here.
//! No network listener, authorization bypass or public endpoint is created.
//! The web gateway alone authorizes every reporting query.

use std::time::{SystemTime, UNIX_EPOCH};

use aws_config::BehaviorVersion;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::Value;
use tally_aws::{
    auth_store::DynamoAuthenticationStore,
    dynamo_repository::DynamoReportRepository,
    entropy::OsTokenSource,
    ses_email::{SesEmailSender, SignInOrigin},
    ses_identity::{IdentityEvidence, SesIdentityReader},
    ses_receiving::{ReceiptEvidence, SesReceiptReader},
};
use tally_core::{
    authentication::{AdminEmail, Authentication},
    identity::DomainSet,
};
use tally_lambda::web_event::handle_http_v2;
use tally_web::{
    http::SiteOrigin,
    setup::{CheckState, SetupCheck, SetupInspector, SetupSnapshot},
};

#[derive(Clone)]
struct App {
    administrator: AdminEmail,
    domains: DomainSet,
    site: SiteOrigin,
    auth_store: DynamoAuthenticationStore,
    reports: DynamoReportRepository,
    email: SesEmailSender,
    entropy: OsTokenSource,
    setup: SesSetupInspector,
}

#[derive(Clone)]
struct SesSetupInspector {
    receiving_address: Option<String>,
    sender_identity: String,
    identities: SesIdentityReader,
    receipts: SesReceiptReader,
    receiving_rule_set: String,
    receiving_rule_name: String,
    intake_bucket: String,
    domains: DomainSet,
}

#[async_trait::async_trait]
impl SetupInspector for SesSetupInspector {
    async fn inspect(&self) -> SetupSnapshot {
        // These on-demand SES v2 lookups establish identity status only.
        // Neither a verified identity nor a configured address proves delivery.
        let receiving_domain = self.receiving_address.as_deref().and_then(|address| {
            if AdminEmail::parse(address).is_ok() {
                address.split_once('@').map(|(_, domain)| domain)
            } else {
                None
            }
        });
        let receiving = match receiving_domain {
            Some(domain) => Some(self.identities.inspect(domain, false).await),
            None => None,
        };
        let sending = self.identities.inspect(&self.sender_identity, true).await;
        let receipt = match self.receiving_address.as_deref() {
            Some(address) if AdminEmail::parse(address).is_ok() => {
                self.receipts
                    .inspect(
                        &self.receiving_rule_set,
                        &self.receiving_rule_name,
                        address,
                        &self.intake_bucket,
                    )
                    .await
            }
            _ => ReceiptEvidence::ActionRequired(
                "Configure a valid receiving address before checking the SES rule.",
            ),
        };
        let (receipt_state, receipt_detail) = match receipt {
            ReceiptEvidence::Ready => (
                CheckState::Ready,
                "The active SES rule matches this recipient and writes to the expected S3 intake prefix. Rule ordering, role permissions and actual delivery are not proven.",
            ),
            ReceiptEvidence::ActionRequired(detail) => (CheckState::ActionRequired, detail),
            ReceiptEvidence::UnableToCheck => (
                CheckState::UnableToCheck,
                "Unable to inspect the active SES receipt rule set. Check permissions, region and SES availability.",
            ),
        };
        let (receiving_state, receiving_detail) = match receiving {
            Some(IdentityEvidence::Verified) => (
                CheckState::Ready,
                "The receiving domain identity is verified in SES in this region. Mail routing and receipt rules still need checking.",
            ),
            Some(IdentityEvidence::NotVerified) => (
                CheckState::ActionRequired,
                "This exact receiving domain identity is not verified in SES. Check its verification and any applicable parent-domain identity.",
            ),
            Some(IdentityEvidence::UnableToCheck) => (
                CheckState::UnableToCheck,
                "SES could not verify the receiving domain status. Check read permissions, identity existence and regional configuration.",
            ),
            None => (
                CheckState::NotVerified,
                "Configure a valid receiving address before checking its SES identity.",
            ),
        };
        let (sending_state, sending_detail) = match sending {
            IdentityEvidence::Verified => (
                CheckState::Ready,
                "The configured sending identity is verified and enabled for sending in this SES region.",
            ),
            IdentityEvidence::NotVerified => (
                CheckState::ActionRequired,
                "The configured sending identity is not verified or enabled for sending in this SES region.",
            ),
            IdentityEvidence::UnableToCheck => (
                CheckState::UnableToCheck,
                "SES could not verify the sending identity status. Check read permissions, identity existence and regional configuration.",
            ),
        };
        SetupSnapshot {
            receiving_address: self.receiving_address.clone(),
            monitored_domains: self.domains.domains().iter().cloned().collect(),
            checks: vec![
                SetupCheck {
                    title: "SES receiving rule and S3 destination",
                    state: receipt_state,
                    detail: receipt_detail.into(),
                },
                SetupCheck {
                    title: "SES receiving identity",
                    state: receiving_state,
                    detail: receiving_detail.into(),
                },
                SetupCheck {
                    title: "SES sending identity",
                    state: sending_state,
                    detail: sending_detail.into(),
                },
                SetupCheck {
                    title: "MX and DMARC DNS",
                    state: CheckState::NotVerified,
                    detail: "Receiving MX, monitored-domain rua and external authorization have not been checked.".into(),
                },
                SetupCheck {
                    title: "End-to-end report delivery",
                    state: CheckState::NotVerified,
                    detail: "A successfully received, processed report has not been verified.".into(),
                },
                SetupCheck {
                    title: "Failure notifications",
                    state: CheckState::NotVerified,
                    detail: "SNS subscription and alarm delivery have not been verified.".into(),
                },
            ],
        }
    }
}

fn required(name: &'static str) -> Result<String, Error> {
    let value = std::env::var(name)?;
    if value.trim().is_empty() {
        return Err(format!("Required application configuration is empty: {name}").into());
    }
    Ok(value)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let auth_table = required("AUTH_TABLE")?;
    let reports_table = required("REPORTS_TABLE")?;
    if auth_table == reports_table {
        return Err("Authentication and reporting must use separate DynamoDB tables".into());
    }
    let administrator = AdminEmail::parse(&required("ADMIN_EMAIL")?)?;
    let sender = AdminEmail::parse(&required("SES_FROM_EMAIL")?)?;
    let sender_identity = required("SES_SENDER_IDENTITY")?;
    let receiving_rule_set = required("SES_RECEIPT_RULE_SET")?;
    let receiving_rule_name = required("SES_RECEIPT_RULE_NAME")?;
    let intake_bucket = required("INTAKE_BUCKET")?;
    let configured_origin = required("PUBLIC_ORIGIN")?;
    let site = SiteOrigin::parse(&configured_origin)?;
    let email_origin = SignInOrigin::parse(&configured_origin)?;
    let domains = DomainSet::new(required("MONITORED_DOMAINS")?.split(',').map(str::trim))?;

    // Each SDK client is shared across warm Lambda invocations.
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ses = aws_sdk_sesv2::Client::new(&config);
    let ses_receiving = aws_sdk_ses::Client::new(&config);
    let app = App {
        administrator: administrator.clone(),
        setup: SesSetupInspector {
            receiving_address: std::env::var("RECEIVING_ADDRESS").ok(),
            sender_identity,
            identities: SesIdentityReader::new(ses.clone()),
            receipts: SesReceiptReader::new(ses_receiving),
            receiving_rule_set,
            receiving_rule_name,
            intake_bucket,
            domains: domains.clone(),
        },
        domains,
        site,
        auth_store: DynamoAuthenticationStore::new(dynamodb.clone(), auth_table),
        reports: DynamoReportRepository::new(dynamodb, reports_table),
        email: SesEmailSender::new(ses, sender, administrator, email_origin),
        entropy: OsTokenSource,
    };

    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let app = app.clone();
        async move {
            // Do not use user-controlled request timestamps for session expiry.
            let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let now = i64::try_from(epoch)?;
            let auth = Authentication::new(
                &app.administrator,
                &app.auth_store,
                &app.email,
                &app.entropy,
            );
            let response = handle_http_v2(
                &event.payload,
                &auth,
                &app.reports,
                &app.domains,
                &app.site,
                &app.setup,
                now,
            )
            .await;
            // Never log the event or response: either may include secrets.
            Ok::<Value, Error>(response)
        }
    }))
    .await
}
