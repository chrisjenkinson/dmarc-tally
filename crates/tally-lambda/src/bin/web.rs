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
};
use tally_core::{
    authentication::{AdminEmail, Authentication},
    identity::DomainSet,
};
use tally_lambda::web_event::handle_http_v2;
use tally_web::http::SiteOrigin;

#[derive(Clone)]
struct App {
    administrator: AdminEmail,
    domains: DomainSet,
    site: SiteOrigin,
    auth_store: DynamoAuthenticationStore,
    reports: DynamoReportRepository,
    email: SesEmailSender,
    entropy: OsTokenSource,
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
    let configured_origin = required("PUBLIC_ORIGIN")?;
    let site = SiteOrigin::parse(&configured_origin)?;
    let email_origin = SignInOrigin::parse(&configured_origin)?;
    let domains = DomainSet::new(required("MONITORED_DOMAINS")?.split(',').map(str::trim))?;

    // Each SDK client is shared across warm Lambda invocations.
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ses = aws_sdk_sesv2::Client::new(&config);
    let app = App {
        administrator: administrator.clone(),
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
                now,
            )
            .await;
            // Never log the event or response: either may include secrets.
            Ok::<Value, Error>(response)
        }
    }))
    .await
}
