//! S3 ObjectCreated → DynamoDB report persistence → captured=true tagging.
//!
//! This is the deployable \`provided.al2023\` ingestion Lambda entry point.
//! The CloudFormation stack (separate feature) supplies environment variables
//! and an S3 notification filtered to the \`incoming/\` prefix.

use aws_config::BehaviorVersion;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};
use tally_aws::{
    dynamo_repository::DynamoReportRepository,
    s3::AwsS3EmailStore,
    setup_evidence::ProcessingEvidenceStore,
};
use tally_core::{identity::DomainSet, ingest::IngestLimits};
use tally_lambda::{
    ingestion::{ingest_s3_object, ProcessingOutcome, RetainedInput},
    s3_event::created_intake_objects,
};

#[derive(Clone)]
struct Handler {
    bucket: String,
    domains: DomainSet,
    s3: AwsS3EmailStore,
    reports: DynamoReportRepository,
    evidence: ProcessingEvidenceStore,
}

async fn process_s3_event(event: LambdaEvent<Value>, handler: Handler) -> Result<Value, Error> {
    let objects = created_intake_objects(&event.payload, &handler.bucket)?;
    let mut captured = 0_usize;
    let mut retained = 0_usize;
    let mut new_reports = 0_usize;
    let mut existing_reports = 0_usize;

    for object in &objects {
        // ASYNC S3 notification → synchronous work within this handler.
        // Errors here reject the whole invocation, which Lambda retries.
        // The persistent repository is idempotent under duplicate delivery.
        let outcome = ingest_s3_object(
            object,
            &handler.s3,
            &handler.reports,
            &handler.domains,
            &IngestLimits::default(),
        )
        .await?;

        match outcome {
            ProcessingOutcome::Captured(result) => {
                // Report persistence and S3 capture tagging succeeded. Keep
                // only a tiny, non-identifying processing-evidence marker.
                // A failure is retryable: the ingestion workflow is idempotent.
                handler.evidence.record_success(&handler.bucket).await?;
                captured += 1;
                new_reports += result.newly_completed;
                existing_reports += result.previously_completed;
            }
            ProcessingOutcome::Retained(reason) => {
                retained += 1;
                // Log only categorical retention reasons. Do not put raw MIME,
                // XML, email addresses, S3 keys or message bodies into logs.
                let reason_code = match reason {
                    RetainedInput::Incomplete(_) => "incomplete-report",
                    RetainedInput::Unsupported => "unsupported-message",
                    RetainedInput::TooLarge => "oversize-message",
                };
                println!("DMARC intake retained: reason={reason_code}");
            }
        }
    }

    println!(
        "DMARC intake processed={} captured={} retained={} new_reports={} duplicate_reports={}",
        objects.len(),
        captured,
        retained,
        new_reports,
        existing_reports
    );
    Ok(json!({
        "processed": objects.len(),
        "captured": captured,
        "retained": retained,
        "new_reports": new_reports,
        "duplicate_reports": existing_reports
    }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let bucket = std::env::var("INTAKE_BUCKET")?;
    let table = std::env::var("REPORTS_TABLE")?;
    let configured = std::env::var("MONITORED_DOMAINS")?;
    if bucket.trim().is_empty() || table.trim().is_empty() {
        return Err("INTAKE_BUCKET and REPORTS_TABLE must be nonempty".into());
    }
    let domains = DomainSet::new(configured.split(',').map(str::trim))?;

    // SDK clients are reused across warm invocations.
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let handler = Handler {
        bucket,
        domains,
        s3: AwsS3EmailStore::new(aws_sdk_s3::Client::new(&config)),
        evidence: ProcessingEvidenceStore::new(aws_sdk_s3::Client::new(&config)),
        reports: DynamoReportRepository::new(aws_sdk_dynamodb::Client::new(&config), table),
    };

    lambda_runtime::run(service_fn(move |event| {
        process_s3_event(event, handler.clone())
    }))
    .await
}
