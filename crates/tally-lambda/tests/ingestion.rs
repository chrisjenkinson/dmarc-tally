//! Contract tests for S3 → core → repository → conditional capture tagging.
//! No AWS account is needed: the fake is strictly at the S3 adapter boundary.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use tally_aws::s3::{S3EmailStore, S3ObjectRef, S3StoreError};
use tally_core::{
    identity::{report_identity, DomainSet},
    ingest::IngestLimits,
    model::ParseLimits,
    ports::{InMemoryReportRepository, ReportRepository},
    xml::parse_dmarc_xml,
};
use tally_lambda::ingestion::{ingest_s3_object, ProcessingOutcome};

const GOOD: &[u8] = include_bytes!("../../../tests/fixtures/xml/legacy.xml");
const UNKNOWN: &[u8] = include_bytes!("../../../tests/fixtures/xml/unknown-extension.xml");

fn email(xmls: &[&[u8]]) -> Vec<u8> {
    let mut result = String::from(
        "From: reports@receiver.example\r\nTo: reports@example.net\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=dm\r\n\r\n",
    );
    for xml in xmls {
        result.push_str("--dm\r\nContent-Type: application/xml\r\nContent-Disposition: attachment; filename=\"report.xml\"\r\n\r\n");
        result.push_str(std::str::from_utf8(xml).unwrap());
        result.push_str("\r\n");
    }
    result.push_str("--dm--\r\n");
    result.into_bytes()
}

fn object() -> S3ObjectRef {
    S3ObjectRef {
        bucket: "private-dmarc-bucket".into(),
        key: "incoming/sample.eml".into(),
        version_id: None,
    }
}

#[derive(Default)]
struct FakeS3 {
    bodies: Mutex<HashMap<String, Vec<u8>>>,
    tags: Mutex<Vec<String>>,
    tagging_failure: Mutex<bool>,
    read_failure: Mutex<bool>,
}

impl FakeS3 {
    fn insert(&self, key: &str, bytes: Vec<u8>) {
        self.bodies.lock().unwrap().insert(key.to_string(), bytes);
    }
    fn tag_count(&self) -> usize {
        self.tags.lock().unwrap().len()
    }
}

#[async_trait]
impl S3EmailStore for FakeS3 {
    async fn read_email(
        &self,
        object: &S3ObjectRef,
        max_bytes: usize,
    ) -> Result<Vec<u8>, S3StoreError> {
        if *self.read_failure.lock().unwrap() {
            return Err(S3StoreError::Unavailable("temporary S3 failure".into()));
        }
        let value = self
            .bodies
            .lock()
            .unwrap()
            .get(&object.key)
            .cloned()
            .ok_or_else(|| S3StoreError::Unavailable("missing test object".into()))?;
        if value.len() > max_bytes {
            return Err(S3StoreError::TooLarge);
        }
        Ok(value)
    }

    async fn mark_captured(&self, object: &S3ObjectRef) -> Result<(), S3StoreError> {
        if *self.tagging_failure.lock().unwrap() {
            return Err(S3StoreError::Unavailable("tagging failed".into()));
        }
        self.tags.lock().unwrap().push(object.key.clone());
        Ok(())
    }
}

fn domains() -> DomainSet {
    DomainSet::new(["example.com", "example.net"]).unwrap()
}

#[tokio::test]
async fn tags_only_after_successful_persistence_and_is_idempotent_on_replay() {
    let s3 = FakeS3::default();
    s3.insert(&object().key, email(&[GOOD]));
    let reports = InMemoryReportRepository::default();

    let first = ingest_s3_object(
        &object(),
        &s3,
        &reports,
        &domains(),
        &IngestLimits::default(),
    )
    .await
    .unwrap();
    assert!(matches!(first, ProcessingOutcome::Captured(_)));
    assert_eq!(s3.tag_count(), 1);

    let repeated = ingest_s3_object(
        &object(),
        &s3,
        &reports,
        &domains(),
        &IngestLimits::default(),
    )
    .await
    .unwrap();
    let ProcessingOutcome::Captured(outcome) = repeated else {
        panic!("repeat should be captured")
    };
    assert_eq!(outcome.previously_completed, 1);
    assert_eq!(outcome.newly_completed, 0);
    assert_eq!(s3.tag_count(), 2);
}

#[tokio::test]
async fn mixed_batch_persists_good_report_but_never_tags_outer_email() {
    let s3 = FakeS3::default();
    s3.insert(&object().key, email(&[GOOD, UNKNOWN]));
    let reports = InMemoryReportRepository::default();
    let result = ingest_s3_object(
        &object(),
        &s3,
        &reports,
        &domains(),
        &IngestLimits::default(),
    )
    .await
    .unwrap();
    assert!(matches!(result, ProcessingOutcome::Retained(_)));
    assert_eq!(s3.tag_count(), 0);

    let parsed = parse_dmarc_xml(GOOD, &ParseLimits::default()).unwrap();
    assert!(reports
        .get_report(&report_identity(&parsed))
        .await
        .unwrap()
        .is_some());
    assert!(matches!(
        ingest_s3_object(
            &object(),
            &s3,
            &reports,
            &domains(),
            &IngestLimits::default()
        )
        .await
        .unwrap(),
        ProcessingOutcome::Retained(_)
    ));
    assert_eq!(s3.tag_count(), 0);
}

#[tokio::test]
async fn unsupported_or_oversized_mail_is_retained_without_tagging() {
    let s3 = FakeS3::default();
    s3.insert(&object().key, email(&[b"<invalid/>"]));
    let reports = InMemoryReportRepository::default();
    assert!(matches!(
        ingest_s3_object(
            &object(),
            &s3,
            &reports,
            &domains(),
            &IngestLimits::default()
        )
        .await
        .unwrap(),
        ProcessingOutcome::Retained(_)
    ));
    let mut limits = IngestLimits::default();
    limits.mail.max_message_bytes = 10;
    assert!(matches!(
        ingest_s3_object(&object(), &s3, &reports, &domains(), &limits)
            .await
            .unwrap(),
        ProcessingOutcome::Retained(_)
    ));
    assert_eq!(s3.tag_count(), 0);
}

#[tokio::test]
async fn failed_tagging_returns_retryable_error_after_report_was_saved() {
    let s3 = FakeS3::default();
    s3.insert(&object().key, email(&[GOOD]));
    *s3.tagging_failure.lock().unwrap() = true;
    let reports = InMemoryReportRepository::default();

    assert!(ingest_s3_object(
        &object(),
        &s3,
        &reports,
        &domains(),
        &IngestLimits::default()
    )
    .await
    .is_err());
    assert_eq!(s3.tag_count(), 0);
    *s3.tagging_failure.lock().unwrap() = false;

    let result = ingest_s3_object(
        &object(),
        &s3,
        &reports,
        &domains(),
        &IngestLimits::default(),
    )
    .await
    .unwrap();
    let ProcessingOutcome::Captured(report) = result else {
        panic!("retry must complete")
    };
    assert_eq!(report.previously_completed, 1);
    assert_eq!(s3.tag_count(), 1);
}

#[tokio::test]
async fn transient_s3_read_error_causes_retry_not_retention_acknowledgement() {
    let s3 = FakeS3::default();
    *s3.read_failure.lock().unwrap() = true;
    let reports = InMemoryReportRepository::default();
    assert!(ingest_s3_object(
        &object(),
        &s3,
        &reports,
        &domains(),
        &IngestLimits::default()
    )
    .await
    .is_err());
    assert_eq!(s3.tag_count(), 0);
}

#[tokio::test]
async fn unconfigured_domain_is_retained_without_tagging() {
    let s3 = FakeS3::default();
    s3.insert(&object().key, email(&[GOOD]));
    let reports = InMemoryReportRepository::default();
    let other = DomainSet::new(["other.example"]).unwrap();
    assert!(matches!(
        ingest_s3_object(&object(), &s3, &reports, &other, &IngestLimits::default())
            .await
            .unwrap(),
        ProcessingOutcome::Retained(_)
    ));
    assert_eq!(s3.tag_count(), 0);
}
