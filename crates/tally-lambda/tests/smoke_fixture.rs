//! The exact synthetic emails used by the isolated AWS smoke check.
//! Verify them with the real parser and application before deployment.

use tally_core::{
    identity::DomainSet,
    ingest::{import_email, IngestLimits},
    ports::InMemoryReportRepository,
};

const VALID_EMAIL: &[u8] = include_bytes!("../../../tests/fixtures/mime/smoke-valid.eml");
const INVALID_EMAIL: &[u8] = include_bytes!("../../../tests/fixtures/mime/smoke-invalid.eml");

#[tokio::test]
async fn smoke_valid_email_imports_seven_messages_once_and_can_be_replayed() {
    let domains = DomainSet::new(["example.com"]).unwrap();
    let repo = InMemoryReportRepository::default();

    let first = import_email(VALID_EMAIL, &domains, &repo, &IngestLimits::default())
        .await
        .expect("synthetic email must be readable");
    assert!(first.fully_captured);
    assert_eq!(first.documents_seen, 1);
    assert_eq!(first.newly_completed, 1);

    let repeated = import_email(VALID_EMAIL, &domains, &repo, &IngestLimits::default())
        .await
        .expect("replaying synthetic email must be idempotent");
    assert_eq!(repeated.previously_completed, 1);
    assert_eq!(repeated.newly_completed, 0);
    assert!(repeated.fully_captured);
}

#[tokio::test]
async fn smoke_invalid_email_must_not_mark_original_as_captured() {
    let domains = DomainSet::new(["example.com"]).unwrap();
    let repo = InMemoryReportRepository::default();
    let result = import_email(INVALID_EMAIL, &domains, &repo, &IngestLimits::default())
        .await
        .expect("invalid XML must produce a retained input rather than a database exception");
    assert!(!result.fully_captured);
    assert!(!result.retained.is_empty());
    assert_eq!(result.newly_completed, 0);
}
