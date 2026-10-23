use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use tally_core::identity::{DomainName, ReportIdentity, ReportReference};
use tally_core::identity::{DomainSet, StoredReport};
use tally_core::ingest::{import_email, IngestLimits, RetainedReason};
use tally_core::model::{DateRange, ParseLimits};
use tally_core::ports::{
    Cursor, InMemoryReportRepository, PersistOutcome, ReportPage, ReportRepository, StoreError,
};
use tally_core::xml::parse_dmarc_xml;

const LEGACY: &[u8] = include_bytes!("../../../tests/fixtures/xml/legacy.xml");
const UNRECOGNISED: &[u8] = include_bytes!("../../../tests/fixtures/xml/unknown-extension.xml");

fn mime(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = String::from(
        "From: reports@receiver.example\r\nTo: tally@example.net\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=dm\r\n\r\n",
    );
    for (filename, data) in parts {
        body.push_str(&format!(
            "--dm\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Type: application/xml\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            STANDARD.encode(data)
        ));
    }
    body.push_str("--dm--\r\n");
    body.into_bytes()
}

#[tokio::test]
async fn processes_direct_report_and_exact_duplicate_once() {
    let repository = InMemoryReportRepository::default();
    let domains = DomainSet::new(["example.com"]).unwrap();
    let bytes = mime(&[("report.xml", LEGACY)]);
    let first = import_email(&bytes, &domains, &repository, &IngestLimits::default())
        .await
        .unwrap();
    assert_eq!(first.newly_completed, 1);
    assert!(first.fully_captured);
    let duplicate = import_email(&bytes, &domains, &repository, &IngestLimits::default())
        .await
        .unwrap();
    assert_eq!(duplicate.previously_completed, 1);
    assert!(duplicate.fully_captured);
}

#[tokio::test]
async fn mixed_batch_saves_known_report_and_retains_original_on_extension() {
    let repository = InMemoryReportRepository::default();
    let domains = DomainSet::new(["example.com", "example.net"]).unwrap();
    let bytes = mime(&[("first.xml", LEGACY), ("second.xml", UNRECOGNISED)]);
    let first = import_email(&bytes, &domains, &repository, &IngestLimits::default())
        .await
        .unwrap();
    assert_eq!(first.newly_completed, 1);
    assert!(!first.fully_captured);
    assert!(first
        .retained
        .iter()
        .any(|reason| matches!(reason, RetainedReason::UnknownFields { .. })));
    let again = import_email(&bytes, &domains, &repository, &IngestLimits::default())
        .await
        .unwrap();
    assert_eq!(again.previously_completed, 2);
    assert!(!again.fully_captured);
}

#[tokio::test]
async fn unconfigured_domain_is_not_imported_and_original_is_retained() {
    let repository = InMemoryReportRepository::default();
    let domains = DomainSet::new(["other.example"]).unwrap();
    let result = import_email(
        &mime(&[("report.xml", LEGACY)]),
        &domains,
        &repository,
        &IngestLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.newly_completed, 0);
    assert!(!result.fully_captured);
    assert!(result
        .retained
        .iter()
        .any(|r| matches!(r, RetainedReason::UnconfiguredDomain(_))));
    let parsed = parse_dmarc_xml(LEGACY, &ParseLimits::default()).unwrap();
    assert!(repository
        .get_report(&tally_core::identity::report_identity(&parsed))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn permanently_invalid_xml_is_retained_without_any_db_write() {
    let repository = InMemoryReportRepository::default();
    let domains = DomainSet::new(["example.com"]).unwrap();
    let result = import_email(
        &mime(&[("bad.xml", b"<feedback/>")]),
        &domains,
        &repository,
        &IngestLimits::default(),
    )
    .await
    .unwrap();
    assert!(!result.fully_captured);
    assert_eq!(result.newly_completed, 0);
    assert!(result
        .retained
        .iter()
        .any(|r| matches!(r, RetainedReason::InvalidReport { .. })));
}

struct FailedStorage;

#[async_trait]
impl ReportRepository for FailedStorage {
    async fn persist_report(&self, _: &StoredReport) -> Result<PersistOutcome, StoreError> {
        Err(StoreError::Unavailable("simulated backend outage".into()))
    }
    async fn list_for_domain(
        &self,
        _: &DomainName,
        _: DateRange,
        _: Option<Cursor>,
    ) -> Result<ReportPage, StoreError> {
        Err(StoreError::Unavailable("simulated backend outage".into()))
    }

    async fn get_report_by_reference(
        &self,
        _: &ReportReference,
    ) -> Result<Option<StoredReport>, StoreError> {
        Err(StoreError::Unavailable("simulated backend outage".into()))
    }

    async fn get_report(&self, _: &ReportIdentity) -> Result<Option<StoredReport>, StoreError> {
        Err(StoreError::Unavailable("simulated backend outage".into()))
    }
}

#[tokio::test]
async fn persistence_failure_propagates_for_event_retry() {
    let domains = DomainSet::new(["example.com"]).unwrap();
    assert!(import_email(
        &mime(&[("report.xml", LEGACY)]),
        &domains,
        &FailedStorage,
        &IngestLimits::default()
    )
    .await
    .is_err());
}
