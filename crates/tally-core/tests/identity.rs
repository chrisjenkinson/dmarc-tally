use tally_core::identity::{
    report_content_hash, report_identity, DomainName, DomainSet, StoredReport,
};
use tally_core::model::ParseLimits;
use tally_core::ports::{InMemoryReportRepository, PersistOutcome, ReportRepository};
use tally_core::xml::parse_dmarc_xml;

fn fixture() -> tally_core::model::ParsedReport {
    parse_dmarc_xml(
        include_bytes!("../../../tests/fixtures/xml/legacy.xml"),
        &ParseLimits::default(),
    )
    .expect("synthetic DMARC XML")
}

#[test]
fn same_report_in_a_different_envelope_has_same_identity_and_hash() {
    let first = fixture();
    let second = fixture();
    assert_eq!(report_identity(&first), report_identity(&second));
    assert_eq!(report_content_hash(&first), report_content_hash(&second));
    assert_eq!(report_identity(&first).domain.as_str(), "example.com");
    assert_eq!(report_identity(&first).report_id, "legacy-001");
}

#[test]
fn domain_case_and_trailing_dot_do_not_split_reports() {
    let first = fixture();
    let mut second = fixture();
    second.published_policy.domain = "EXAMPLE.COM.".to_string();
    assert_eq!(report_identity(&first), report_identity(&second));
}

#[test]
fn different_report_content_with_same_identity_is_a_conflict() {
    let first = fixture();
    let mut altered = fixture();
    altered.records[0].count = 999;
    altered.records[0]
        .raw
        .children
        .iter_mut()
        .find(|x| x.name == "row")
        .unwrap()
        .children
        .iter_mut()
        .find(|x| x.name == "count")
        .unwrap()
        .text = "999".into();
    assert_eq!(report_identity(&first), report_identity(&altered));
    assert_ne!(report_content_hash(&first), report_content_hash(&altered));
}

#[test]
fn validates_domain_set_and_rejects_unconfigured_domains() {
    let set = DomainSet::new(["Example.COM.", "another.example", "example.com"]).unwrap();
    assert_eq!(set.domains().len(), 2);
    assert!(set.contains(&DomainName::parse("example.com").unwrap()));
    assert!(!set.contains(&DomainName::parse("third.example").unwrap()));
    assert!(DomainSet::new(["*"]).is_err());
    assert!(DomainName::parse("not a domain").is_err());
    assert!(DomainSet::new(std::iter::empty::<&str>()).is_err());
}

#[tokio::test]
async fn in_memory_port_is_idempotent_and_does_not_overwrite_a_conflict() {
    let repository = InMemoryReportRepository::default();
    let report = StoredReport::from_parsed(fixture(), "parser-v1");
    assert_eq!(
        repository.persist_report(&report).await.unwrap(),
        PersistOutcome::NewlyCompleted
    );
    assert_eq!(
        repository.persist_report(&report).await.unwrap(),
        PersistOutcome::PreviouslyCompleted
    );
    let mut altered = report.clone();
    altered.report.records[0].count = 999;
    altered.content_hash = report_content_hash(&altered.report);
    assert_eq!(
        repository.persist_report(&altered).await.unwrap(),
        PersistOutcome::Conflict
    );
    assert_eq!(
        repository.get_report(&report.identity).await.unwrap(),
        Some(report.clone())
    );
}
