//! Tests for portable, read-only report queries used after authentication.
//! No AWS, Lambda, session cookies or external services are involved.

use async_trait::async_trait;
use tally_core::{
    identity::{DomainName, DomainSet, ReportIdentity, ReportReference, StoredReport},
    model::{DateRange, ParseLimits},
    ports::{
        Cursor, InMemoryReportRepository, PersistOutcome, ReportPage, ReportRepository, StoreError,
    },
    xml::parse_dmarc_xml,
};
use tally_web::report_queries::{load_overview, OverviewError, OverviewSelection, SelectionError};

const NOW: i64 = 1_791_936_000;

fn monitored() -> DomainSet {
    DomainSet::new(["example.com", "example.net"]).unwrap()
}

fn stored(domain: &str, report_id: &str, end: i64, messages: u64) -> StoredReport {
    let mut parsed = parse_dmarc_xml(
        include_bytes!("../../../tests/fixtures/xml/legacy.xml"),
        &ParseLimits::default(),
    )
    .unwrap();
    parsed.published_policy.domain = domain.to_string();
    parsed.metadata.report_id = report_id.to_owned();
    parsed.metadata.date_range.begin = end - 86_400;
    parsed.metadata.date_range.end = end;
    parsed.records[0].count = messages;
    StoredReport::from_parsed(parsed, "parser-v1")
}

#[test]
fn defaults_to_all_monitored_domains_over_last_thirty_days() {
    let selected = OverviewSelection::parse("", &monitored()).unwrap();
    assert_eq!(selected.days, 30);
    assert_eq!(selected.selected_domain, None);
    let explicit = OverviewSelection::parse("domain=all&days=30", &monitored()).unwrap();
    assert_eq!(selected, explicit);
}

#[test]
fn normalises_allowed_domain_and_decodes_url_parameters() {
    let selected = OverviewSelection::parse("days=7&domain=EXAMPLE%2Ecom", &monitored()).unwrap();
    assert_eq!(selected.days, 7);
    assert_eq!(selected.selected_domain.unwrap().as_str(), "example.com");
}

#[test]
fn rejects_unknown_domains_and_invalid_periods() {
    assert!(matches!(
        OverviewSelection::parse("domain=outsider.example&days=7", &monitored()),
        Err(SelectionError::UnconfiguredDomain)
    ));
    for query in [
        "days=8", "days=0", "days=-7", "days=365", "days=foo", "days=",
    ] {
        assert!(matches!(
            OverviewSelection::parse(query, &monitored()),
            Err(SelectionError::InvalidPeriod)
        ));
    }
}

#[test]
fn rejects_ambiguous_query_parameters_without_exposing_data() {
    for query in [
        "days=7&days=90",
        "domain=example.com&domain=example.net",
        "filter=secret",
        "domain=example.com&debug=yes",
        "domain=%00example.com",
    ] {
        assert!(
            OverviewSelection::parse(query, &monitored()).is_err(),
            "unexpectedly accepted {query}"
        );
    }
}

#[tokio::test]
async fn reports_from_all_domains_are_combined_without_mixing_periods() {
    let repo = InMemoryReportRepository::default();
    for report in [
        stored("example.com", "current-com", NOW - 86_400, 7),
        stored("example.net", "current-net", NOW - 86_400, 4),
        stored("example.com", "old-com", NOW - 45 * 86_400, 99),
    ] {
        assert_eq!(
            repo.persist_report(&report).await.unwrap(),
            PersistOutcome::NewlyCompleted
        );
    }
    let selection = OverviewSelection::parse("days=7&domain=all", &monitored()).unwrap();
    let view = load_overview(&repo, &monitored(), &selection, NOW)
        .await
        .unwrap();
    assert_eq!(view.days, 7);
    assert_eq!(view.summary.reports, 2);
    assert_eq!(view.summary.messages, 11);
    assert_eq!(view.summary.passed, 11);
    assert_eq!(view.summary.by_reporter["receiver example"].messages, 11);
    assert_eq!(view.configured_domains.len(), 2);

    let domain = OverviewSelection::parse("domain=example.com&days=7", &monitored()).unwrap();
    let filtered = load_overview(&repo, &monitored(), &domain, NOW)
        .await
        .unwrap();
    assert_eq!(filtered.summary.reports, 1);
    assert_eq!(filtered.summary.messages, 7);
}

#[tokio::test]
async fn follows_repository_cursors_and_does_not_drop_the_next_page() {
    let repo = InMemoryReportRepository::default();
    for n in 0..101 {
        let report = stored("example.com", &format!("report-{n:03}"), NOW - 1, 1);
        repo.persist_report(&report).await.unwrap();
    }
    let selection = OverviewSelection::parse("days=30&domain=example.com", &monitored()).unwrap();
    let view = load_overview(&repo, &monitored(), &selection, NOW)
        .await
        .unwrap();
    assert_eq!(view.summary.reports, 101);
    assert_eq!(view.summary.messages, 101);
    assert_eq!(view.summary.by_ip["192.0.2.10"].messages, 101);
    assert_eq!(view.summary.by_reporter["receiver example"].messages, 101);
    assert_eq!(view.summary.dispositions["none"], 101);
}

struct CursorLoopRepository;

#[async_trait]
impl ReportRepository for CursorLoopRepository {
    async fn persist_report(&self, _report: &StoredReport) -> Result<PersistOutcome, StoreError> {
        unreachable!("read-only test")
    }

    async fn list_for_domain(
        &self,
        _domain: &DomainName,
        _range: DateRange,
        _cursor: Option<Cursor>,
    ) -> Result<ReportPage, StoreError> {
        Ok(ReportPage {
            reports: vec![],
            next_cursor: Some(Cursor("same-value".into())),
        })
    }


    async fn get_report_by_reference(
        &self,
        _: &ReportReference,
    ) -> Result<Option<StoredReport>, StoreError> {
        unreachable!("overview never loads individual report references")
    }

    async fn get_report(
        &self,
        _identity: &ReportIdentity,
    ) -> Result<Option<StoredReport>, StoreError> {
        unreachable!("overview never loads individual reports")
    }
}

#[tokio::test]
async fn detects_broken_repository_pagination_instead_of_looping() {
    let selection = OverviewSelection::parse("", &monitored()).unwrap();
    let result = load_overview(&CursorLoopRepository, &monitored(), &selection, NOW).await;
    assert!(matches!(result, Err(OverviewError::PaginationLoop)));
}
