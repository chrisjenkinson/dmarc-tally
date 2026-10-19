use tally_core::identity::{DomainName, StoredReport};
use tally_core::model::{DateRange, ParseLimits};
use tally_core::ports::{Cursor, InMemoryReportRepository, ReportRepository};
use tally_core::reporting::{summarise, Summary};
use tally_core::xml::parse_dmarc_xml;
use time::OffsetDateTime;

fn baseline() -> tally_core::model::ParsedReport {
    parse_dmarc_xml(
        include_bytes!("../../../tests/fixtures/xml/legacy.xml"),
        &ParseLimits::default(),
    ).unwrap()
}

fn report(id: &str, source_ip: &str, count: u64, dkim: &str, spf: &str) -> StoredReport {
    let mut parsed = baseline();
    parsed.metadata.report_id = id.to_owned();
    parsed.records[0].source_ip = source_ip.into();
    parsed.records[0].count = count;
    for element in &mut parsed.records[0].evaluated.raw.children {
        if element.name == "dkim" { element.text = dkim.into(); }
        if element.name == "spf" { element.text = spf.into(); }
    }
    StoredReport::from_parsed(parsed, "parser-v1")
}

#[test]
fn summarises_ip_across_reports_using_either_aligned_authentication_path() {
    let first = report("a", "192.0.2.10", 7, "pass", "fail");
    let second = report("b", "192.0.2.10", 3, "fail", "pass");
    let third = report("c", "198.51.100.20", 4, "fail", "fail");
    let Summary {
        reports, messages, passed, failed, by_ip, by_reporter, dispositions
    } = summarise([first, second, third].into_iter());
    assert_eq!(reports, 3);
    assert_eq!((messages, passed, failed), (14, 10, 4));
    assert_eq!(by_ip.get("192.0.2.10").unwrap().messages, 10);
    assert_eq!(by_ip.get("192.0.2.10").unwrap().failed, 0);
    assert_eq!(by_ip.get("198.51.100.20").unwrap().failed, 4);
    assert_eq!(by_reporter.get("receiver example").unwrap().messages, 14);
    assert_eq!(dispositions.get("none"), Some(&14));
}

#[test]
fn date_range_accepts_only_a_standard_window() {
    let now = OffsetDateTime::from_unix_timestamp(1_791_936_000).unwrap();
    for days in [7, 30, 90] {
        let range = DateRange::last_days(days, now).unwrap();
        assert_eq!(range.end, now.unix_timestamp());
        assert_eq!(range.begin, now.unix_timestamp() - i64::from(days)*86_400);
    }
    assert!(DateRange::last_days(0, now).is_err());
    assert!(DateRange::last_days(31, now).is_err());
}

#[tokio::test]
async fn repository_lists_only_requested_domains_and_reporting_periods() {
    let db = InMemoryReportRepository::default();
    let first = report("in", "192.0.2.10", 7, "pass", "fail");
    let mut other_domain = report("in-other", "192.0.2.10", 2, "fail", "fail");
    other_domain.identity.domain = DomainName::parse("another.example").unwrap();
    let mut older = report("old", "192.0.2.10", 1, "fail", "fail");
    older.identity.period_end = 1_000;
    for stored in [&first, &other_domain, &older] {
        db.persist_report(stored).await.unwrap();
    }
    let page = db.list_for_domain(
        &DomainName::parse("example.com").unwrap(),
        DateRange { begin: 1_791_000_000, end: 1_792_000_000 },
        None,
    ).await.unwrap();
    assert_eq!(page.reports.len(), 1);
    assert_eq!(page.reports[0].identity.report_id, "in");
}

#[tokio::test]
async fn repository_uses_a_stable_cursor_for_more_than_one_page() {
    let db = InMemoryReportRepository::default();
    for n in 0..105 {
        let r = report(&format!("report-{n:03}"), "192.0.2.10", 1, "pass", "fail");
        db.persist_report(&r).await.unwrap();
    }
    let domain = DomainName::parse("example.com").unwrap();
    let range = DateRange { begin: 1_791_000_000, end: 1_792_000_000 };
    let mut cursor: Option<Cursor> = None;
    let mut ids = std::collections::BTreeSet::new();
    loop {
        let page = db.list_for_domain(&domain, range.clone(), cursor).await.unwrap();
        for record in page.reports {
            assert!(ids.insert(record.identity.report_id));
        }
        cursor = page.next_cursor;
        if cursor.is_none() { break; }
    }
    assert_eq!(ids.len(), 105);
}

#[test]
fn empty_summary_is_not_reported_as_healthy() {
    let s = summarise(std::iter::empty::<StoredReport>());
    assert_eq!(s.reports, 0);
    assert_eq!(s.messages, 0);
    assert_eq!(s.passed, 0);
    assert_eq!(s.failed, 0);
}
