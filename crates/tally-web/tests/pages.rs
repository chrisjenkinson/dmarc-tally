use tally_core::{
    identity::{DomainName, StoredReport},
    model::ParseLimits,
    reporting::{Summary, Traffic},
    xml::parse_dmarc_xml,
};
use tally_web::pages::{
    render_report_detail, render_report_page, ReportDetailViewModel, ReportViewModel,
};

fn view() -> ReportViewModel {
    ReportViewModel {
        selected_domain: None,
        configured_domains: vec![
            DomainName::parse("example.com").unwrap(),
            DomainName::parse("example.net").unwrap(),
        ],
        days: 30,
        summary: Summary::default(),
        recent_reports: vec![],
    }
}

#[test]
fn empty_report_explains_absence_without_claiming_health() {
    let page = render_report_page(&view());
    assert!(page.contains("No DMARC reports"));
    assert!(page.contains("messages observed in DMARC reports"));
    assert!(!page.contains("100% healthy"));
    assert!(page.contains("<main"));
    assert!(page.contains("name=\"domain\""));
    assert!(page.contains("name=\"days\""));
}

#[test]
fn overview_exposes_all_domains_and_date_choices() {
    let page = render_report_page(&view());
    assert!(page.contains("value=\"all\""));
    assert!(page.contains("example.com"));
    assert!(page.contains("example.net"));
    for days in [7, 30, 90] {
        assert!(page.contains(&format!("value=\"{days}\"")));
    }
}

#[test]
fn reporter_names_are_escaped_not_rendered_as_html() {
    let mut view = view();
    view.summary.reports = 1;
    view.summary.messages = 3;
    view.summary.passed = 2;
    view.summary.failed = 1;
    view.summary.by_reporter.insert(
        "<script>alert('pwned')</script>".into(),
        Traffic {
            messages: 3,
            passed: 2,
            failed: 1,
        },
    );
    let page = render_report_page(&view);
    assert!(!page.contains("<script>alert"));
    assert!(page.contains("&lt;script&gt;"));
    assert!(page.contains("Reporting organisation"));
    assert!(page.contains("3"));
}

fn detail(original_available: bool) -> ReportDetailViewModel {
    let parsed = parse_dmarc_xml(
        include_bytes!("../../../tests/fixtures/xml/legacy.xml"),
        &ParseLimits::default(),
    )
    .unwrap();
    ReportDetailViewModel {
        report: StoredReport::from_parsed(parsed, "parser-v1"),
        original_available,
    }
}

#[test]
fn report_details_include_ip_dkim_spf_and_disposition() {
    let page = render_report_detail(&detail(false));
    assert!(page.contains("192.0.2.10"));
    assert!(page.contains("receiver example"));
    assert!(page.contains("DKIM"));
    assert!(page.contains("SPF"));
    assert!(page.contains("forwarded"));
    assert!(page.contains("Disposition"));
    assert!(!page.contains("View original email"));
}

#[test]
fn original_link_only_shown_when_original_is_available() {
    let page = render_report_detail(&detail(true));
    assert!(page.contains("View original email"));
    let other = render_report_detail(&detail(false));
    assert!(!other.contains("View original email"));
}
