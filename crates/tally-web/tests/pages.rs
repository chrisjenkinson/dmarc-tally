use tally_core::identity::ReportReference;
use tally_core::{
    identity::{DomainName, StoredReport},
    model::ParseLimits,
    reporting::{Summary, Traffic},
    xml::parse_dmarc_xml,
};
use tally_web::pages::{
    render_report_detail, render_report_page, RecentReport, ReportDetailViewModel, ReportViewModel,
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

#[test]
fn recent_links_are_escaped_and_only_show_bounded_navigation() {
    let mut view = view();
    view.summary.reports = 1;
    let mut report = detail(false).report;
    report.identity.organisation = "<img src=x onerror=alert(1)>".into();
    view.recent_reports.push(RecentReport {
        reference: ReportReference::from_identity(&report.identity),
        organisation: report.identity.organisation,
        messages: 5,
    });
    let page = render_report_page(&view);
    assert!(page.contains("Recent reports"));
    assert!(page.contains("up to 20 reports"));
    assert!(page.contains("href=\"/reports/"));
    assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(!page.contains("<img src=x"));
}

#[test]
fn failure_sources_are_sorted_by_failed_volume_with_rates_and_full_totals() {
    let mut model = view();
    model.summary.reports = 9;
    model.summary.messages = 25;
    model.summary.passed = 11;
    model.summary.failed = 14;
    model.summary.by_ip.insert(
        "198.51.100.2".into(),
        Traffic {
            messages: 15,
            passed: 10,
            failed: 5,
        },
    );
    model.summary.by_ip.insert(
        "203.0.113.42".into(),
        Traffic {
            messages: 9,
            passed: 0,
            failed: 9,
        },
    );
    model.summary.by_ip.insert(
        "192.0.2.1".into(),
        Traffic {
            messages: 1,
            passed: 1,
            failed: 0,
        },
    );
    model.summary.by_reporter.insert(
        "Second reporter".into(),
        Traffic {
            messages: 12,
            passed: 11,
            failed: 1,
        },
    );
    model.summary.by_reporter.insert(
        "Highest failure reporter".into(),
        Traffic {
            messages: 13,
            passed: 0,
            failed: 13,
        },
    );
    model.summary.dispositions.insert("none".into(), 20);
    model.summary.dispositions.insert("reject".into(), 5);
    let html = render_report_page(&model);
    assert!(html.contains("Sources with DMARC failures"));
    assert!(html.contains("Failure rate</th>"));
    assert!(html.contains("56.0%"));
    assert!(html.contains("100.0%"));
    let first = html.find("<th scope=\"row\">203.0.113.42</th>").unwrap();
    let second = html.find("<th scope=\"row\">198.51.100.2</th>").unwrap();
    assert!(first < second, "sort sources by failed-message count");
    assert!(!html.contains("<th scope=\"row\">192.0.2.1</th>"));
    assert!(
        html.find("Highest failure reporter</th>").unwrap()
            < html.find("Second reporter</th>").unwrap()
    );
    assert!(html.contains("Receiver-reported dispositions"));
    assert!(html.contains("does not mean authentication passed"));
    assert!(html.contains("A source with failed DMARC is not necessarily malicious"));
    assert!(html.contains(">25</strong>"), "retain observed totals");
}

#[test]
fn passing_reports_are_not_misrepresented_as_complete_delivery_health() {
    let mut model = view();
    model.summary.reports = 1;
    model.summary.messages = 5;
    model.summary.passed = 5;
    model.summary.by_ip.insert(
        "192.0.2.10".into(),
        Traffic {
            messages: 5,
            passed: 5,
            failed: 0,
        },
    );
    let html = render_report_page(&model);
    assert!(html.contains("No DMARC failures observed in the selected reports"));
    assert!(!html.contains("100% healthy"));
    assert!(!html.contains("<th scope=\"row\">192.0.2.10</th>"));
    assert!(html.contains("not a count of all email sent"));
}

#[test]
fn arbitrary_reported_values_remain_html_escaped_in_new_sections() {
    let mut model = view();
    model.summary.reports = 1;
    model.summary.messages = 3;
    model.summary.failed = 3;
    model.summary.by_ip.insert(
        "<img src=x onerror=alert(1)>".into(),
        Traffic {
            messages: 3,
            passed: 0,
            failed: 3,
        },
    );
    model
        .summary
        .dispositions
        .insert("<script>bad()</script>".into(), 3);
    let html = render_report_page(&model);
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(html.contains("&lt;script&gt;bad()&lt;/script&gt;"));
    assert!(!html.contains("<img src=x"));
    assert!(!html.contains("<script>bad()"));
}

#[test]
fn failure_sources_table_is_bounded_while_observed_totals_remain_complete() {
    let mut model = view();
    model.summary.reports = 20;
    model.summary.messages = 20;
    model.summary.failed = 20;
    for n in 0..20 {
        model.summary.by_ip.insert(
            format!("192.0.2.{n}"),
            Traffic {
                messages: 1,
                passed: 0,
                failed: 1,
            },
        );
    }
    let html = render_report_page(&model);
    assert!(html.contains("ten largest failing sources"));
    assert_eq!(html.matches("<td class=\"risk\">1</td>").count(), 10);
    assert!(html.contains(">20</strong>"));
}

#[test]
fn detail_shows_aligned_dmarc_result_separately_from_raw_authentication() {
    let html = render_report_detail(&detail(false));
    assert!(html.contains("Policy-evaluated observations"));
    assert!(html.contains("Aligned DKIM"));
    assert!(html.contains("Aligned SPF"));
    assert!(html.contains("individual authentication results"));
    assert!(html.contains("href=\"#observation-1\""));
    assert!(html.contains("id=\"observation-1\""));
    assert!(html.contains("Reported DKIM authentication results"));
    assert!(html.contains("Reported SPF authentication results"));
    assert!(html.contains("Receiver-reported policy reasons"));
    assert!(html.contains("Period start"));
    assert!(html.contains("Period end"));
    assert!(html.contains("Authentication details by observation"));
    assert!(!html.contains("View original email"));
}

#[test]
fn failure_in_aligned_policy_result_is_not_overridden_by_raw_dkim_pass() {
    let mut view = detail(false);
    let evaluated = &mut view.report.report.records[0].evaluated.raw;
    evaluated
        .children
        .iter_mut()
        .find(|field| field.name == "dkim")
        .unwrap()
        .text = "fail".into();
    let html = render_report_detail(&view);
    assert!(html.contains("Not passed</td>"));
    assert!(html.contains("Reported DKIM authentication results"));
    assert!(
        html.contains("example.com: pass"),
        "raw DKIM pass still reported"
    );
}
